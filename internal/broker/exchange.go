package broker

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/cchulo/project-juggernaut/internal/auth"
	"github.com/cchulo/project-juggernaut/internal/config"
)

// Exchange implements RFC 8693 token exchange against the IdP token endpoint.
//
// Keycloak (standard token exchange, 26.2+), Entra ID (on-behalf-of) and Okta all
// accept grant_type=urn:ietf:params:oauth:grant-type:token-exchange with a
// subject_token and an audience. The resulting token has `sub` of the user and
// an `act` claim naming the gateway client.
type Exchange struct {
	cfg      config.Identity
	endpoint string
	client   *http.Client
	secret   func(*config.SecretRef) (string, error)

	mu    sync.Mutex
	cache map[string]*Token // key: tokenHash + "|" + server name
}

// NewExchange builds the broker; the token endpoint defaults to Keycloak's layout under the issuer.
func NewExchange(cfg config.Identity, secret func(*config.SecretRef) (string, error)) (*Exchange, error) {
	ep := cfg.Broker.TokenEndpoint
	if ep == "" {
		ep = strings.TrimRight(cfg.Issuer, "/") + "/protocol/openid-connect/token"
	}
	if cfg.Broker.ClientID == "" {
		return nil, fmt.Errorf("identity.broker.clientId is required for exchange")
	}
	return &Exchange{
		cfg:      cfg,
		endpoint: ep,
		client:   &http.Client{Timeout: 10 * time.Second},
		secret:   secret,
		cache:    map[string]*Token{},
	}, nil
}

// TokenFor returns a cached or freshly exchanged token for (principal, server).
// In milestone 1 the cache moves to Redis (encrypted with the gateway KEK) so
// every gateway replica shares it.
func (e *Exchange) TokenFor(ctx context.Context, p *auth.Principal, s *config.Server, minRemaining time.Duration) (*Token, error) {
	if s.Token.Mode == config.TokenNone || s.Token.Mode == config.TokenStatic {
		return nil, nil
	}
	key := p.TokenHash + "|" + s.Name
	e.mu.Lock()
	if t, ok := e.cache[key]; ok && time.Until(t.Expiry) > minRemaining {
		e.mu.Unlock()
		return t, nil
	}
	e.mu.Unlock()

	t, err := e.exchange(ctx, p.RawToken, s)
	if err != nil {
		return nil, err
	}
	// Never let a downstream token outlive the token it was minted from.
	if t.Expiry.After(p.Expiry) {
		t.Expiry = p.Expiry
	}
	e.mu.Lock()
	e.cache[key] = t
	e.mu.Unlock()
	return t, nil
}

func (e *Exchange) exchange(ctx context.Context, subjectToken string, s *config.Server) (*Token, error) {
	secret, err := e.secret(e.cfg.Broker.ClientSecretRef)
	if err != nil {
		return nil, err
	}
	form := url.Values{
		"grant_type":           {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"subject_token":        {subjectToken},
		"subject_token_type":   {"urn:ietf:params:oauth:token-type:access_token"},
		"requested_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
		"audience":             {s.Token.Audience},
	}
	if len(s.Token.Scopes) > 0 {
		form.Set("scope", strings.Join(s.Token.Scopes, " "))
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(e.cfg.Broker.ClientID, secret)
	resp, err := e.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token exchange: %w", err)
	}
	defer resp.Body.Close()
	var body struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int    `json:"expires_in"`
		Error       string `json:"error"`
		ErrorDesc   string `json:"error_description"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, fmt.Errorf("token exchange: decode: %w", err)
	}
	if resp.StatusCode != http.StatusOK || body.AccessToken == "" {
		return nil, fmt.Errorf("token exchange for %s failed: %s %s (%d)", s.Name, body.Error, body.ErrorDesc, resp.StatusCode)
	}
	exp := time.Now().Add(time.Duration(body.ExpiresIn) * time.Second)
	if body.ExpiresIn == 0 {
		exp = time.Now().Add(e.cfg.Broker.CacheTTL.Or(5 * time.Minute))
	}
	typ := body.TokenType
	if typ == "" {
		typ = "Bearer"
	}
	return &Token{Value: body.AccessToken, Expiry: exp, Type: typ}, nil
}

// Revoke drops cached tokens; the cache key is per incoming token, so we scan.
// Milestone 1 indexes by subject in Redis.
func (e *Exchange) Revoke(_ context.Context, subject string) error {
	_ = subject
	e.mu.Lock()
	defer e.mu.Unlock()
	e.cache = map[string]*Token{}
	return nil
}
