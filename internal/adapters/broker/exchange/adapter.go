// Package exchange is the reference token broker: RFC 8693 token exchange
// against the IdP token endpoint. Keycloak (standard token exchange, 26.2+),
// Entra ID (on-behalf-of) and Okta accept
// grant_type=urn:ietf:params:oauth:grant-type:token-exchange with a
// subject_token and an audience; the result keeps the user's `sub` and carries
// an `act` claim naming the gateway.
//
// Options: token_endpoint (override the Keycloak layout under the issuer).
package exchange

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/cchulo/project-juggernaut/internal/config"
	"github.com/cchulo/project-juggernaut/internal/core"
	"github.com/cchulo/project-juggernaut/internal/core/contracts"
	"github.com/cchulo/project-juggernaut/internal/core/registry"
)

// Type is the registry name.
const Type = "exchange"

func init() { registry.Broker.Register(Type, New) }

// Adapter exchanges tokens and caches the results per (incoming token, server type).
type Adapter struct {
	ctx    *core.Context
	client *http.Client

	mu    sync.Mutex
	cache map[string]*contracts.Token
}

// New validates the broker configuration.
func New(ctx *core.Context) (contracts.TokenBroker, error) {
	b := ctx.Cfg().Identity.Broker
	if b.ClientID == "" {
		return nil, fmt.Errorf("identity.broker.clientId is required for exchange")
	}
	return &Adapter{ctx: ctx, client: &http.Client{Timeout: 10 * time.Second}, cache: map[string]*contracts.Token{}}, nil
}

func (a *Adapter) endpoint() string {
	id := a.ctx.Cfg().Identity
	if ep := a.ctx.Options.String("token_endpoint", id.Broker.TokenEndpoint); ep != "" {
		return ep
	}
	return strings.TrimRight(id.Issuer, "/") + "/protocol/openid-connect/token"
}

// TokenFor returns a cached or freshly exchanged token. The cache is per
// process; a shared, sealed cache in the routing table is a follow-up.
func (a *Adapter) TokenFor(ctx context.Context, p *core.Principal, s *config.Server, minRemaining time.Duration) (*contracts.Token, error) {
	if s.Token.Mode == config.TokenNone || s.Token.Mode == config.TokenStatic {
		return nil, nil
	}
	key := p.TokenHash + "|" + s.Name
	a.mu.Lock()
	if t, ok := a.cache[key]; ok && time.Until(t.Expiry) > minRemaining {
		a.mu.Unlock()
		return t, nil
	}
	a.mu.Unlock()

	t, err := a.exchange(ctx, p.RawToken, s)
	if err != nil {
		return nil, err
	}
	if t.Expiry.After(p.Expiry) { // never outlive the token it was minted from
		t.Expiry = p.Expiry
	}
	a.mu.Lock()
	a.cache[key] = t
	a.mu.Unlock()
	return t, nil
}

func (a *Adapter) exchange(ctx context.Context, subjectToken string, s *config.Server) (*contracts.Token, error) {
	b := a.ctx.Cfg().Identity.Broker
	secret, err := a.ctx.Secrets.Get(b.ClientSecretRef)
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
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.endpoint(), strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(b.ClientID, secret)
	resp, err := a.client.Do(req)
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
		exp = time.Now().Add(b.CacheTTL.Or(5 * time.Minute))
	}
	typ := body.TokenType
	if typ == "" {
		typ = "Bearer"
	}
	return &contracts.Token{Value: body.AccessToken, Expiry: exp, Type: typ}, nil
}

// Revoke drops every cached token (the cache is keyed by token hash, not subject).
func (a *Adapter) Revoke(context.Context, string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.cache = map[string]*contracts.Token{}
	return nil
}
