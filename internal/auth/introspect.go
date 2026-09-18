package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/cchulo/project-juggernaut/internal/config"
)

// Introspector detects revocation before a JWT expires by asking the IdP's
// introspection endpoint (RFC 7662) at most once per interval per token.
type Introspector struct {
	cfg      config.Introspection
	endpoint string
	client   *http.Client
	secret   func(*config.SecretRef) (string, error)

	mu   sync.Mutex
	seen map[string]seen // token hash → last result
}

type seen struct {
	at     time.Time
	active bool
}

// NewIntrospector builds an introspector; endpoint defaults to Keycloak's layout.
func NewIntrospector(id config.Identity, secret func(*config.SecretRef) (string, error)) *Introspector {
	ep := id.Introspection.Endpoint
	if ep == "" {
		ep = strings.TrimRight(id.Issuer, "/") + "/protocol/openid-connect/token/introspect"
	}
	return &Introspector{cfg: id.Introspection, endpoint: ep, client: &http.Client{Timeout: 5 * time.Second}, secret: secret, seen: map[string]seen{}}
}

// Active reports whether the token is still active, consulting the IdP when
// the cached answer is older than the interval. Errors fail open (the JWT is
// still cryptographically valid) but are returned for logging.
func (i *Introspector) Active(ctx context.Context, p *Principal) (bool, error) {
	if !i.cfg.Enabled {
		return true, nil
	}
	i.mu.Lock()
	s, ok := i.seen[p.TokenHash]
	i.mu.Unlock()
	if ok && time.Since(s.at) < i.cfg.Interval.Or(60*time.Second) {
		return s.active, nil
	}
	active, err := i.query(ctx, p.RawToken)
	if err != nil {
		return true, err
	}
	i.mu.Lock()
	i.seen[p.TokenHash] = seen{at: time.Now(), active: active}
	// Drop entries for tokens that expired long ago.
	if len(i.seen) > 10000 {
		for k, v := range i.seen {
			if time.Since(v.at) > time.Hour {
				delete(i.seen, k)
			}
		}
	}
	i.mu.Unlock()
	return active, nil
}

func (i *Introspector) query(ctx context.Context, token string) (bool, error) {
	secret, err := i.secret(i.cfg.ClientSecretRef)
	if err != nil {
		return true, err
	}
	form := url.Values{"token": {token}, "token_type_hint": {"access_token"}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, i.endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return true, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(i.cfg.ClientID, secret)
	resp, err := i.client.Do(req)
	if err != nil {
		return true, err
	}
	defer resp.Body.Close()
	var body struct {
		Active bool `json:"active"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return true, err
	}
	return body.Active, nil
}

// Forget drops cached answers for a subject's tokens (after an admin disable
// the next request re-checks immediately).
func (i *Introspector) Forget() {
	i.mu.Lock()
	i.seen = map[string]seen{}
	i.mu.Unlock()
}
