// Package bearer_introspect is bearer_jwt plus RFC 7662 introspection: the JWT
// is validated locally, then the IdP is asked (at most once per interval per
// token) whether it is still active, so revocation is detected before expiry.
//
// Options: those of bearer_jwt, plus fail_open (default false: an unreachable
// introspection endpoint rejects the request; zero trust means an unverifiable
// token is not accepted on the strength of the network being fine yesterday).
package bearer_introspect

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/cchulo/project-juggernaut/internal/adapters/identity/bearer_jwt"
	"github.com/cchulo/project-juggernaut/internal/config"
	"github.com/cchulo/project-juggernaut/internal/core"
	"github.com/cchulo/project-juggernaut/internal/core/contracts"
	"github.com/cchulo/project-juggernaut/internal/core/registry"
)

// Type is the registry name.
const Type = "bearer_introspect"

func init() { registry.Identity.Register(Type, New) }

// Adapter wraps bearer_jwt with introspection.
type Adapter struct {
	contracts.IdentityProvider // bearer_jwt: Challenge and PRM delegate to it
	jwt                        *bearer_jwt.Adapter
	ctx                        *core.Context
	client                     *http.Client

	mu   sync.Mutex
	seen map[string]seen // token hash → last answer
}

type seen struct {
	at     time.Time
	active bool
}

// New builds the adapter.
func New(ctx *core.Context) (contracts.IdentityProvider, error) {
	inner, err := bearer_jwt.New(ctx)
	if err != nil {
		return nil, err
	}
	return &Adapter{IdentityProvider: inner, jwt: inner.(*bearer_jwt.Adapter), ctx: ctx,
		client: &http.Client{Timeout: 5 * time.Second}, seen: map[string]seen{}}, nil
}

func (a *Adapter) cfg() config.Introspection { return a.ctx.Cfg().Identity.Introspection }

// Resolve validates the JWT and checks revocation.
func (a *Adapter) Resolve(ctx context.Context, req contracts.RequestInfo) (*core.Principal, error) {
	p, err := a.IdentityProvider.Resolve(ctx, req)
	if err != nil {
		return nil, err
	}
	active, err := a.active(ctx, p)
	if err != nil {
		if !a.ctx.Options.Bool("fail_open", false) {
			return nil, fmt.Errorf("%w: introspection unavailable", contracts.ErrUnauthenticated)
		}
		a.ctx.Log.Warn("introspection failed; accepting token until expiry", "err", err)
		return p, nil
	}
	if !active {
		return nil, fmt.Errorf("%w: token revoked", contracts.ErrUnauthenticated)
	}
	return p, nil
}

func (a *Adapter) active(ctx context.Context, p *core.Principal) (bool, error) {
	c := a.cfg()
	a.mu.Lock()
	s, ok := a.seen[p.TokenHash]
	a.mu.Unlock()
	if ok && time.Since(s.at) < c.Interval.Or(60*time.Second) {
		return s.active, nil
	}
	active, err := a.query(ctx, p.RawToken)
	if err != nil {
		return true, err
	}
	a.mu.Lock()
	a.seen[p.TokenHash] = seen{at: time.Now(), active: active}
	if len(a.seen) > 10000 {
		for k, v := range a.seen {
			if time.Since(v.at) > time.Hour {
				delete(a.seen, k)
			}
		}
	}
	a.mu.Unlock()
	return active, nil
}

func (a *Adapter) query(ctx context.Context, token string) (bool, error) {
	id := a.ctx.Cfg().Identity
	c := id.Introspection
	ep := c.Endpoint
	if ep == "" {
		ep = strings.TrimRight(id.Issuer, "/") + "/protocol/openid-connect/token/introspect"
	}
	secret, err := a.ctx.Secrets.Get(c.ClientSecretRef)
	if err != nil {
		return true, err
	}
	form := url.Values{"token": {token}, "token_type_hint": {"access_token"}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ep, strings.NewReader(form.Encode()))
	if err != nil {
		return true, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(c.ClientID, secret)
	resp, err := a.client.Do(req)
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
