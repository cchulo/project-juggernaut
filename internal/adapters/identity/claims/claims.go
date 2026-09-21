// Package claims holds the mapping helpers identity adapters share: config
// seeds and token claims → Principal. It is not an adapter.
package claims

import (
	"fmt"
	"strings"

	"github.com/cchulo/project-juggernaut/internal/config"
	"github.com/cchulo/project-juggernaut/internal/core"
	"github.com/cchulo/project-juggernaut/internal/core/contracts"
)

// AllScopes lists every OAuth scope the gateway knows, from configuration.
func AllScopes(c *config.Config) []string {
	return []string{c.Identity.Scopes.MCP, c.Identity.Scopes.Admin, c.Identity.Scopes.UsersAdmin}
}

// FromSeed turns a `principal:` / `tokens:` entry into a Principal. Empty
// scopes mean every scope, mirroring cerebro's seeds.
func FromSeed(c *config.Config, seed config.PrincipalSeed, issuer string) *core.Principal {
	scopes := seed.Scopes
	if len(scopes) == 0 {
		scopes = AllScopes(c)
	}
	kind := seed.Kind
	if kind == "" {
		kind = "user"
	}
	return &core.Principal{Subject: seed.Subject, Username: seed.Subject, DisplayName: seed.Subject,
		Kind: kind, Groups: append([]string(nil), seed.Groups...), Scopes: scopes, Issuer: issuer}
}

// AsList accepts claims that arrive as JSON lists or space/comma separated
// strings (Keycloak, Entra, RFC 7662 `scope`).
func AsList(v any) []string {
	switch t := v.(type) {
	case nil:
		return nil
	case string:
		return strings.Fields(strings.ReplaceAll(t, ",", " "))
	case []any:
		out := make([]string, 0, len(t))
		for _, e := range t {
			if s, ok := e.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	case []string:
		return t
	}
	return []string{fmt.Sprint(v)}
}

// Claim reads `groups` or a dotted path such as `realm_access.roles`.
func Claim(claims map[string]any, path string) any {
	var cur any = claims
	for _, part := range strings.Split(path, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur = m[part]
	}
	return cur
}

// FromClaims maps validated token claims (JWT payload or introspection
// response) to a Principal:
//
//   - groups from groupsClaim (list or delimited string; Keycloak "/name" paths trimmed)
//   - scopes from the `scope` claim
//   - kind service when there is no human identity claim and client_id/azp equals sub
func FromClaims(claims map[string]any, groupsClaim, usernameClaim string) (*core.Principal, error) {
	sub := str(claims["sub"])
	if sub == "" {
		sub = str(claims["client_id"])
	}
	if sub == "" {
		return nil, fmt.Errorf("%w: token carries no subject", contracts.ErrUnauthenticated)
	}
	groups := AsList(Claim(claims, groupsClaim))
	for i, g := range groups {
		groups[i] = strings.TrimPrefix(g, "/")
	}
	human := str(claims["email"]) != "" || str(claims["preferred_username"]) != ""
	client := str(claims["client_id"])
	if client == "" {
		client = str(claims["azp"])
	}
	kind := "user"
	if !human && client != "" && client == sub {
		kind = "service"
	}
	display := str(claims["name"])
	if display == "" {
		display = str(claims["preferred_username"])
	}
	if display == "" {
		display = str(claims["email"])
	}
	username := str(claims[usernameClaim])
	if username == "" {
		username = sub
	}
	return &core.Principal{Subject: sub, Username: username, DisplayName: display, Kind: kind,
		Groups: groups, Scopes: AsList(claims["scope"]), Issuer: str(claims["iss"])}, nil
}

func str(v any) string {
	s, _ := v.(string)
	return s
}
