package core

import (
	"context"
	"sort"
	"strings"
	"time"
)

// Principal is what an IdentityProvider produces from a request: a validated
// identity. Tools and handlers never look at headers or raw tokens; they
// consult Grants, which an AccessPolicy derives from a Principal.
type Principal struct {
	Subject  string
	Username string
	Groups   []string
	Scopes   []string
	Issuer   string
	Expiry   time.Time
	// RawToken is the validated bearer token. Only the token broker may read
	// it (as the subject_token of an RFC 8693 exchange); it is never logged
	// or forwarded upstream.
	RawToken string
	// TokenHash is a stable, non-reversible identifier for RawToken used as a cache key.
	TokenHash string
}

// HasScope reports whether the token carries the OAuth scope.
func (p *Principal) HasScope(s string) bool { return contains(p.Scopes, s) }

// InGroup reports IdP group membership.
func (p *Principal) InGroup(g string) bool { return contains(p.Groups, g) }

// Grants is the effective authorization of one caller for one config version:
// the only thing the data plane consults when deciding what a caller may spawn
// or see.
type Grants struct {
	Subject string
	// ServerTypes the caller may use, sorted for deterministic output.
	ServerTypes []string
	// Admin is true when a group grants admin or the token carries the admin scope.
	Admin bool
	// PodsPerUser is the effective per-user pod cap.
	PodsPerUser int
	// LazyTools is true when tools are exposed through meta-tools.
	LazyTools bool
	// Groups are the configured groups the caller belongs to.
	Groups []string
}

// Allows reports whether the caller may use a server type.
func (g Grants) Allows(serverType string) bool { return contains(g.ServerTypes, serverType) }

// InGroup reports whether the caller is in a configured group.
func (g Grants) InGroup(name string) bool { return contains(g.Groups, name) }

// NewGrants builds a Grants with sorted, de-duplicated lists.
func NewGrants(subject string, serverTypes, groups []string, admin bool, podsPerUser int, lazy bool) Grants {
	return Grants{Subject: subject, ServerTypes: sortedUnique(serverTypes), Groups: sortedUnique(groups),
		Admin: admin, PodsPerUser: podsPerUser, LazyTools: lazy}
}

// ToolRule is the exposure decision for one upstream tool: hidden, or visible
// under a (possibly renamed) name.
type ToolRule struct {
	Visible bool
	Name    string
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func sortedUnique(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// HasPrefixFold reports whether s starts with prefix, ignoring ASCII case.
func HasPrefixFold(s, prefix string) bool {
	return len(s) >= len(prefix) && strings.EqualFold(s[:len(prefix)], prefix)
}

type principalKey struct{}

// WithPrincipal stores the principal in the context.
func WithPrincipal(ctx context.Context, p *Principal) context.Context {
	return context.WithValue(ctx, principalKey{}, p)
}

// PrincipalFrom returns the principal stored by the identity middleware, or nil.
func PrincipalFrom(ctx context.Context) *Principal {
	p, _ := ctx.Value(principalKey{}).(*Principal)
	return p
}
