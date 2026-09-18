// Package authz converts a validated Principal into Grants: which server types
// the caller may spawn, which tools they may see, and per-user limits. It keeps
// cerebro's Principal → Grants shape.
package authz

import (
	"sort"

	"github.com/cchulo/project-juggernaut/internal/auth"
	"github.com/cchulo/project-juggernaut/internal/config"
)

// Grants is the effective authorization of one caller for one config version.
type Grants struct {
	// ServerTypes the caller may use, sorted.
	ServerTypes []string
	// Admin is true when any group grants admin or the token carries the admin scope.
	Admin bool
	// PodsPerUser is the effective per-user pod cap (max over groups, else gateway default).
	PodsPerUser int
	// LazyTools is true when tools should be exposed through meta-tools.
	LazyTools bool
	groups    map[string]bool
}

// Compute derives grants for p under c. clientName is initialize.clientInfo.name
// (may be empty before initialize) and only influences lazy loading.
func Compute(c *config.Config, p *auth.Principal, clientName string) Grants {
	g := Grants{PodsPerUser: c.Gateway.Caps.PodsPerUser, groups: map[string]bool{}}
	set := map[string]bool{}
	lazy := c.Gateway.Tools.DefaultLoading == "lazy"
	for _, grp := range c.Authorization.Groups {
		if !p.InGroup(grp.Name) {
			continue
		}
		g.groups[grp.Name] = true
		if grp.Admin {
			g.Admin = true
		}
		if grp.PodsPerUser > g.PodsPerUser {
			g.PodsPerUser = grp.PodsPerUser
		}
		if grp.Tools != nil && grp.Tools.Loading == "lazy" {
			lazy = true
		}
		for _, st := range grp.ServerTypes {
			if st == "*" {
				for _, s := range c.Servers {
					set[s.Name] = true
				}
				continue
			}
			set[st] = true
		}
	}
	if p.HasScope(c.Identity.Scopes.Admin) {
		g.Admin = true
	}
	for _, lg := range c.Gateway.Tools.LazyForGroups {
		if g.groups[lg] {
			lazy = true
		}
	}
	for _, lc := range c.Gateway.Tools.LazyForClients {
		if clientName != "" && hasPrefixFold(clientName, lc) {
			lazy = true
		}
	}
	g.LazyTools = lazy
	for name := range set {
		if c.Server(name) != nil {
			g.ServerTypes = append(g.ServerTypes, name)
		}
	}
	sort.Strings(g.ServerTypes)
	return g
}

// Allows reports whether the caller may use a server type.
func (g Grants) Allows(serverType string) bool {
	for _, s := range g.ServerTypes {
		if s == serverType {
			return true
		}
	}
	return false
}

// InGroup reports whether the caller is in a configured group.
func (g Grants) InGroup(name string) bool { return g.groups[name] }

// ToolVisible applies a server's exposure rules to an upstream tool name for this caller.
// It returns the exposed (possibly renamed) name and whether it is visible.
func (g Grants) ToolVisible(s *config.Server, upstreamName string) (string, bool) {
	if s.Tools.Expose != nil {
		listed := contains(s.Tools.Expose.Names, upstreamName)
		switch s.Tools.Expose.Mode {
		case "allow":
			if !listed {
				return "", false
			}
		case "deny":
			if listed {
				return "", false
			}
		}
	}
	if groups, ok := s.Tools.Groups[upstreamName]; ok && !g.Admin {
		visible := false
		for _, grp := range groups {
			if g.groups[grp] {
				visible = true
				break
			}
		}
		if !visible {
			return "", false
		}
	}
	name := upstreamName
	if renamed, ok := s.Tools.Rename[upstreamName]; ok {
		name = renamed
	}
	return name, true
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func hasPrefixFold(s, prefix string) bool {
	if len(prefix) > len(s) {
		return false
	}
	return equalFold(s[:len(prefix)], prefix)
}

func equalFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if 'A' <= ca && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if 'A' <= cb && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}
