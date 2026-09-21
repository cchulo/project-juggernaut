// Package groups is the policy adapter that maps IdP groups (authorization.groups
// in juggernaut.yaml) to server types, per-user caps, admin and tool visibility.
// It is the port of cerebro's `policy.type: groups`.
//
// Options: always_groups (groups every authenticated caller implicitly holds,
// e.g. [everyone], so a group entry named everyone grants to all users).
package groups

import (
	"github.com/cchulo/project-juggernaut/internal/config"
	"github.com/cchulo/project-juggernaut/internal/core"
	"github.com/cchulo/project-juggernaut/internal/core/contracts"
	"github.com/cchulo/project-juggernaut/internal/core/registry"
)

// Type is the registry name.
const Type = "groups"

func init() { registry.Policy.Register(Type, New) }

// Adapter computes grants from configuration.
type Adapter struct{ ctx *core.Context }

// New builds the adapter.
func New(ctx *core.Context) (contracts.AccessPolicy, error) { return &Adapter{ctx: ctx}, nil }

// Grants derives grants for p under the current config.
func (a *Adapter) Grants(p *core.Principal, clientName string) core.Grants {
	c := a.ctx.Cfg()
	podsPerUser := c.Gateway.Caps.PodsPerUser
	admin := p.HasScope(c.Identity.Scopes.Admin)
	lazy := c.Gateway.Tools.DefaultLoading == "lazy"
	var serverTypes, groups []string
	always := a.alwaysGroups()
	for _, grp := range c.Authorization.Groups {
		if !p.InGroup(grp.Name) && !always[grp.Name] {
			continue
		}
		groups = append(groups, grp.Name)
		if grp.Admin {
			admin = true
		}
		if grp.PodsPerUser > podsPerUser {
			podsPerUser = grp.PodsPerUser
		}
		if grp.Tools != nil && grp.Tools.Loading == "lazy" {
			lazy = true
		}
		for _, st := range grp.ServerTypes {
			if st == "*" {
				serverTypes = append(serverTypes, c.ServerNames()...)
				continue
			}
			if c.Server(st) != nil {
				serverTypes = append(serverTypes, st)
			}
		}
	}
	for _, lg := range c.Gateway.Tools.LazyForGroups {
		for _, g := range groups {
			if g == lg {
				lazy = true
			}
		}
	}
	for _, lc := range c.Gateway.Tools.LazyForClients {
		if clientName != "" && core.HasPrefixFold(clientName, lc) {
			lazy = true
		}
	}
	return core.NewGrants(p.Subject, serverTypes, groups, admin, podsPerUser, lazy)
}

func (a *Adapter) alwaysGroups() map[string]bool {
	out := map[string]bool{}
	if raw, ok := a.ctx.Options["always_groups"]; ok {
		for _, g := range asStrings(raw) {
			out[g] = true
		}
	}
	return out
}

func asStrings(v any) []string {
	switch t := v.(type) {
	case []string:
		return t
	case []any:
		out := make([]string, 0, len(t))
		for _, e := range t {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// ToolRule applies allow/deny lists, per-group visibility and renames.
func (a *Adapter) ToolRule(g core.Grants, s *config.Server, upstream string) core.ToolRule {
	if s.Tools.Expose != nil {
		listed := contains(s.Tools.Expose.Names, upstream)
		switch s.Tools.Expose.Mode {
		case "allow":
			if !listed {
				return core.ToolRule{}
			}
		case "deny":
			if listed {
				return core.ToolRule{}
			}
		}
	}
	if groups, ok := s.Tools.Groups[upstream]; ok && !g.Admin {
		visible := false
		for _, grp := range groups {
			if g.InGroup(grp) {
				visible = true
				break
			}
		}
		if !visible {
			return core.ToolRule{}
		}
	}
	name := upstream
	if renamed, ok := s.Tools.Rename[upstream]; ok {
		name = renamed
	}
	return core.ToolRule{Visible: true, Name: name}
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
