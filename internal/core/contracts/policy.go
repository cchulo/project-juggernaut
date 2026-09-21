package contracts

import (
	"github.com/cchulo/project-juggernaut/internal/config"
	"github.com/cchulo/project-juggernaut/internal/core"
)

// AccessPolicy turns a Principal into Grants: the only place group membership
// becomes server-type access and tool visibility.
type AccessPolicy interface {
	// Grants computes the caller's grants. clientName is initialize.clientInfo.name
	// (empty before initialize) and only influences lazy loading.
	Grants(p *core.Principal, clientName string) core.Grants
	// ToolRule applies a server's exposure rules to an upstream tool for these grants.
	ToolRule(g core.Grants, s *config.Server, upstreamTool string) core.ToolRule
}
