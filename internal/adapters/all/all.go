// Package all registers every in-tree adapter. Binaries blank-import it; a
// custom build that wants a different set (or an out-of-tree adapter) imports
// the packages it needs instead.
package all

import (
	_ "github.com/cchulo/project-juggernaut/internal/adapters/audit/file"
	_ "github.com/cchulo/project-juggernaut/internal/adapters/audit/stdout"
	_ "github.com/cchulo/project-juggernaut/internal/adapters/broker/exchange"
	_ "github.com/cchulo/project-juggernaut/internal/adapters/broker/none"
	_ "github.com/cchulo/project-juggernaut/internal/adapters/broker/refresh_token"
	_ "github.com/cchulo/project-juggernaut/internal/adapters/directory/keycloak"
	_ "github.com/cchulo/project-juggernaut/internal/adapters/egress/cilium"
	_ "github.com/cchulo/project-juggernaut/internal/adapters/egress/none"
	_ "github.com/cchulo/project-juggernaut/internal/adapters/egress/proxy"
	_ "github.com/cchulo/project-juggernaut/internal/adapters/identity/bearer_introspect"
	_ "github.com/cchulo/project-juggernaut/internal/adapters/identity/bearer_jwt"
	_ "github.com/cchulo/project-juggernaut/internal/adapters/policy/groups"
	_ "github.com/cchulo/project-juggernaut/internal/adapters/provision/kube"
	_ "github.com/cchulo/project-juggernaut/internal/adapters/provision/local"
	_ "github.com/cchulo/project-juggernaut/internal/adapters/routing/memory"
	_ "github.com/cchulo/project-juggernaut/internal/adapters/routing/redis"
)
