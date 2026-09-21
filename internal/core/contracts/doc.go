// Package contracts defines one interface per adapter kind. Adapters implement
// exactly one; the gateway, controller, router and admin listener depend only
// on these interfaces and on core, never on a concrete adapter.
//
//	kind         contract          in-tree types
//	identity     IdentityProvider  bearer_jwt, bearer_introspect
//	policy       AccessPolicy      groups
//	broker       TokenBroker       exchange, none, refresh-token
//	provision    Provisioner       local, kube
//	routing      RoutingTable      memory, redis
//	egress       EgressEnforcer    cilium, proxy, none
//	directory    Directory         keycloak
//	audit        AuditSink         stdout, file
package contracts
