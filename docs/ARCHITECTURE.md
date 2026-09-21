# Code architecture

Juggernaut's Go code follows the same shape as cerebro: a small **core** of shared types, one
**contract** (interface) per kind of pluggable component, **adapters** that each implement exactly
one contract, a **registry** that maps the `type:` names in `juggernaut.yaml` to adapter
constructors, and **composition roots** that are the only place adapters are chosen. Every other
package depends on contracts, never on an adapter.

```
internal/core             Principal, Grants, session/pod ids, Sealer, Context, Secrets   (depends on config)
internal/core/contracts   IdentityProvider, AccessPolicy, TokenBroker, Provisioner,
                          RoutingTable, EgressEnforcer, Directory, AuditSink, SessionManager
internal/core/registry    typed registries; adapters register in init()
internal/adapters/<kind>/<type>   one package per adapter, exporting New and Type
internal/gateway, router, controller, admin, audit   consumers: contracts only
internal/app              GatewayFromConfig / ControllerFromConfig: selectors → adapters → wiring
cmd/*                     flags, logging, signals; blank-import internal/adapters/all
```

## Kinds, contracts and selectors

| Kind | Contract | Selector in `juggernaut.yaml` | In-tree types |
|------|----------|-------------------------------|---------------|
| identity | `IdentityProvider` (request → Principal, challenge, PRM) | `identity.type` (+ `identity.options`) | `bearer_jwt`, `bearer_introspect` |
| policy | `AccessPolicy` (Principal → Grants, tool rules) | `authorization.type` | `groups` |
| broker | `TokenBroker` (per-user downstream token) | `identity.broker.mode` | `exchange`, `none`, `refresh-token` |
| provision | `Provisioner` (ensure / status / release / logs) | `gateway.runtime.kind` | `local`, `kube` |
| routing | `RoutingTable` (session ids, pods, activity) | `gateway.routing.type` | `memory`, `redis` |
| egress | `EgressEnforcer` (objects, hooks, pod env) | `network.egressEnforcer` | `cilium`, `proxy`, `none` |
| directory | `Directory` (admin user management) | `identity.keycloakAdmin` present | `keycloak` |
| audit | `AuditSink` (persist records) | `gateway.audit.sink` | `stdout`, `file` |

`SessionManager` is not an adapter kind. It is the gateway's core use case (`gateway.Manager`),
implemented once and consumed by the data plane, the router and the admin listener through the
contract.

## How the SOLID principles map

- **Single responsibility**: `gateway.Manager` owns the (user, server type) → pod use case;
  `gateway.Authn` owns the challenge flow; `audit.Logger` owns redaction; each adapter owns one
  external system. The old `controller.Isolation` was split into three egress adapters plus a
  generic `applyObject`.
- **Open/closed**: adding an IdP, a store or an enforcer is a new package under
  `internal/adapters/<kind>/` that calls `registry.<Kind>.Register` in `init()` and one line in
  `internal/adapters/all`. No existing package changes.
- **Liskov**: adapters are exchanged freely at the composition root; consumers hold only the
  contract, and tests substitute fakes (see `internal/audit/audit_test.go`).
- **Interface segregation**: contracts are small and role-shaped. The router needs
  `SessionManager`, `TokenBroker`, `RoutingTable` and `AccessPolicy`; it does not see the
  provisioner. The admin listener sees `Directory`, `IdentityProvider` and `SessionManager`.
- **Dependency inversion**: `internal/app` is the only package that imports both contracts and
  adapters. `cmd/*` binaries blank-import `internal/adapters/all`; a custom build can import a
  different set, including out-of-tree adapters, without editing a registry file.

## Adding an adapter

1. Create `internal/adapters/<kind>/<type>/adapter.go` with `const Type`, a `New(*core.Context)`
   constructor returning the contract, and `func init() { registry.<Kind>.Register(Type, New) }`.
2. Read your configuration from `ctx.Cfg()` (the typed file) and `ctx.Options` (the free-form
   `options:` map of your selector). Read secrets through `ctx.Secrets`, never from the config.
3. Add the blank import to `internal/adapters/all/all.go`.
4. `juggernaut adapters` lists what the binary can build; `juggernaut validate` checks the file.

## Differences from cerebro

- cerebro resolves `type: mypkg.mod:Class` by importing at runtime. Go links statically, so the
  registry is populated by `init()` and the set of available adapters is fixed at build time.
- cerebro's `Adapter` base class carries `units()`/`jobs()` so adapters can ask the provisioner for
  workloads. Juggernaut's server types are data (`servers[]`), so that hook is not needed; the
  provisioner is asked for pods by the `SessionManager`.
- `Locator` (unit name → URL) has no counterpart: pods are addressed by the endpoint the
  provisioner reports in `PodStatus`.
