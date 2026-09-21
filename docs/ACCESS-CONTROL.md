# Access control

## The model

Two things decide what a caller can do; they are computed once per request by the `AccessPolicy`
adapter (`authorization.type: groups`) into `Grants`, which is all the data plane consults.

- **Groups → server types.** `authorization.groups[]` maps IdP groups to the server types
  (adapters) a member may spawn, plus `podsPerUser` and `admin`. `*` grants every server type.
  `options.always_groups` names groups every authenticated caller implicitly holds (`everyone`).
- **Server type → tools.** `servers[].tools` filters what a pod's tools look like to callers:
  `expose` (allow or deny list of upstream names), `rename`, `prefix`, and `groups` (a tool only
  members of listed groups see). Admins see every tool.
- **Token scopes** decide *which API* a token may use, not which server types: `juggernaut:mcp` on
  the data plane, `juggernaut:admin` for cross-user reads and terminations, `juggernaut:users.admin`
  for the admin listener.

Isolation is per (user, server type): every pod runs with a token that names one user, reaches one
allowlist of hosts, and is reachable only from the gateway. Nothing is shared between users.

## What the gateway checks on every call

1. **Identity**: the identity adapter resolves the request or the middleware answers 401 with the
   adapter's challenge. No principal, no request.
2. **Token scope**: `juggernaut:mcp` on the data plane; `juggernaut:admin` where a handler acts on
   another user; `juggernaut:users.admin` or the admin role on the admin listener.
3. **Server type**: `/adapters/{name}/mcp` and every routed tool call check `Grants.Allows(name)`;
   an unknown or ungranted type is 404 / 403, and the router never lists its tools.
4. **Caps**: per-user pods (`Grants.PodsPerUser`), per-type `servers[].maxPods`, cluster-wide
   `gateway.caps.totalPods`, checked in the gateway before a Session is created and again in the
   controller.
5. **Session binding**: a gateway `Mcp-Session-Id` is bound to the subject that created it and to
   one pod; another subject presenting it gets 404, and the client re-initializes.
6. **Tool visibility**: `ToolRule` hides tools outside the allowlist, on the denylist, or reserved
   for other groups; `execute` and `describe_tool` refuse hidden names.
7. **Pod ingress**: the wrapper accepts only requests carrying that pod's secret, and the
   NetworkPolicy admits only gateway pods on the wrapper ports.

## Network isolation: what a compromised pod can reach

| Target | `cilium` | `proxy` | `none` |
|---|---|---|---|
| its allowlisted hosts on declared ports | ✅ | ✅ (through juggernaut-egress) | ✅ |
| any other internet host | ❌ `toFQDNs` | ❌ proxy refuses CONNECT | ✅ |
| arbitrary DNS names | ❌ DNS proxy allowlist | ❌ no resolver in the pod | ✅ |
| other users' pods, gateway, Redis, Keycloak | ❌ | ❌ | ❌ (default-deny + per-pod ingress) |
| Kubernetes API, cloud metadata 169.254.169.254 | ❌ | ❌ | ❌ (denied CIDRs) |

`none` needs `network.allowInsecure: true` and is for laptops. Pods always run under Pod Security
Admission `restricted`: non-root, read-only rootfs, no capabilities, seccomp RuntimeDefault, no
service-account token; `runtimeClassName` (gVisor, Kata) is a per-server switch.

## What you give up

- A user's pod for a server type is shared by all of that user's MCP clients; there is no
  per-client pod.
- Cold starts are real: the first request per (user, server type) waits up to
  `gateway.coldStartBudget`. Lazy tool loading spreads that over `execute` calls.
- Token modes `env` restart the child on rotation, which drops in-flight state inside the server.
- Every server image must bundle its runtime; `npx`/`uvx` at start would need registry egress the
  policy does not allow.
- `refresh-token` brokering for IdPs without exchange is not implemented; such IdPs are limited to
  token modes `none` and `static`.

## Checklist before opening to the team

- [ ] `identity.type` is `bearer_jwt` or `bearer_introspect`; `none` and `static` are not in use
- [ ] `gateway.publicURL` is the URL clients use (it is the resource in the metadata) and only a TLS proxy or Ingress reaches the data listener
- [ ] the admin listener stays on `127.0.0.1:24680`, reached by `kubectl port-forward`
- [ ] `network.egressEnforcer` is `cilium` or `proxy`; `allowInsecure` is false; every server declares its `egress` hosts
- [ ] `imagePolicy.requireDigest` is true and every `servers[].image` is pinned by digest
- [ ] `identity.broker.mode` is `exchange`, every server that acts on behalf of the user has a `token.audience`, and the IdP has an audience client per server type
- [ ] secrets come from `{env: ...}` / `{file: ...}` references, never literals; `JUGGERNAUT_KEK` is set so pod tokens are sealed in Redis
- [ ] a user in no extra group sees only what `always_groups` grants with `whoami`; a service token without `juggernaut:admin` cannot read another user's sessions
