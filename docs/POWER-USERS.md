# Juggernaut in depth

For operators who have finished the [quickstart](QUICKSTART.md) and want to know every knob,
what it does, and what happens underneath. Sections follow `juggernaut.yaml`; the schema is
`schemas/juggernaut.schema.json` (`juggernaut schema` prints it for editor completion).

## 1. The file

- One file, `juggernaut.yaml`, is the source of truth. `apiVersion: juggernaut.io/v1alpha1`,
  `kind: Config`. Unknown keys are rejected.
- Secrets never appear as values. Every secret is a reference: `{ env: NAME }` reads an
  environment variable, `{ file: /path }` reads a file (mounted Secret). References are resolved
  at use time, so a rotated file is picked up on the next use.
- `${NAME}` and `${NAME:-default}` inside any string are interpolated from the environment when
  the file loads, so one file can name different endpoints in compose and Kubernetes. Do not put
  secrets in interpolated strings; use references.
- Adapter selectors have the shape `type` plus a free-form `options` map that only that adapter
  reads: `identity.type` / `identity.options`, `authorization.type` / `options`,
  `identity.broker.mode` / `options`, `gateway.routing.type` / `options`, `gateway.audit.sink` /
  `options`. `gateway.runtime.kind` and `network.egressEnforcer` are selectors without an options
  map (their settings live next to them).
- Validation is two-stage: the JSON Schema (structure), then semantic rules (`juggernaut validate
  -f file`): every server type a group names exists, egress hosts are valid FQDNs, `env` token
  mode needs `token.env`, `header` mode is impossible for stdio, images are digest-pinned unless
  `imagePolicy.requireDigest: false`, `none`/`static` identity runs with `broker.mode: none`, the
  admin listener is loopback-bound or has TLS, and so on. `juggernaut render -f file` prints the
  fully defaulted document as JSON.
- Hot reload: the gateway and the controller watch the mounted file (fsnotify plus a 30-second
  hash poll for ConfigMap symlink swaps). A valid change swaps in atomically; an invalid one is
  logged, counted in `juggernaut_config_reload_errors_total`, and the previous config stays live.

## 2. `identity`

| Key | Meaning |
|---|---|
| `type` | `none`, `static`, `bearer_jwt` (default), `bearer_introspect` (default when `introspection.enabled`) |
| `issuer`, `audience` | required for `bearer_*`: OIDC issuer (discovery must work from the gateway) and the `aud` tokens must carry |
| `jwksURL` | skip discovery and fetch keys here |
| `groupsClaim`, `usernameClaim` | claim names; `groupsClaim` may be a dotted path (`realm_access.roles`) |
| `scopes.mcp` / `admin` / `usersAdmin` | scope names the gateway requires (`juggernaut:mcp`, `juggernaut:admin`, `juggernaut:users.admin`) |
| `principal` | `type: none`: the fixed principal (`subject`, `groups`, `scopes`, `kind`) |
| `allowRemote`, `staticTokenEnv` | `type: none`: accept non-loopback peers, but require `Bearer $JUGGERNAUT_TOKEN` on every request |
| `tokens` | `type: static`: bearer string → principal seed |
| `introspection` | `enabled`, `interval`, `endpoint`, `clientId`, `clientSecretRef` for RFC 7662 revocation checks |
| `broker` | see §3 |
| `keycloakAdmin` | enables the admin listener: `realm`, `clientId`, `clientSecretRef`, `baseURL` (defaults to the issuer's origin), `adminRole` (default `juggernaut-admin`) |

Adapter options: `bearer_jwt`: `jwks_url`, `skip_audience_check` (never in production).
`bearer_introspect`: those plus `fail_open` (default **false**: an unreachable introspection
endpoint rejects the request; set true only if availability matters more than revocation latency).

What a principal looks like after resolution: subject, username, display name, `kind` (`user`, or
`service` for client-credentials tokens: no `email` / `preferred_username` and `azp` or
`client_id` equal to `sub`), groups (Keycloak `/path` prefixes trimmed; Keycloak realm roles added
as groups), token scopes. `whoami` on `/mcp` prints it.

Details and the discovery flow: [IDENTITY.md](IDENTITY.md).

## 3. `identity.broker`: per-user tokens for pods

| `mode` | What the pod receives |
|---|---|
| `exchange` | an RFC 8693 exchanged token: same `sub`, `aud` = `servers[].token.audience`, optional `scope` = `servers[].token.scopes`; cached per (incoming token, server type) until 60s before expiry and never past the incoming token's expiry |
| `none` | nothing; servers must use token modes `none` or `static` |
| `refresh-token` | placeholder, not implemented |

`exchange` needs `clientId` and `clientSecretRef` (the gateway's confidential client with token
exchange enabled) and, optionally, `tokenEndpoint` (option `token_endpoint`) when the IdP does not
use Keycloak's layout. Each server type that acts on behalf of the user needs an audience the IdP
knows (`jira-mcp`, `github-mcp` in the reference realm).

Rotation: the client refreshes its own token; the next request carries a new one, which yields a
new exchange. For stdio servers in `env` token mode the wrapper restarts the child at the next
idle boundary so the new token is in its environment; `file` mode rewrites the tmpfs file per
request; `header` mode needs nothing. Revocation: disabling a user in the admin UI, or
`DELETE /users/{sub}/sessions`, terminates the pods and drops the exchange cache; with
`bearer_introspect` a revoked token is refused within `introspection.interval`.

## 4. `gateway`

| Key | Default | Meaning |
|---|---|---|
| `publicURL` | required | what clients use; the `resource` in the protected-resource metadata |
| `listeners.data` / `admin` / `metrics` | `:8080` / `127.0.0.1:24680` / `:9090` | three separate servers; the admin listener must be loopback or carry `tls` (or `allowInsecureAdmin: true`); `tls.clientCAFile` requires client certificates |
| `runtime.kind` | `kube` | `local` (docker or process on this host) or `kube` (the controller) |
| `runtime.local` | | `mode: docker | process`, `wrapperBinary`, `network`, `portRange` |
| `routing.type` | `redis` when `redis` is set, else `memory` | where session ids, pods and activity live; `kube` requires `redis` |
| `redis` | | `address`, `passwordRef`, `db`, `keyPrefix` (`jg:`) |
| `coldStartBudget` | `60s` (max `180s`) | how long a request holds while a pod starts; then `503` + `Retry-After: 10` |
| `idleTimeout` | `15m` | reaper default; per-server override |
| `maxSessionAge` | `12h` | recycle even if active (hard stop at +15m) |
| `maxBodyBytes` | 4 MiB | request body cap |
| `caps.podsPerUser`, `caps.totalPods` | 5, 2000 | hard caps; groups may raise `podsPerUser` |
| `tools.defaultLoading` | `eager` | `eager` lists every namespaced tool; `lazy` exposes meta-tools |
| `tools.lazyForClients` | | `initialize.clientInfo.name` prefixes (case-insensitive) that get lazy mode (`cursor`) |
| `tools.lazyForGroups` | | groups that get lazy mode |
| `tools.namespaceSeparator` | `__` | `<adapter>__<tool>` |
| `audit.sink` | `stdout` | `stdout`, `file` (`audit.file`, option `path`), `otlp` (stdout for now) |
| `audit.redactArguments` | password, token, secret, authorization, api_key, apikey | argument keys whose values are replaced; bearer- and JWT-shaped strings are always redacted |
| `telemetry.otlpEndpoint`, `serviceName`, `sampleRatio` | off | OTLP/HTTP traces |

Routing adapter options: `redis`: `key_prefix`, `seal_pod_tokens` (default true; needs
`JUGGERNAUT_KEK`, base64 of 32 bytes, in the gateway's environment; without it tokens are stored
unsealed and a warning is logged). With the KEK present every pod and session record also carries
an HMAC; a tampered record reads as not found.

Local provisioner options: `state_dir` (default `$JUGGERNAUT_STATE_DIR` or `/var/lib/juggernaut`).
`mode: docker` runs `docker run --read-only --cap-drop ALL` with the server image and the wrapper
as entrypoint on a per-user bridge network `<runtime.local.network>-<userHash>` (the gateway
container joins it when `JUGGERNAUT_CONTAINER_NAME` is set); `mode: process` execs `wrapperBinary` directly with
ports from `portRange`. Neither isolates anything; they exist for development.

## 5. `network`

| Key | Default | Meaning |
|---|---|---|
| `sessionsNamespace` | `juggernaut-sessions` | where session pods run |
| `egressEnforcer` | `cilium` | `cilium` (CiliumNetworkPolicy `toFQDNs` + DNS proxy rules), `proxy` (juggernaut-egress CONNECT proxy, pods without a resolver), `none` (laptops; requires `allowInsecure: true`) |
| `proxy.address` | | required in proxy mode; exported to pods as `HTTPS_PROXY` |
| `podAuth` | `shared-secret` | `mtls` (recommended, needs `runtime.kind: kube`): controller-issued per-pod certificates, both sides verify SPIFFE identities; `shared-secret`: the per-pod secret header only, no TLS (laptops) |
| `mtls.*` | `/etc/juggernaut/tls/{tls.crt,tls.key,ca.crt}`, Secrets `juggernaut-pod-ca` / `juggernaut-gateway-client-tls`, trust domain `juggernaut` | where the gateway finds its client certificate and what the controller names its Secrets |
| `gatewayPodSelector` | `app.kubernetes.io/name: juggernaut-gateway` | who may reach pods |
| `denyCIDRs`, `apiServerCIDR` | metadata + link-local + `fd00::/8` | never reachable even in `none` |
| `imagePolicy.requireDigest` | true | `servers[].image` must be `@sha256:...` |
| `imagePolicy.cosign` | off | parsed, not yet enforced |

Egress proxy adapter options: `allowlist_configmap` (`juggernaut-egress-allowlist`),
`system_namespace` (`juggernaut-system`). The controller publishes `{podIP: {session, hosts}}`
there when a pod becomes Ready and removes it on cleanup; `juggernaut-egress` reloads it on change
and on a 10-second poll, accepts CONNECT only for listed (pod IP, host:port), resolves the name
itself, and refuses results inside denied or private CIDRs. Wildcards `*.example.com` match one
label.

How to verify from inside a pod: `deploy/policies/README.md`.

## 6. `servers[]`

| Key | Meaning |
|---|---|
| `name` | DNS-label; the adapter name in URLs and tool namespaces |
| `image` | digest-pinned unless `requireDigest: false`; must contain the server and its runtime (no `npx` at start: the pod has no registry egress) |
| `transport` | `stdio` (wrapper owns the child), `streamable-http` or `sse` (server binds to loopback in the pod; wrapper reverse-proxies `http.path`, default `/mcp`, port `http.port`, default 8081) |
| `command`, `args`, `env`, `envFrom` | the child; `command[0]` must be an absolute path |
| `wrapper` | `restart.maxRestarts` (5) / `window` (10m) / `backoffMax` (30s), `startupTimeout` (20s), `logRedaction` (true), `port` (9000), `readinessPort` (9001) |
| `token.mode` | `env` (child env `token.env`, needs restart on rotation), `file` (`token.file`, default `/run/juggernaut/token`, tmpfs, rewritten per request), `header` (HTTP transports only; `token.header` / `token.scheme`), `static` (`token.staticRef`: one shared credential, discouraged), `none` |
| `token.audience`, `token.scopes` | what the broker requests for this server |
| `egress[]` | `host` (FQDN or `*.suffix`), `ports` (default 443), `protocol` (TCP); required unless `egressEnforcer: none` |
| `resources` | requests 100m/128Mi, limits 500m/512Mi by default |
| `runtimeClassName` | gVisor / Kata switch; the class must exist |
| `idleTimeout`, `maxSessionAge`, `maxPods` (200) | per-type overrides and cap |
| `security` | `writableTmp` (emptyDir at `/tmp`), `runAsUser` / `runAsGroup` (65532), `readOnlyRootFilesystem` (true), `extraWritablePaths` |
| `tools` | see §7 |

Images that will not tolerate the restricted defaults usually need `security.writableTmp: true`
(Node, Python caches) or an `extraWritablePaths` entry; keep `readOnlyRootFilesystem` on.

Pod anatomy (Kubernetes): one container `wrapper` running the server image with
`/juggernaut-wrapper` as command (or `/opt/juggernaut/juggernaut-wrapper` copied in by an init
container from `--wrapper-image` when the image lacks it), `/etc/juggernaut/wrapper.json` from the
`<type>-wrapper` ConfigMap, `/run/juggernaut-secret/pod-token` from the per-session Secret,
`/run/juggernaut` tmpfs, readiness on `/readyz` every second, liveness on `/healthz`.

## 6b. `servers[].userSecrets`: credentials the user supplies

For servers that need the user's own third-party credentials (mcp-atlassian with Jira and
Confluence API tokens), declare what the server needs and where it reads it:

```yaml
    token: { mode: none }
    userSecrets:
      sources: [sealed, store, header]         # lookup order; omit any you do not want to accept
      items:
        - { name: JIRA_USERNAME,  env: JIRA_USERNAME,  required: true }
        - { name: JIRA_API_TOKEN, env: JIRA_API_TOKEN, required: true }
```

`env` is for stdio children (set at start; a change restarts the child at the next idle
boundary), `header` for HTTP servers (per request), `file` for either (tmpfs). A required item
missing from every source is a JSON-RPC error (`-32001`) before any pod is spawned.

How users supply them, per source:

| Source | User does | Gateway holds |
|---|---|---|
| `sealed` | runs `juggernaut connect` and points the client at `http://127.0.0.1:8090/mcp` | nothing readable, ever |
| `store` | `juggernaut secrets init --passphrase ...`, `juggernaut secrets set atlassian JIRA_API_TOKEN=...`, then the client sends `X-Juggernaut-Vault-Key` | ciphertext at rest; plaintext for one request |
| `header` | puts `X-Juggernaut-Secret-<NAME>` in the client config | nothing |

`gateway.userSecrets.store` selects where entries live (`memory`, `redis`; default the routing
type); header names are configurable under `gateway.userSecrets`. The full model, including what
each attacker can read, is in [SECURITY.md](SECURITY.md).

## 7. Tool exposure and the router

Per server, `tools`:

```yaml
tools:
  expose: { mode: allow, names: [jira_get_issue, jira_search] }   # allow | deny | all
  rename: { jira_search: search_issues }                           # exposed name
  prefix: "jira_"                                                  # documentation only today
  groups: { jira_create_issue: [engineering, product] }            # visible only to these groups (admins see all)
```

On `/adapters/{name}/mcp` the pod's tools appear under their own names; the gateway does not
filter that endpoint's tool list today (the pod exposes what the server has). On `/mcp` the router
applies the rules: hidden tools are absent from `tools/list`, `search_tools` and `describe_tool`,
and `execute` refuses them.

Every tool call re-resolves the caller from the request's current bearer and recomputes grants
before forwarding, so a revoked token or a changed group takes effect on the next call. Eager
mode registers every visible tool of every granted adapter as `<adapter>__<name>` when the
client finishes `initialize`. Listing tools needs a pod per adapter, so the first user of an
adapter pays its cold start at connect time; the tool list is then cached per (adapter, config
hash) for 10 minutes for everyone. Lazy mode registers `search_tools`, `describe_tool`, `execute`
and enumerates on demand. `whoami` is always present. Which mode a session gets:
`tools.defaultLoading`, then `lazyForGroups`, then `lazyForClients` matched against the client
name; any match means lazy.

## 8. `authorization`

```yaml
authorization:
  type: groups
  options: { always_groups: [everyone] }     # groups every authenticated caller implicitly holds
  groups:
    - { name: engineering, serverTypes: [jira, github], podsPerUser: 5 }
    - { name: support, serverTypes: [jira], tools: { loading: lazy } }
    - { name: juggernaut-admins, serverTypes: ["*"], admin: true }
```

Grants are the union over the caller's groups: server types (sorted, `*` = all), the maximum
`podsPerUser`, `admin` if any group says so or the token carries `juggernaut:admin`, lazy if any
source says so. What is checked where: [ACCESS-CONTROL.md](ACCESS-CONTROL.md).

## 9. Operations

**Kubernetes objects you will see**

```sh
kubectl -n juggernaut-sessions get servertypes          # one per servers[] entry, with the config hash
kubectl -n juggernaut-sessions get sessions             # TYPE, USER (hash), PHASE, AGE
kubectl -n juggernaut-sessions describe session jira-3f9a1c2b
kubectl -n juggernaut-system get configmap juggernaut-egress-allowlist -o yaml   # proxy mode
```

Phases: `Pending` → `Starting` → `Ready` → (`Idle`) → `Terminating` → gone; `Failed` with a
message on image pull errors, crash loops or a vanished pod. Setting `spec.desiredPhase:
Terminating` on a Session by hand terminates it; deleting the Session does the same.

**Reaper**: every 30 seconds, for each Ready/Idle session: terminate when idle beyond the type's
`idleTimeout` with nothing in flight, when older than `maxSessionAge` with nothing in flight, or
unconditionally at `maxSessionAge` + 15m. In-flight counts and last-activity times come from the
routing table; with `routing.type: memory` the controller cannot see gateway activity and reaps
on age alone (a warning says so).

**Controller flags**: `--config`, `--wrapper-image` (`JUGGERNAUT_WRAPPER_IMAGE`),
`--metrics-bind-address` (`:9091`), `--health-probe-bind-address` (`:8081`), `--leader-elect`.
Gateway flags: `--config` (`JUGGERNAUT_CONFIG`), `--log-level` (`JUGGERNAUT_LOG_LEVEL`).
Egress: `--listen`, `--allowlist`, `--deny-cidrs`. Wrapper: `--config` (`JUGGERNAUT_WRAPPER_CONFIG`),
`--install <path>` (init-container mode).

**Environment the binaries read**: `JUGGERNAUT_KEK` (seal pod tokens in Redis), `JUGGERNAUT_TOKEN`
(or `identity.staticTokenEnv`) for `none` + `allowRemote`, `JUGGERNAUT_TRUSTED_NETWORK=1` (set by
a provisioner on the gateway workload in `none` mode, never by hand), `JUGGERNAUT_STATE_DIR`
(local provisioner), plus whatever your `SecretRef`s name.

**RBAC**: the gateway's Role in the sessions namespace allows `sessions` get/list/watch/create/delete,
`servertypes` read, `secrets` create/delete, `pods/log` get. The controller's Role owns
`sessions`, `servertypes`, `pods`, `secrets`, `configmaps`, `events`, `networkpolicies`,
`ciliumnetworkpolicies` there, plus leases and the allowlist ConfigMap in the system namespace.

**Helm values worth knowing**: `config` (`--set-file config=juggernaut.yaml`),
`secrets.existingSecret` or the individual `secrets.*` (a KEK is generated when empty),
`gateway.ingress.*`, `gateway.exposeAdminOnService` (false; keep it that way),
`egress.enabled`, `redis.enabled`, `keycloak.enabled` with `keycloak.service.nodePort` for kind,
`namespaces.sessionsPSA` (`restricted`). `make helm-template` renders the chart for a syntax check.

**Metrics** (`:9090` gateway, `:9091` controller): `juggernaut_pods_active{server_type,phase}`,
`juggernaut_cold_start_seconds`, `juggernaut_idle_terminations_total{reason}`,
`juggernaut_auth_failures_total{reason}`, `juggernaut_tool_calls_total{server_type,outcome}`,
`juggernaut_tool_call_seconds`, `juggernaut_config_reload_errors_total`,
`juggernaut_egress_decisions_total{decision}`.

**Audit** (one JSON line per event): `kind` is `tool_call` (router), `adapter_request`
(per-adapter endpoint) or `admin_action`; fields subject, serverType, pod, sessionId, tool,
upstreamTool, arguments (redacted), durationMs, outcome (`ok`, `tool_error`, `error`), error, lazy.
Ship stdout to your log pipeline or use `sink: file`.

## 10. CLI and API

```sh
juggernaut validate -f juggernaut.yaml       # schema + semantic rules; prints hash, counts
juggernaut render   -f juggernaut.yaml       # defaulted config as JSON
juggernaut schema                            # JSON Schema
juggernaut adapters                          # adapter types compiled into this binary
juggernaut admin login --issuer https://kc/realms/juggernaut   # device flow; prints a token
juggernaut secrets init --passphrase '...'                     # create the local vault (key cached 0600)
juggernaut secrets set atlassian JIRA_USERNAME=a@x JIRA_API_TOKEN=...   # seal + upload (merges)
juggernaut secrets list | delete <adapter> | rotate --passphrase '<new>'
juggernaut connect --gateway https://mcp.example.internal      # tier-B companion on 127.0.0.1:8090
```

`secrets` and `connect` take `--gateway` (`JUGGERNAUT_GATEWAY`), `--issuer` (`JUGGERNAUT_ISSUER`)
and `--client-id` (default `mcp-client`, which needs the device grant enabled), or an existing
token in `JUGGERNAUT_ACCESS_TOKEN`.

Control plane (bearer with `juggernaut:mcp`; `juggernaut:admin` where noted):

| Method and path | Returns |
|---|---|
| `GET /adapters`, `GET /adapters/{name}` | adapters the caller may use, with transport, token mode, egress, timeouts, config hash |
| `GET /adapters/{name}/status` | pods by phase, `maxPods` |
| `GET /adapters/{name}/logs?tailLines=500[&user=sub]` | the caller's pod logs (another user's with admin) |
| `GET /tools`, `GET /tools/{name}` | allowlisted tool names per adapter (live metadata comes from the router) |
| `GET /sessions`, `GET /sessions/{id}`, `DELETE /sessions/{id}` | the caller's session pods; delete terminates one |
| `GET /users/{sub}/sessions`, `DELETE /users/{sub}/sessions` | admin: another user's pods; delete terminates all and revokes cached tokens |
| `GET /me/secrets`, `PUT /me/secrets/{adapter}`, `DELETE /me/secrets/{adapter}` | the caller's sealed entries (ciphertext; the CLI is the intended client); a put or delete recycles that adapter's pod |
| `GET /adapters/{name}/session-key` | the caller's pod's ephemeral public key for tier-B sealing (spawns the pod if needed) |
| `GET /.well-known/oauth-protected-resource` | RFC 9728 metadata (404 for `none`/`static`) |
| `GET /healthz`, `GET /readyz` | liveness; readiness checks the routing table |

Admin listener (`127.0.0.1:24680`, bearer with the admin role or `juggernaut:users.admin`):
`/admin/` (the SPA), `/admin/api/me`, `/config`, `/users`, `/users/{id}`, `/users/{id}/groups`,
`/users/{id}/reset-password`, `/users/{id}/sessions`, `/groups`, and unauthenticated
`/admin/api/oidc` (issuer and client id for the SPA's PKCE flow). The full API is `api/openapi.yaml`.

## 11. Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `401` on every call, `WWW-Authenticate` names a metadata URL | no or wrong bearer; the client should follow the URL. Check `identity.issuer`/`audience` match what the IdP signs (`aud` must include `identity.audience`) |
| `401` and the challenge is a bare `Bearer` | `identity.type` is `none` or `static`: no OAuth here; peer not loopback (`none`) or unknown token (`static`) |
| `403 adapter not granted to caller` | the caller's groups do not name the server type; check `groupsClaim` and the token's groups with `whoami` |
| `429 pod cap reached` | `caps.podsPerUser`, `servers[].maxPods` or `caps.totalPods`; `GET /sessions` shows what is running |
| `503 session pod starting; retry` | cold start exceeded `coldStartBudget`; `kubectl describe session` shows why (image pull, probe) |
| `502 could not obtain a downstream token` | token exchange failed: exchange not enabled on the gateway client, missing audience client, wrong `clientSecretRef` |
| `422 adapter X requires user secret NAME` | the caller supplied no value from any accepted source; run `juggernaut secrets set` (and send the vault key or use `connect`), or add the header |
| `502 pod did not return a session key` | `podAuth` or the pod secret mismatch between gateway and wrapper, or the pod is not Ready |
| gateway fails to start with `podAuth mtls: gateway client cert` | the controller has not issued `juggernaut-gateway-client-tls` yet, or the Secret is not mounted at `/etc/juggernaut/tls` |
| session `Failed: isolation: ... CiliumNetworkPolicy CRD is not installed` | `egressEnforcer: cilium` on a cluster without Cilium; use `proxy` |
| session `Failed: ... declares no egress hosts` | add `servers[].egress` or, for laptops, `egressEnforcer: none` with `allowInsecure` |
| pod never Ready, `/readyz` 503 | the wrapper could not read `/run/juggernaut-secret/pod-token`; check the Secret and the mount |
| tools missing on `/mcp` | hidden by `tools.expose`/`groups`, or the adapter's pod failed to list; gateway log `eager tool load failed` names it |
| everything reaped while in use | `routing.type: memory` in a cluster; switch to `redis` so the reaper sees activity |
| `config reload rejected` | the new file failed validation; the log line has the reasons; the old config is still live |

## 12. Extending

New IdP behaviour, store, enforcer or sink: implement one contract in
`internal/core/contracts`, register it in `init()`, run the harness in
`internal/core/contracts/contracttest`, blank-import it in `internal/adapters/all`. The layering,
the contracts table and the wire contract a session pod must satisfy are in
[ARCHITECTURE.md](ARCHITECTURE.md). A custom binary can import a different adapter set (an
out-of-tree adapter is just a package) without touching the registry.
