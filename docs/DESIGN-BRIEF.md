# Design brief: Juggernaut

You are a senior platform engineer and security architect. Produce a complete system design for **Juggernaut**, an open-source, Kubernetes-native MCP (Model Context Protocol) gateway that runs one isolated MCP server pod per user session, brokers OAuth 2.0 on the front door, and passes per-user tokens to the MCP servers we host behind it.

Work through the design in the order given below. Do not skip to implementation. Where a decision has real trade-offs, present the options in a short table, pick one, and say why. Where the MCP spec or Kubernetes has a constraint that shapes the design, name it. Ask me at most three clarifying questions before you begin; otherwise make reasonable assumptions and list them at the top.

## Reference point

The closest existing project is `cchulo/cerebro` (https://github.com/cchulo/cerebro): a self-hosted context stack whose `mcp/gateway` is the one MCP endpoint agents use, sits behind an SSO reverse proxy, and enforces per-user access by mapping IdP groups to scopes. It runs upstream MCP servers (e.g. `mcp-atlassian`, CodeGraphContext via `supergateway`) as long-lived shared services on Docker Compose or k3s.

Juggernaut keeps cerebro's identity-aware single-endpoint model but changes three things:

1. Upstream MCP servers are **per-user pods**, not shared services.
2. The gateway is a proper **OAuth 2.0 resource server / authorization gateway** rather than a reverse-proxy SSO shim.
3. Pods are **ephemeral**: created on first use, torn down after idle.

Read cerebro's `docs/ARCHITECTURE.md`, `docs/ACCESS-CONTROL.md`, and `mcp/gateway/` before designing, and call out what you keep, what you drop, and why.

## Hard requirements

### Identity and auth
- The gateway is an OAuth 2.0 protected resource per the MCP authorization spec (2025-06-18 or later): it serves `/.well-known/oauth-protected-resource`, validates bearer tokens from an external IdP (Keycloak, Entra ID, Okta, Dex, or any OIDC provider — design for pluggability, pick Keycloak for the reference deployment), and rejects unauthenticated requests with `401` + `WWW-Authenticate` so MCP clients (Claude Code, Cursor, VS Code) can drive the standard discovery-and-login flow without custom config.
- **Per-user token passthrough**: the MCP servers we host must receive a token that identifies the calling user, so upstream actions (Jira, GitHub, internal APIs) are attributed to that person, not a shared service identity. Design this. Candidates to evaluate: forward the original access token; OAuth token exchange (RFC 8693) to mint a downstream-scoped token; the gateway holding per-user refresh tokens and injecting short-lived access tokens. State clearly which one is chosen, how the token reaches the pod (env var at spawn, injected header per request, projected file, mounted Secret), how it is rotated when it expires mid-session, and what happens on revocation.
- Authorization: IdP groups/claims map to which MCP server *types* a user may spawn and which tools are exposed. Keep cerebro's "scopes" concept where it still applies.

### Session and pod lifecycle
- One MCP server pod per (user, server-type), in full isolation from every other user's pods. Define what "session" means (MCP session id vs. user identity vs. pod) and how the three relate; MCP `Mcp-Session-Id` must map to exactly one pod.
- Cold start: first request from a user for a given server type creates the pod, waits for readiness, then forwards. Specify the readiness probe, the maximum cold-start budget, and what the client sees while waiting (hold the request vs. return a retryable error).
- Warm path: subsequent requests route to the existing pod. Design the routing table (in-memory + durable store; Redis is acceptable) and how it survives gateway restarts and horizontal scaling of the gateway itself.
- Idle scale-to-zero: a pod with no requests for a configurable idle timeout (default 15 min) is terminated. Define how idle is measured, how in-flight long-running tool calls or SSE streams are protected from termination, what per-server-type overrides look like, and how the client experiences a re-spawn (session id validity, `initialize` re-handshake).
- Hard caps: per-user max concurrent pods, per-server-type max pods cluster-wide, pod resource requests/limits, and a max session age after which the pod is recycled regardless of activity.
- Stdio-only MCP servers must be supported by bridging to Streamable HTTP inside the pod (cerebro uses `supergateway`; evaluate that vs. building the bridge in).

### Network isolation
- A user's MCP server pod may reach **only** the endpoints it is configured for — the specific upstream API(s) that server type needs — and **nothing else**: no public internet, no other users' pods, no cluster services beyond what is explicitly listed, no Kubernetes API, no cloud metadata endpoint (169.254.169.254).
- Design this with Kubernetes `NetworkPolicy` as the baseline and state its limits (L3/L4 only, no FQDN egress in vanilla NetworkPolicy). Then evaluate how to enforce hostname-level egress allowlists: Cilium `CiliumNetworkPolicy` with `toFQDNs`, an egress proxy the pod is forced through (with `HTTPS_PROXY` + iptables fallback block), Istio/Envoy sidecar with `ServiceEntry` allowlists, or a service mesh. Pick one for the reference design and one fallback for clusters without a CNI that supports it.
- DNS: the pod must not be able to resolve arbitrary names as a covert channel. Address this.
- The gateway → pod path must itself be authenticated (the pod should only accept traffic from the gateway), so a compromised pod cannot be reached by another pod. mTLS or a per-pod shared secret at spawn — choose and justify.

### Pod-level isolation
- Each session pod runs in its own Kubernetes namespace or a shared namespace with strict labels — evaluate both for isolation vs. operational overhead at scale (1,000 users × 5 server types).
- Non-root, read-only root filesystem, dropped capabilities, `seccompProfile: RuntimeDefault`, no service account token automount, Pod Security Admission `restricted`. State which server images will not tolerate this and how to handle them.
- Optional stronger sandboxing (gVisor / Kata via `RuntimeClass`) as a per-server-type switch.
- Secrets: the per-user token must not appear in `kubectl get pod -o yaml`, pod logs, or the gateway's management API. Design accordingly.

### Gateway interface (modelled on Microsoft MCP Gateway)
- The external interface follows the shape of `microsoft/mcp-gateway` (https://github.com/microsoft/mcp-gateway): a **control plane** REST API for managing registered servers and tools, and a **data plane** with `POST /adapters/{name}/mcp` for direct access to one server and `POST /mcp` for a router that aggregates every server the caller is authorized for. Keep its resource vocabulary (`adapters`, `tools`) unless there is a strong reason to rename; document any deliberate divergence. Read its README and `openapi/mcp-gateway.openapi.json` before designing the API, and produce Juggernaut's own OpenAPI spec as a deliverable.
- Unlike Microsoft's gateway, the control plane is **read-mostly**: server definitions come from the config file (below), not from `POST /adapters`. The API exposes status, logs, sessions, and pod state; creation/update through the API is optional and, if supported, must round-trip to the same YAML schema.

### MCP server transport support
- Every MCP server variant must work behind the gateway: Streamable HTTP, legacy HTTP+SSE, and **stdio**. Stdio servers (`npx`, `uvx`, `docker`, arbitrary binaries) run inside the session pod behind a **wrapper** that adapts them to a network transport. Design the wrapper: it is a small sidecar or entrypoint that owns the child process, speaks Streamable HTTP to the gateway, translates session lifecycle (one stdio process = one MCP session; restart policy on crash), forwards the per-user token into the child's environment or headers according to the server's token mode, and reports readiness. Evaluate reusing `supergateway` (cerebro's choice) versus writing the wrapper in-house; the wrapper must not widen the pod's network access.

### Single configuration file
- All of Juggernaut is configured from **one YAML file** (`juggernaut.yaml`), which is the source of truth. It declares: the IdP connection (Keycloak realm, client, issuer, JWKS), gateway settings (ports, idle timeouts, caps), every server (name, image, transport, command/args, allowed egress endpoints, token-passthrough mode, resources, runtime class, idle override), **tool exposure per server** (explicit allowlist or denylist of tool names, optional rename/prefix, optional per-group visibility), and group → server authorization. Produce the full schema with a worked example covering one stdio server, one HTTP server, and per-server tool filtering.
- Explain how the single file reaches the cluster (ConfigMap + hot reload vs. rendered into Kubernetes objects by the controller) and how validation and versioning work. CRDs are acceptable only as an internal representation the controller derives from the file, never as something an operator edits by hand.

### Admin UI
- The gateway serves an **admin web page** on a separate interface, default `localhost:24680` (configurable in the YAML), from which an operator administers user accounts in Keycloak: list users, create/disable users, assign the groups that map to server access, reset credentials, and see each user's active sessions/pods. The page talks to the Keycloak Admin REST API using a dedicated service-account client with the minimum realm roles required (`manage-users`, `view-users`, `query-groups`; enumerate exactly). It must never be exposed on the same listener as the MCP data plane; state how it is protected (bound to loopback by default, requires an admin-role token, and how that is obtained).

### Gateway behaviour
- Single Streamable HTTP endpoint (`/mcp`) plus per-server endpoints (`/adapters/{name}/mcp`); state which the reference client config should use.
- Tool aggregation across a user's authorized server types with namespaced tool names; support lazy tool loading via meta-tools (`search_tools`, `describe_tool`, `execute`) so a client like Cursor sees a small tool surface regardless of how many server types are behind the gateway. Make lazy vs. eager loading a per-client or per-user setting.
- Full audit log: every tool call with user, server type, pod, tool name, redacted arguments, duration, and outcome. OpenTelemetry traces and Prometheus metrics (pods active, cold-start latency, idle terminations, auth failures).

### Operations
- A controller reconciles `juggernaut.yaml` into whatever Kubernetes objects are needed. Users and their sessions are runtime state, not configuration.
- Helm chart for the gateway + controller + a bundled Keycloak (optional, for laptops); a `kubectl apply -k` path as well.
- Works on a laptop (kind/k3s/OrbStack) and on a managed cluster (EKS/GKE/AKS) without cloud-specific dependencies in the core. Cloud integrations (Key Vault, Secrets Manager) are optional plugins.
- Fully free and open source (Apache-2.0 or MIT). No dependency whose licence would block that; flag source-available components (cerebro notes Sourcebot is FSL-1.1 — Juggernaut must not require anything like that in its core).

## Deliverables

Produce these sections, in this order:

1. **Assumptions and open questions** (short).
2. **Architecture overview** — one Mermaid diagram of the request path (client → gateway → session pod → upstream API) and one of the control path (CRD → controller → pod lifecycle). Name every component.
3. **Identity and token flow** — sequence diagram of first-time login, warm request, token refresh, and revocation. State the chosen passthrough mechanism and rejected alternatives.
4. **Session and pod lifecycle** — state machine for a session pod (Pending → Starting → Ready → Idle → Terminating → Gone, or your own), the routing table schema, and the idle reaper design.
5. **Network isolation** — the chosen enforcement mechanism, example manifests (`NetworkPolicy` and the FQDN-level policy), and a threat table: what a fully compromised session pod can and cannot reach.
6. **`juggernaut.yaml` schema** — the complete schema and a worked example with one stdio server (with wrapper settings), one HTTP server, per-server tool exposure, group mappings, Keycloak connection, and the admin UI listener. Include the JSON Schema used to validate it.
7. **API surface** — the control-plane and data-plane endpoints as an OpenAPI outline, noting where it matches and where it diverges from `microsoft/mcp-gateway`.
8. **Stdio wrapper design** — process model, transport translation, token injection, readiness, crash handling.
9. **Admin UI** — page map, the Keycloak Admin API calls it makes, the service-account client and its exact roles, and how the `localhost:24680` listener is secured.
10. **Security review** — top ten risks ranked by severity with mitigations, including token leakage, cross-tenant access, egress bypass, resource exhaustion, and supply chain of MCP server images.
11. **Tech stack decision** — language (Go with controller-runtime vs. TypeScript/Python with the reference MCP SDK), rationale, and the list of libraries, including what the admin UI is built with.
12. **Phased implementation plan** — milestone 0 (single-user, no isolation, prove the token flow and the stdio wrapper), milestone 1 (per-user pods + idle reaper), milestone 2 (network isolation), milestone 3 (lazy tools, audit, admin UI, Helm). Each milestone lists what is demoable.
13. **Repository layout** for the monorepo.

Keep prose tight. Prefer tables and diagrams to paragraphs. Do not write application code yet; manifests and schemas only.
