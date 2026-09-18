# Milestone 3 — lazy tools, audit, admin UI, Helm

Goal: make Juggernaut operable by one person on their own cluster: a single `/mcp` endpoint with a
small tool surface, a complete audit trail, metrics and traces, an admin page to manage users in
Keycloak, and a Helm chart that installs everything (optionally with a bundled Keycloak).

## What is in this milestone

| Area | Package / path |
|------|----------------|
| Aggregated `/mcp` router: per-session MCP server, tools namespaced `<adapter>__<tool>`, eager or lazy per client/group, tool-list cache per config version, upstream MCP client sessions to pods with per-request token injection | `internal/router` |
| Lazy meta-tools `search_tools`, `describe_tool`, `execute` | `internal/router/router.go` |
| Audit log: one JSON record per tool call / adapter request / admin action, argument redaction by key and by shape (bearer strings, JWT-like strings) | `internal/audit` |
| Prometheus metrics (`juggernaut_pods_active`, `cold_start_seconds`, `idle_terminations_total`, `auth_failures_total`, `tool_calls_total`, `tool_call_seconds`, `config_reload_errors_total`, `egress_decisions_total`) and OTLP tracing | `internal/telemetry` |
| Revocation before expiry via RFC 7662 introspection, cached per token per interval | `internal/auth/introspect.go` |
| Admin listener: Keycloak `Directory` (gocloak) with the exact service-account roles, `/admin/api/*`, admin-role check, disable/kill semantics, embedded SPA | `internal/admin` |
| Admin UI: Preact + Vite, PKCE in the browser, users / user detail / groups pages | `ui/admin` |
| `juggernaut admin login` (device authorization grant) | `cmd/juggernaut` |
| Helm chart with gateway, controller, egress proxy, Valkey, optional Keycloak, CRDs, RBAC, PSA labels | `charts/juggernaut` |

## Reference client configuration

Use `/mcp` for clients that should see one endpoint. Cursor is in `gateway.tools.lazyForClients`
by default in the example so it sees three tools; Claude Code sees the eager, namespaced list.
Per-adapter endpoints remain for clients that want one server type only.

## Admin listener security

- Bound to `127.0.0.1:24680` unless `gateway.listeners.admin.tls` or `allowInsecureAdmin` is set.
- A separate `http.Server`; the data-plane router has no `/admin` route.
- Every `/admin/api` call needs a bearer token from the same IdP carrying the realm role
  `juggernaut-admin` (or scope `juggernaut:users.admin`). The SPA obtains it with PKCE against the
  public client `juggernaut-admin-ui`; scripts use `juggernaut admin login`.
- Service-account client `juggernaut-admin` holds only `view-users`, `manage-users`, `query-users`,
  `query-groups`, `view-realm` on `realm-management`.
- Disabling a user logs them out of Keycloak and terminates all their pods; changing groups
  terminates pods so grants are re-evaluated on the next request.

## Demo (to run locally)

```sh
make ui images
helm install juggernaut charts/juggernaut -n juggernaut-system --create-namespace \
  --set keycloak.enabled=true --set keycloak.service.type=NodePort --set keycloak.service.nodePort=30880 \
  --set-file config=deploy/kustomize/base/juggernaut.yaml \
  --set secrets.brokerClientSecret=juggernaut-gateway-secret \
  --set secrets.keycloakAdminSecret=juggernaut-admin-secret
kubectl -n juggernaut-system port-forward deploy/juggernaut-gateway 8080:8080 24680:24680
```

1. Point Cursor at `http://localhost:8080/mcp`: it lists `search_tools`, `describe_tool`, `execute`.
2. Point Claude Code at the same URL: it lists `everything__echo`, … (eager).
3. `kubectl logs deploy/juggernaut-gateway | grep tool_call` shows user, pod, tool, redacted args, duration.
4. `curl localhost:9090/metrics | grep juggernaut_` shows pods active and cold-start histograms.
5. Open `http://127.0.0.1:24680/admin`, log in as `alice`, create a user, add them to
   `engineering`, and watch their pod appear under Sessions after they connect.

## Known gaps

- `/tools` on the control plane still lists exposure rules rather than live tool metadata.
- The SPA build output is not committed; run `make ui` before building images.
- OTLP audit sink writes to stdout; a log-record exporter is a follow-up.
