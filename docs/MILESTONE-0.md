# Milestone 0 — single user, no isolation

Goal: prove the OAuth front door, the RFC 8693 token flow and the stdio wrapper on a laptop,
without Kubernetes. Nothing here is isolated; it is the foundation the later milestones harden.

## What is in this milestone

| Area | Package / path |
|------|----------------|
| Config loader, JSON Schema validation, semantic checks, hot reload | `internal/config` |
| OAuth 2.0 protected resource: JWKS validation, PRM document, 401 challenge | `internal/auth` |
| Principal → Grants (groups → server types, tool exposure) | `internal/authz` |
| Token broker (RFC 8693 exchange; `none`; `refresh-token` stub) | `internal/broker` |
| Session ids, routing table interface + in-memory implementation | `internal/session` |
| Runtime backend interface + local (docker / process) backend | `internal/runtime`, `internal/runtime/local` |
| Streamable HTTP proxy with header rewriting and SSE passthrough | `internal/mcpproxy` |
| Gateway HTTP surface: `/adapters/{name}/mcp`, control plane, three listeners | `internal/gateway` |
| Stdio wrapper: child ownership, token modes, readiness, redaction, per-pod secret | `internal/wrapper` |
| Binaries | `cmd/juggernaut-gateway`, `cmd/juggernaut-wrapper`, `cmd/juggernaut` |
| Laptop stack | `deploy/compose`, `deploy/keycloak/realm-juggernaut.json` |

Not in this milestone: the aggregated `/mcp` router (returns 501), Kubernetes, network policy,
Redis, audit log, admin UI.

## Demo (to run locally)

```sh
make build
docker build -f images/juggernaut-wrapper/Dockerfile -t ghcr.io/cchulo/juggernaut-wrapper:latest .
docker build -f images/example-stdio-server/Dockerfile -t ghcr.io/cchulo/example-stdio-server:dev images/example-stdio-server
docker compose -f deploy/compose/docker-compose.yaml up --build
```

1. Configure an MCP client with `http://localhost:8080/adapters/everything/mcp` and no auth settings.
2. The client gets `401` + `WWW-Authenticate`, fetches `/.well-known/oauth-protected-resource`,
   discovers Keycloak, and logs in as `alice` / `alice` (client id `mcp-client`, PKCE).
3. The first `initialize` spawns the `everything` container, waits for the wrapper's `/readyz`,
   then forwards. The gateway exchanges Alice's token for one with `aud=everything-mcp` and hands
   it to the wrapper, which starts the child with `EXAMPLE_USER_TOKEN` set.
4. `curl -H "Authorization: Bearer $TOKEN" localhost:8080/sessions` lists Alice's session pod.
5. `bob` (group `support`) gets `403` on `/adapters/everything/mcp` because his group grants nothing.

Keycloak's standard token exchange must be enabled on the `juggernaut-gateway` client
(`standard.token.exchange.enabled` in the realm export; requires Keycloak 26.2+).

## Known gaps to close in later milestones

- Exchange cache is per gateway process (Redis in M1).
- `Mcp-Session-Id` mapping lives in memory (Redis in M1).
- The local backend has no idle reaper (M1).
- HTTP-transport servers are not yet proxied through the wrapper (M1 adds the sidecar mode).
