# Quickstart

Three paths, from nothing to a working gateway. Each one builds on the previous; stop at the one
that matches what you have. Status: pre-alpha scaffold. The steps are the intended flow and the
configs validate, but the stack has not yet been exercised end to end on a real machine; expect
rough edges and report them.

| Path | You need | You get |
|---|---|---|
| A. One machine, no identity provider | Docker, Go 1.24+ | the gateway and a stdio MCP server behind the wrapper, no login |
| B. Laptop with Keycloak | Docker Compose | the real OAuth flow: client discovery, login, token exchange, per-user token in the pod |
| C. kind cluster | kind, kubectl | per-user pods, idle reaper, network isolation, admin UI |

## Path A: one machine, no identity provider

```sh
git clone https://github.com/cchulo/project-juggernaut && cd project-juggernaut
make build                                            # bin/juggernaut, juggernaut-gateway, juggernaut-wrapper, ...
docker build -f images/juggernaut-wrapper/Dockerfile -t ghcr.io/cchulo/juggernaut-wrapper:latest .
docker build -f images/example-stdio-server/Dockerfile -t ghcr.io/cchulo/example-stdio-server:dev images/example-stdio-server
docker network create juggernaut
bin/juggernaut validate -f examples/juggernaut.laptop.yaml
JUGGERNAUT_STATE_DIR=$PWD/.state bin/juggernaut-gateway --config examples/juggernaut.laptop.yaml
```

The gateway listens on `127.0.0.1:8080`. `identity.type: none` makes every loopback request the
principal `local` in groups `everyone` and `juggernaut-admins`; there is no token and no login.

Connect a client:

```sh
claude mcp add --transport http juggernaut http://127.0.0.1:8080/mcp --scope user
```

Or, for Cursor, `~/.cursor/mcp.json`:

```json
{ "mcpServers": { "juggernaut": { "url": "http://127.0.0.1:8080/mcp" } } }
```

What to expect: the first tool call starts a docker container named `juggernaut-everything-<hash>`
on the `juggernaut` network and waits for it (up to `coldStartBudget`, 60s). `whoami` shows the
principal and the granted adapter `everything`. After 15 minutes without requests nothing reaps the
container in this path (the reaper lives in the controller); stop it with `docker rm -f`.

Check without a client:

```sh
curl -s localhost:8080/adapters | jq          # adapters you may use
curl -s localhost:8080/sessions | jq          # your session pods
curl -s -X POST localhost:8080/adapters/everything/mcp \
  -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"curl","version":"0"}}}' -i
```

The response carries `Mcp-Session-Id: jg_...`; send it on the following requests.

## Path B: laptop with Keycloak (Docker Compose)

```sh
docker compose -f deploy/compose/docker-compose.yaml up --build
```

This starts Keycloak 26 on `localhost:8180` with the realm from
`deploy/keycloak/realm-juggernaut.json` (users `alice`/`alice` in `engineering` and
`juggernaut-admins`, `bob`/`bob` in `support`; clients `juggernaut-gateway`, `mcp-client`,
`juggernaut-admin`, `juggernaut-admin-ui`; audience clients per server type) and the gateway on
`localhost:8080` configured by `deploy/compose/juggernaut.yaml` (`identity.type: bearer_jwt`,
`broker.mode: exchange`, `runtime.kind: local` with docker).

Connect a client with the URL only:

```sh
claude mcp add --transport http juggernaut http://localhost:8080/mcp --scope user
```

What to expect:

1. The client gets `401` with `WWW-Authenticate: Bearer resource_metadata="http://localhost:8080/.well-known/oauth-protected-resource"`.
2. It discovers Keycloak, registers itself (Dynamic Client Registration for loopback redirects, or
   uses `mcp-client`), and opens the browser. Log in as `alice`.
3. The first tool call spawns the `everything` container. The gateway exchanges Alice's token for
   one with `aud=everything-mcp` and hands it to the wrapper, which starts the child with
   `EXAMPLE_USER_TOKEN` set (token mode `env`).
4. `whoami` shows subject, groups `engineering` and `juggernaut-admins`, and adapter `everything`.
5. Log in as `bob` from another client: `/adapters/everything/mcp` answers `403`; his group grants nothing.

Keycloak's standard token exchange must be on for `juggernaut-gateway`
(`standard.token.exchange.enabled` in the realm export; Keycloak 26.2+).

## Path C: kind cluster

```sh
kind create cluster --config deploy/kind/kind-config.yaml
make images                                                     # gateway, controller, wrapper, egress
kind load docker-image ghcr.io/cchulo/juggernaut-gateway:dev ghcr.io/cchulo/juggernaut-controller:dev \
  ghcr.io/cchulo/juggernaut-wrapper:dev ghcr.io/cchulo/juggernaut-egress:dev ghcr.io/cchulo/example-stdio-server:dev
kubectl apply -k deploy/kustomize/overlays/kind
kubectl -n juggernaut-system get pods -w                        # keycloak, redis, gateway, controller, egress
kubectl -n juggernaut-system port-forward svc/juggernaut-gateway 8080:8080
```

The overlay uses `network.egressEnforcer: proxy` (no Cilium needed) and Redis routing. With
Cilium installed on a cluster created from `deploy/kind/kind-config-cilium.yaml`, apply
`deploy/kustomize/overlays/kind-cilium` instead.

Same client configuration as path B. What to expect:

```sh
kubectl -n juggernaut-sessions get sessions                     # one everything-<hash> per logged-in user
kubectl -n juggernaut-sessions get pod,networkpolicy            # pod + its policy
kubectl -n juggernaut-sessions get pod everything-<hash> -o yaml | grep -i token   # nothing: no user token in the object
kubectl -n juggernaut-system rollout restart deploy/juggernaut-gateway   # clients keep working
```

After `idleTimeout` (5 minutes in the kind config) the reaper terminates an unused pod; the next
request gets `404`, the client re-initializes, and a new pod appears.

Admin UI (build it once with `make ui`, then rebuild the gateway image):

```sh
kubectl -n juggernaut-system port-forward deploy/juggernaut-gateway 24680:24680
open http://127.0.0.1:24680/admin                               # log in as alice (juggernaut-admins)
```

Helm instead of kustomize:

```sh
helm install juggernaut charts/juggernaut -n juggernaut-system --create-namespace \
  --set keycloak.enabled=true \
  --set-file config=deploy/kustomize/base/juggernaut.yaml \
  --set secrets.brokerClientSecret=juggernaut-gateway-secret \
  --set secrets.keycloakAdminSecret=juggernaut-admin-secret
```

## Next

- Add your own server: copy a `servers[]` entry in `examples/juggernaut.yaml`, pin the image by
  digest, declare its `egress` hosts and `token` mode, map a group to it, run `juggernaut validate`.
- Point the gateway at your IdP instead of the bundled Keycloak: [IDENTITY.md](IDENTITY.md).
- Before opening it to a team: the checklist in [ACCESS-CONTROL.md](ACCESS-CONTROL.md).
- Everything the file can express and how the pieces behave: [POWER-USERS.md](POWER-USERS.md).
