# Self-hosting Juggernaut

Juggernaut is built to be run by the people who use it: on a laptop, a home-lab k3s box, or a
managed cluster you administer. Nothing in the core needs a cloud account.

## What you need

| Requirement | Laptop (kind / k3s / OrbStack) | Managed cluster (EKS / GKE / AKS) |
|-------------|-------------------------------|-----------------------------------|
| Kubernetes ≥ 1.29 | kind 0.23+, k3s 1.29+, OrbStack | any |
| OIDC provider | bundled Keycloak (Helm `keycloak.enabled=true`) | your Keycloak / Entra / Okta / Dex |
| Redis / Valkey | bundled | bundled or external |
| CNI with FQDN egress | Cilium on kind (`kind-config-cilium.yaml`) **or** `network.egressEnforcer: proxy` | Cilium (EKS/GKE/AKS all support it) or `proxy` |
| Ingress / TLS | `localhost` + `kubectl port-forward` is fine | any ingress; TLS termination in front of the gateway |

Milestone 0 does not need Kubernetes at all: `deploy/compose/` starts Keycloak, Redis and the
gateway with Docker Compose, and session "pods" are local containers.

## Quick path (kind + Helm)

```sh
kind create cluster --config deploy/kind/kind-config.yaml
# optional: cilium install
helm install juggernaut charts/juggernaut \
  --namespace juggernaut-system --create-namespace \
  --set keycloak.enabled=true \
  --set-file config=examples/juggernaut.yaml
kubectl -n juggernaut-system port-forward svc/juggernaut-gateway 8080:8080 24680:24680
```

Point an MCP client at `http://localhost:8080/mcp` and log in through the standard OAuth flow.
The admin UI is on `http://127.0.0.1:24680/admin` and is never exposed on the data listener.

## Kustomize path

```sh
kubectl apply -k deploy/kustomize/overlays/kind
```

## Configuration

Everything lives in one file, `juggernaut.yaml`. Secrets are referenced by environment variable or
file (`{ env: NAME }` / `{ file: /path }`) and never written into the file. See
`examples/juggernaut.yaml` and `schemas/juggernaut.schema.json`.

Validate before applying:

```sh
juggernaut validate -f juggernaut.yaml
```

The file is mounted as a ConfigMap and hot-reloaded by the gateway and controller. An invalid
reload is rejected and the previous configuration stays live.

## Keycloak setup (reference)

`deploy/keycloak/realm-juggernaut.json` is a realm export that creates:

- realm `juggernaut`
- client `juggernaut-gateway` (the audience of data-plane tokens; token exchange enabled)
- client `juggernaut-admin` (confidential, service account, realm-management roles
  `view-users`, `manage-users`, `query-users`, `query-groups`, `view-realm`)
- client `juggernaut-admin-ui` (public, PKCE, redirect `http://127.0.0.1:24680/admin/callback`)
- realm role `juggernaut-admin`
- client scopes `juggernaut:mcp`, `juggernaut:admin`, `juggernaut:users.admin`
- groups `engineering`, `product`, `support`, `juggernaut-admins`

Import it with `kc.sh import --file realm-juggernaut.json` or through the bundled chart.

## Running on a laptop without Cilium

Set `network.egressEnforcer: proxy`. Session pods then have **no DNS resolver** and reach the
internet only through `juggernaut-egress`, which enforces the per-server hostname allowlist.
Servers must honour `HTTPS_PROXY`; almost every HTTP client library does.

If you only want to try things out, `network.egressEnforcer: none` with
`network.allowInsecure: true` disables egress enforcement. The gateway logs a warning on every
start in this mode. Do not use it with real credentials.

## Resource footprint

| Component | Idle CPU / memory |
|-----------|-------------------|
| gateway | ~20m / 64Mi |
| controller | ~10m / 48Mi |
| Redis | ~5m / 32Mi |
| Keycloak (bundled) | ~200m / 600Mi |
| session pod (stdio server) | per `servers[].resources`, default 100m / 128Mi |
