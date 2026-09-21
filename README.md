# Juggernaut

Juggernaut is a **self-hosted**, open-source, Kubernetes-native MCP (Model Context Protocol) gateway.

It runs **one isolated MCP server pod per (user, server type)**, brokers OAuth 2.0 on the front door
(the gateway is an MCP-spec OAuth 2.0 protected resource), and passes a **per-user token** to the MCP
servers hosted behind it so upstream actions (Jira, GitHub, internal APIs) are attributed to the
calling person, not to a shared service identity.

Juggernaut is designed for people running their own cluster: a laptop (kind, k3s, OrbStack) or a
managed cluster (EKS, GKE, AKS) with no cloud-specific dependency in the core. Identity comes from
your own OIDC provider (Keycloak is the reference; Entra ID, Okta, Dex and others are pluggable).

The repository is being built up in milestones. See `docs/DESIGN.md` for the full design and
`docs/SELF-HOSTING.md` for how to run it on your own hardware.

## Status

Pre-alpha scaffold. Nothing here is production-ready yet.


## Documents

| File | What |
|------|------|
| `docs/QUICKSTART.md` | three paths: one machine without an IdP, Compose with Keycloak, kind |
| `docs/POWER-USERS.md` | every configuration knob, token modes, tool exposure, isolation, operations, CLI and API, troubleshooting |
| `docs/ARCHITECTURE.md` | system diagram, contracts, wire contract of a session pod, test harness |
| `docs/IDENTITY.md` | identity types (`none`, `static`, `bearer_jwt`, `bearer_introspect`), token brokering, discovery |
| `docs/ACCESS-CONTROL.md` | groups → server types → tools; what is checked on every call; checklist before opening to a team |
| `docs/CONNECT.md` | client configuration for Claude Code, Cursor and others |
| `docs/DESIGN.md` | the design record (identity, lifecycle, isolation, schema, API, wrapper, admin UI, security, stack, plan, layout) |
| `docs/DESIGN-BRIEF.md` | the brief the design answers |
| `docs/SELF-HOSTING.md` | running it on your own laptop or cluster |
| `examples/juggernaut.yaml` | worked configuration example (Keycloak, exchange, cilium) |
| `examples/juggernaut.laptop.yaml` | one machine, no identity provider (`identity.type: none`) |
| `schemas/juggernaut.schema.json` | JSON Schema for `juggernaut.yaml` |
| `api/openapi.yaml` | control-plane and data-plane API |
| `deploy/policies/` | reference NetworkPolicy / CiliumNetworkPolicy manifests |

## Milestones

| Milestone | Branch | Demoable |
|-----------|--------|----------|
| Design | `claude/self-hosting-scaffold-rgbu56` | this document set |
| M0 | `…-m0` | single user, token flow + stdio wrapper on Docker Compose |
| M1 | `…-m1` | per-user pods + idle reaper on kind |
| M2 | `…-m2` | network isolation |
| M3 | `…-m3` | lazy tools, audit, admin UI, Helm |

Each milestone has its own document under `docs/MILESTONE-*.md` with the demo checklist.

## Quick tour

```sh
make build                      # bin/juggernaut, juggernaut-gateway, juggernaut-controller, juggernaut-wrapper, juggernaut-egress
bin/juggernaut validate -f examples/juggernaut.yaml
docker compose -f deploy/compose/docker-compose.yaml up   # milestone 0 laptop stack
kubectl apply -k deploy/kustomize/overlays/kind             # kind cluster
helm install juggernaut charts/juggernaut --set-file config=juggernaut.yaml
```
