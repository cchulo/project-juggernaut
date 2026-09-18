# Milestone 1 — per-user pods and idle reaper

Goal: every (user, server type) pair gets its own pod on Kubernetes, created on first use and
torn down when idle. The gateway survives restarts and scales horizontally because the routing
table lives in Redis.

## What is in this milestone

| Area | Package / path |
|------|----------------|
| Internal CRDs `ServerType` and `Session` (`juggernaut.io/v1alpha1`) with generated deepcopy and manifests | `api/v1alpha1`, `deploy/crds` |
| Config → `ServerType` rendering and pruning on hot reload | `internal/controller/render.go` |
| Restricted pod spec (non-root, RO rootfs, no caps, seccomp, no SA token, RuntimeClass switch) | `internal/controller/podspec.go` |
| `Session` reconciler: Pending → Starting → Ready → Terminating → Gone, finalizer, failure detection | `internal/controller/session_controller.go` |
| Idle reaper with in-flight protection, max session age, hard grace | `internal/controller/reaper.go` |
| Redis routing table (sessions, pods, activity, in-flight, encrypted pod tokens) | `internal/session/redis.go`, `cipher.go` |
| Kubernetes runtime backend (Session + Secret, no Pod rights for the gateway) | `internal/runtime/kube` |
| Binaries and wiring | `cmd/juggernaut-controller`, `cmd/juggernaut-gateway` (`runtime.kind: kube`) |
| `kubectl apply -k` path with bundled Valkey and Keycloak for kind | `deploy/kustomize` |

## How the pieces relate

```
gateway ──creates──▶ Session + Secret(pod-token)
controller ──reconciles Session──▶ Pod (+ ConfigMap <type>-wrapper)
controller ──writes status.endpoint──▶ gateway holds request until Ready
gateway ──Touch/InFlight──▶ Redis ◀──reads── reaper ──sets desiredPhase──▶ Session
```

## Demo (to run locally)

```sh
kind create cluster --config deploy/kind/kind-config.yaml
make images && kind load docker-image ghcr.io/cchulo/juggernaut-{gateway,controller,wrapper}:dev
kubectl apply -k deploy/kustomize/overlays/kind
kubectl -n juggernaut-system port-forward svc/juggernaut-gateway 8080:8080
```

1. Alice and Bob (both in `engineering` after you add Bob to the group) connect to
   `/adapters/everything/mcp`. `kubectl -n juggernaut-sessions get sessions` shows two pods,
   `everything-<hash>` each.
2. `kubectl -n juggernaut-system rollout restart deploy/juggernaut-gateway`: the clients keep
   their `Mcp-Session-Id` and continue without re-initializing.
3. Stop using one client. After `idleTimeout` (5m in the kind config) the reaper terminates the
   pod; the next request gets `404`, the client re-initializes, and a new pod appears.
4. `kubectl -n juggernaut-sessions get pod <name> -o yaml` shows no token anywhere: the user
   token is injected per request, the pod token is a Secret mounted read-only.

## Known gaps to close in later milestones

- No NetworkPolicy yet (M2): pods can reach anything the cluster allows.
- HTTP-transport servers: the wrapper only proxies stdio; M2 adds the HTTP sidecar mode.
- Introspection-driven revocation is configured but not yet wired to a poller (M3).
