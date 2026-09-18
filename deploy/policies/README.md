# Reference policies

These manifests show what the controller renders per session pod (milestone 2):

| File | Rendered by | When |
|------|-------------|------|
| `networkpolicy-session.yaml` | `internal/netpol.RenderNetworkPolicy` | `egressEnforcer: cilium` (baseline L3/L4) |
| `networkpolicy-session-proxymode.yaml` | same | `egressEnforcer: proxy` |
| `ciliumnetworkpolicy-session.yaml` | `internal/netpol.RenderCiliumPolicy` | `egressEnforcer: cilium` |

Verification from inside a session pod (`kubectl -n juggernaut-sessions debug <pod> --image=curlimages/curl`):

```sh
curl -sS --max-time 5 https://api.atlassian.com/     # allowed (allowlisted)
curl -sS --max-time 5 https://example.org/           # blocked (not allowlisted)
curl -sS --max-time 5 http://169.254.169.254/        # blocked (metadata)
curl -sS --max-time 5 https://kubernetes.default/    # blocked (API server, no SA token either)
nslookup example.org                                  # NXDOMAIN/refused (cilium) or no resolver (proxy)
```
