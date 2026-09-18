# Milestone 2 — network isolation

Goal: a fully compromised session pod can reach only the upstream hosts its server type declares.
Nothing else: no other pods, no cluster services, no Kubernetes API, no cloud metadata, no
arbitrary DNS.

## What is in this milestone

| Area | Package / path |
|------|----------------|
| Per-session `NetworkPolicy` renderer (baseline; cilium and proxy variants) | `internal/netpol/networkpolicy.go` |
| Per-session `CiliumNetworkPolicy` renderer (`toFQDNs` + DNS proxy rules) as unstructured, no Cilium Go dependency | `internal/netpol/cilium.go` |
| Allowlist format for the fallback proxy | `internal/netpol/allowlist.go` |
| Controller isolation hooks: policies before pod creation, allowlist publish on Ready, cleanup, namespace default-deny | `internal/controller/isolation.go` |
| `juggernaut-egress`: CONNECT-only proxy enforcing (pod IP, host, port), resolving names itself, refusing denied CIDRs after resolution | `internal/egress`, `cmd/juggernaut-egress` |
| Wrapper HTTP-transport mode (server bound to loopback, wrapper is the only listener) | `internal/wrapper/httpmode.go` |
| Manifests: egress proxy deployment + its own policy, namespace default-deny, kind-cilium overlay | `deploy/kustomize`, `deploy/policies` |
| Tests for policy rendering and allowlist matching | `internal/netpol/netpol_test.go` |

## Enforcement matrix

| Threat | cilium mode | proxy mode |
|--------|-------------|------------|
| Non-allowlisted host | `toFQDNs` drops | proxy returns 403 |
| Raw IP without DNS | no FQDN match → drop | pod cannot reach anything but the proxy |
| DNS covert channel | DNS proxy rejects names outside `rules.dns` | no resolver in the pod (`dnsPolicy: None`) |
| Other session pods | default-deny ingress + per-pod ingress from gateway only | same |
| Kubernetes API / metadata | `except` CIDRs + `denyCIDRs` | proxy refuses after resolution; NetworkPolicy blocks direct |
| Gateway → pod spoofing | ingress limited to gateway labels; wrapper requires per-pod secret | same |

## Demo (to run locally)

Proxy mode (no Cilium):

```sh
kubectl apply -k deploy/kustomize/overlays/kind
kubectl -n juggernaut-sessions debug everything-<hash> -it --image=curlimages/curl -- sh
# inside: HTTPS_PROXY is set; only allowlisted hosts succeed, nslookup fails
```

Cilium mode:

```sh
kind create cluster --config deploy/kind/kind-config-cilium.yaml
cilium install --set dnsProxy.enableTransparentMode=true
kubectl apply -k deploy/kustomize/overlays/kind-cilium
kubectl -n juggernaut-sessions get ciliumnetworkpolicies
```

`deploy/policies/README.md` lists the curl checks that must fail and succeed.

## Not in this milestone

- mTLS gateway→pod (`network.podAuth: mtls` is rejected by validation; shared secret is the reference).
- cosign image verification (`imagePolicy.cosign` is parsed but not enforced).
- gVisor/Kata installation: `runtimeClassName` is honoured if the class exists.
