# Testing

Everything runs with plain `go test`; nothing needs docker, a cluster, Redis
or an identity provider. The end-to-end suite builds the real wrapper binary
and a real stdio MCP server and drives the real gateway over HTTP.

| Command | What runs | Needs |
|---------|-----------|-------|
| `make test` | unit, contract and end-to-end tests | Go |
| `make test-unit` | everything except `internal/integration` | Go |
| `make test-race` | the concurrent packages under the race detector | Go |
| `make test-integration` | environment-dependent tests (`-tags integration`), which skip when the environment is missing | docker, `make images` |
| `go test ./internal/integration/ -run TestRouter -v` | one end-to-end test with the gateway log | Go |

Set `JUGGERNAUT_TEST_DEBUG=1` to get debug-level gateway logs from the
end-to-end tests, and `JUGGERNAUT_TEST_STATE=<dir>` to keep the gateway state
directory (each pod's `wrapper.log` and `wrapper.json`) instead of a temp dir.

## Layers

### Unit tests (`*_test.go` next to the code)

Every component has tests for its own behaviour, without the rest of the
system:

| Package | Covers |
|---------|--------|
| `internal/config` | schema and semantic validation rules, env interpolation, hot reload keeps the previous config on a bad edit |
| `internal/core` | principals and grants, ids and hashes, sealing/MAC helpers, the user-secret vault (Argon2id key, per-entry DEK, AAD binding, wrong key and tampering fail), pod key sealing |
| `internal/mcpproxy` | header rewriting (client bearer and cookies never reach a pod, spoofed `X-Juggernaut-*` stripped), gateway session id only when the upstream started a session, SSE streaming, pod mTLS config |
| `internal/gateway` | per-adapter handler (401 challenge and resource metadata, 403 for ungranted, 422 for missing required secret, session bookkeeping), session manager (one pod per user and type, caps, cold start), user-secret resolution across the three sources |
| `internal/wrapper` | pod-token gate, plaintext and sealed secret headers, redaction, child env, HTTP-mode director, child restart on secret rotation without breaking the MCP session, listings cached per child generation |
| `internal/egress` | allow-list enforcement with DNS resolution and private-range denial |
| `internal/controller` | pod spec rendering, reconcile against a fake Kubernetes client, internal CA and SPIFFE certificates |
| `internal/admin` | admin API authorisation and handlers |
| `internal/cli` | vault file, secrets commands, companion sealing |
| `internal/pki` | CA, leaf issuance, mTLS handshake with SPIFFE identity checks |
| `internal/telemetry` | metrics and tracing wiring |

### Contract tests (`internal/core/contracts/contracttest`)

One function per contract (`IdentityProvider`, `AccessPolicy`, `TokenBroker`,
`Provisioner`, `RoutingTable`, `UserSecretStore`, ...). Every adapter runs the
harness for the contracts it implements, so a new adapter is checked against
the same expectations as the built-in ones. Redis adapters run against an
in-process Redis (`miniredis`), the Kubernetes provisioner against the
controller-runtime fake client, introspection and exchange against
`httptest` identity providers.

### End-to-end tests (`internal/integration`)

`local_test.go` starts the gateway in-process from a static-identity
configuration, with the local provisioner in process mode, and connects real
MCP SDK clients:

- **Per-adapter endpoint**: unauthenticated request gets the OAuth challenge;
  a missing required user secret is rejected before any pod is spawned; a
  real MCP session through the wrapper reaches the stdio server; the secret
  arrives as an environment variable and no `JUGGERNAUT_*` variable leaks
  into the child; the session is visible to its owner only; an ungranted
  user gets 403; a foreign session id is 404.
- **Aggregated router**: eager namespaced tools with renames and denials, a
  routed call, `whoami`, lazy meta-tools for a client configured lazy,
  `execute` refusing a hidden tool, and one pod per user across sessions.

`docker_test.go` is behind the `integration` build tag and is the place for
tests that need a docker daemon and locally built images.

## Helpers

`internal/testutil` builds binaries once per test run (`BuildBinary`), finds
free ports, polls for conditions and provides a fake provisioner.
`internal/testutil/stdioserver` is a minimal stdio MCP server with the tools
`echo`, `env`, `secret_tool` and `whoenv` used by the wrapper and end-to-end
tests.
