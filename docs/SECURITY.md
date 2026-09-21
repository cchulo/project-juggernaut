# Security model

Juggernaut is built on one rule: **zero trust, always**. No component trusts another because of
where it sits on the network; every hop is authenticated in both directions and encrypted; every
request is re-authorized; and a compromise of any one component yields nothing beyond what that
component must hold to do its job. Every change is reviewed against the trust table below.

## Trust table

| Hop or component | What is trusted | How it is verified |
|---|---|---|
| client → gateway | nothing | bearer token validated per request by the identity adapter; scope checked; `bearer_introspect` fails **closed** when the IdP cannot be reached |
| gateway → session pod | nothing | `podAuth: mtls`: controller-issued certificates from an internal CA; the gateway verifies the pod's chain and `spiffe://<domain>/session/<pod>`; the pod verifies the gateway's chain and `spiffe://<domain>/gateway`; the per-pod secret header is a second factor. `shared-secret` (no TLS) is the laptop fallback |
| pod → gateway | nothing | the pod accepts only its own certificate peer and its own secret; user secrets can arrive sealed to the pod's ephemeral key so the gateway is a blind carrier |
| gateway → routing store | ciphertext and MACs only | pod tokens sealed with the KEK; every pod and session record carries an HMAC derived from the KEK; a record that fails authentication is treated as not found, so a store compromise cannot redirect a user |
| gateway → user secret store | ciphertext only | entries are encrypted on the user's machine under a key the gateway never has (next section) |
| controller → cluster | Kubernetes RBAC | namespaced Roles; the gateway has no Pod rights; pods have no service-account token |
| pod → network | nothing | default-deny; egress only to declared hosts (Cilium FQDN policy or the CONNECT proxy with a per-pod allowlist); no DNS covert channel |
| session lifetime | nothing beyond the current call | the router re-resolves the bearer and recomputes grants on every tool call; a revoked token or a changed group takes effect on the next call |
| identity types `none` / `static`, `JUGGERNAUT_TRUSTED_NETWORK` | network position | development only: refused off a loopback data listener unless `network.allowInsecure: true`; every such start logs a warning |
| config | the operator | schema plus semantic validation; hash logged on every reload; a rejected reload never replaces a live config |
| images | the registry | digest pinning required by default (cosign verification is a follow-up) |
| operator | nothing about users' credentials | the operator can delete a user's sealed entries but cannot read them |

## User secrets: only the user can decrypt

Users supply third-party credentials (Jira, Confluence, GitHub API tokens) for their own pods. The
gateway stores them, but cannot read them.

**Credential.** The user picks a vault passphrase once. `K_user = Argon2id(passphrase, salt)` is
derived on their machine and kept in `~/.config/juggernaut/vault.json` (0600; a keychain backend
can replace the file). The passphrase and `K_user` never reach the gateway at rest.

**Format** (`core.SealedEntry`, produced by the CLI, stored as-is):

```
DEK      = random 32 bytes per (user, adapter)
blob     = AES-256-GCM(DEK, secrets JSON, AAD = subject | adapter | version)
wrapped  = AES-256-GCM(K_user, DEK,      AAD = subject | adapter)
entry    = {version, salt, argon params, wrapped, nonce, blob, names}
```

The AAD binds an entry to one user and one adapter; it cannot be moved to another user or
replayed for another server type. Only the secret **names** are visible to the gateway and the
audit log, never values.

**Use, tier A (any MCP client).** The client sends `X-Juggernaut-Vault-Key: K_user` with each
request. The gateway unwraps in memory for that request only, forwards the values to that user's
pod, and zeroizes. The gateway process sees plaintext transiently; nothing at rest is readable by
it.

**Use, tier B (`juggernaut connect`, gateway blind).** A local companion holds the OAuth session
and the vault. Each session pod's wrapper generates an X25519 key at start and publishes it
through `GET /adapters/{name}/session-key` (owner only). The companion decrypts locally, seals the
values to the pod's key (nacl box, anonymous sender), and sends the blob as
`X-Juggernaut-Sealed-Secrets-<adapter>`. The gateway forwards it unread; the wrapper opens it in
memory and builds the child's environment. Plaintext exists on the user's machine and inside the
user's own pod, nowhere else.

**Header source.** For servers that prefer it, the client may send plaintext values as
`X-Juggernaut-Secret-<NAME>`; nothing is stored. Per server, `userSecrets.sources` lists which of
`header`, `store`, `sealed` are accepted and in what order.

| Attacker | At rest | In use |
|---|---|---|
| Redis dump or backup | ciphertext only | — |
| operator with the KEK | ciphertext only (the KEK is not the user key) | — |
| compromised gateway process | ciphertext only | tier A: plaintext of users active during the compromise; tier B: nothing |
| compromised session pod | that user's secrets for that adapter | same |
| lost passphrase | entries are unrecoverable; re-enter them | — |

**Rotation and revocation.** `juggernaut secrets rotate` re-encrypts every entry under a new
passphrase on the user's machine. `juggernaut secrets delete <adapter>` or disabling the user
removes entries and recycles the affected pods. A changed secret restarts the stdio child at the
next idle boundary; values are added to the wrapper's log redactor before the child starts.

## Isolation of stdio servers

The unit of isolation is the pod: one child process, in one container, in one pod, for one user.
Routing is by the subject of the validated token, never by anything the client sends; a session id
is bound to its subject and pod; a pod accepts only the gateway; user secrets and tokens are
resolved per subject and reach only that subject's pod; tool lists of servers that run with user
credentials are cached per user. With `runtime.kind: local` (development) each user gets their own
docker bridge network. [ACCESS-CONTROL.md](ACCESS-CONTROL.md) lists what is checked on every call.

## Certificates (`podAuth: mtls`)

- The controller creates a P-256 CA in Secret `juggernaut-pod-ca` (system namespace) on first
  run and never hands out its key.
- Per session, before the pod starts, it issues a server certificate with URI SAN
  `spiffe://juggernaut/session/<pod>` into the pod's own Secret next to the pod token; the wrapper
  serves TLS 1.3 with `RequireAndVerifyClientCert` and accepts only `spiffe://juggernaut/gateway`.
- The gateway's client certificate lives in Secret `juggernaut-gateway-client-tls`, mounted at
  `/etc/juggernaut/tls`, renewed by the controller within seven days of expiry.
- The admin (or data) listener can require client certificates too: `listeners.*.tls.clientCAFile`.

## What is not done yet

Cosign signature enforcement for images, signed configuration, DPoP sender-constrained client
tokens, and an OS keychain backend for the vault key. Each is listed in the trust table as the
next step for its row.
