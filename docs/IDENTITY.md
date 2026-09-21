# Identity

The gateway is always the OAuth 2.0 **resource server**: it turns whatever proves identity into a
`Principal` (subject, kind, groups, token scopes) and never mints tokens for clients. Who mints them,
and how a request proves who it is, is `identity.type`. The adapters are in
`internal/adapters/identity/`; the selector-to-adapter mapping is in `internal/app`.

| `identity.type` | Identity comes from | Token minted by | Protected-resource metadata |
|---|---|---|---|
| `none` | the fixed `identity.principal` | nobody | absent (404); challenge is a bare `Bearer` |
| `static` | `identity.tokens`, a bearer → principal map | you, in the file | absent |
| `bearer_jwt` (default) | JWT claims validated against the issuer's JWKS | Keycloak or your IdP | served; the 401 challenge points at it |
| `bearer_introspect` (default when `introspection.enabled`) | `bearer_jwt` plus RFC 7662 introspection per interval | same | served |

## Type `none`: one person, one machine

Every request is `identity.principal` (default `{subject: local, groups: [everyone, juggernaut-admins]}`)
with every token scope. There is no token, so the network is the whole protection:

- **On the host**: bind the data listener to `127.0.0.1` (`examples/juggernaut.laptop.yaml` does)
  and the adapter refuses any request whose peer is not loopback.
- **Provisioned** (compose, kind): inside a workload the peer is never loopback, so the
  provisioner sets `JUGGERNAUT_TRUSTED_NETWORK=1` on the gateway and the adapter accepts any peer.
  What keeps that safe is where the port lands: compose publishes on the host's `127.0.0.1` only;
  a Kubernetes Service is ClusterIP reached by `kubectl port-forward`. Never set that variable by
  hand on a port other machines can reach.
- `identity.allowRemote: true` is the explicit LAN option: every request, loopback included, must
  carry `Authorization: Bearer <$JUGGERNAUT_TOKEN>` (the name is `identity.staticTokenEnv`). An
  empty secret is a 401, not an open door.

Because there is no real token, `identity.broker.mode` must be `none` and servers use token modes
`none` or `static`; validation enforces it.

## Type `static`: tests and demos

`identity.tokens` maps bearer strings to seeds (`subject`, `groups`, `kind: user | service`,
`scopes`, default all). Tokens never expire and cannot be revoked except by editing the file. It is
what the contract tests use. Never production.

## Types `bearer_jwt` and `bearer_introspect`: Keycloak or your IdP

```yaml
identity:
  type: bearer_jwt                       # or bearer_introspect
  issuer: https://sso.internal/realms/eng  # OIDC discovery must work from the gateway
  audience: juggernaut-gateway           # what the IdP puts in aud for this gateway
  groupsClaim: groups                    # or a dotted path such as realm_access.roles
  jwksURL: ...                           # optional: skip discovery
  introspection: { enabled: true, interval: 60s, clientId: juggernaut-gateway, clientSecretRef: { env: ... } }
  broker: { mode: exchange, clientId: juggernaut-gateway, clientSecretRef: { env: JUGGERNAUT_BROKER_CLIENT_SECRET } }
```

`bearer_jwt` checks signature (JWKS from discovery or `jwksURL`, cached, refetched on an unknown
`kid`), `iss`, `aud`, `exp`, and requires `sub`. Claims map the same way for both types
(`internal/adapters/identity/claims`): groups from `groupsClaim` (list or delimited string;
Keycloak `/name` paths trimmed; Keycloak realm roles are added as groups), token scopes from
`scope`, `kind: service` when there is no `email` / `preferred_username` and `client_id` or `azp`
equals `sub`. `bearer_introspect` adds a revocation check against the introspection endpoint at
most once per `interval` per token; an unreachable endpoint fails open unless `options.fail_open: false`.

Revocation latency with `bearer_jwt` is the token lifetime; use `bearer_introspect` when it must be
immediate. Disabling a user in the admin UI also terminates their pods regardless of type.

## Token brokering: what the pod receives

The client's token is never forwarded. `identity.broker.mode` selects how the per-user downstream
token is minted (`docs/DESIGN.md` §3 has the comparison):

| Mode | Adapter | Result |
|---|---|---|
| `exchange` | RFC 8693 token exchange, audience per server type (`servers[].token.audience`) | a token with the user's `sub`, scoped to one upstream |
| `none` | no user token; servers use token modes `none` or `static` | shared or no credential |
| `refresh-token` | placeholder for IdPs without exchange | not implemented |

How the token reaches the process is the server's `token.mode`: `header` (HTTP servers),
`env` (set when the stdio child starts; rotation restarts the child at the next idle boundary),
`file` (tmpfs, rewritten per request), `static`, `none`.

## User-supplied credentials

Credentials the IdP knows nothing about (Jira and Confluence API tokens) are handled separately
from token brokering: users seal them on their own machine and the gateway stores ciphertext it
cannot read. See [SECURITY.md](SECURITY.md) and `servers[].userSecrets` in
[POWER-USERS.md](POWER-USERS.md).

## Discovery: how an MCP client finds all this

1. The client posts to `/mcp` without a token and gets `401` with
   `WWW-Authenticate: Bearer resource_metadata="<publicURL>/.well-known/oauth-protected-resource"`.
2. It fetches that document (RFC 9728): `resource`, `authorization_servers: [issuer]`,
   `scopes_supported: [juggernaut:mcp, juggernaut:admin]`, `bearer_methods_supported: [header]`.
3. It fetches the issuer's metadata, registers itself (Dynamic Client Registration is allowed for
   loopback redirect URIs in the reference realm; a pre-registered public client `mcp-client`
   exists too), runs the authorization code flow with PKCE in the browser, and retries.
4. The `whoami` tool shows what the gateway made of the token: subject, kind, groups, token
   scopes, granted adapters, and whether tools load lazily.

With `none` and `static` the metadata endpoint is 404 and the challenge is a bare `Bearer`; there
is nothing to discover.

## Service accounts

A client-credentials token from your IdP becomes a `kind: service` principal; its groups decide its
server types like any user's. A CI agent needs `juggernaut:mcp` and a group that grants the server
types it uses.
