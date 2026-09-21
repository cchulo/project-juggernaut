# Connecting Claude Code, Cursor and other MCP clients

Every developer connects to **one** URL. Two endpoint shapes exist:

| Endpoint | Use when |
|---|---|
| `<publicURL>/mcp` | one endpoint for everything: tools of every granted adapter, namespaced `<adapter>__<tool>`, or the lazy `search_tools` / `describe_tool` / `execute` surface for clients named in `gateway.tools.lazyForClients` (Cursor by default) |
| `<publicURL>/adapters/<name>/mcp` | one adapter only, with its tools under their own names |

What the client has to present depends on `identity.type` ([IDENTITY.md](IDENTITY.md)).

## Type `none` (one machine)

```sh
claude mcp add --transport http juggernaut http://127.0.0.1:8080/mcp --scope user
```

With `identity.allowRemote: true` every client adds the static token:

```sh
claude mcp add --transport http juggernaut http://192.168.1.10:8080/mcp --scope user \
  --header "Authorization: Bearer $JUGGERNAUT_TOKEN"
```

```json
{ "mcpServers": { "juggernaut": { "url": "http://127.0.0.1:8080/mcp",
    "headers": { "Authorization": "Bearer <JUGGERNAUT_TOKEN>" } } } }
```

(`~/.cursor/mcp.json`, or `.cursor/mcp.json` in a repository.)

## Types `bearer_jwt` and `bearer_introspect` (OAuth)

Give the client the URL and nothing else:

```sh
claude mcp add --transport http juggernaut https://mcp.example.internal/mcp --scope user
```

```json
{ "mcpServers": { "juggernaut": { "url": "https://mcp.example.internal/mcp" } } }
```

1. The first request gets `401` with a `WWW-Authenticate` header pointing at
   `/.well-known/oauth-protected-resource`.
2. The client reads it, reads the issuer's discovery document, and registers itself (Dynamic
   Client Registration for loopback redirect URIs in the reference realm, or the pre-registered
   public client `mcp-client`).
3. A browser window opens on the identity provider; the user logs in.
4. The client receives a token whose `aud` is the gateway and retries. `tools/list` now shows the
   tools the caller's grants allow; `whoami` shows how the token was interpreted.

Headless use (CI, a bot): a client-credentials token from the IdP with `juggernaut:mcp`, sent as
`Authorization: Bearer ...`. It becomes a service principal whose groups decide its server types.

## Tools the agent sees on `/mcp`

| Tool | Present | What it does |
|---|---|---|
| `whoami` | always | subject, kind, groups, token scopes, granted adapters, lazy flag |
| `<adapter>__<tool>` | eager mode | every visible tool of every granted adapter, forwarded to the caller's own pod |
| `search_tools(query, limit)` | lazy mode | search names and descriptions across granted adapters |
| `describe_tool(name)` | lazy mode | the full definition of one tool |
| `execute(name, arguments)` | lazy mode | run one tool by namespaced name |

The first call that needs an adapter's pod starts it; the request waits up to
`gateway.coldStartBudget` and then returns a retryable error. Pods idle out after
`servers[].idleTimeout`; the client's session id becomes invalid (404), and the client
re-initializes on its own.

## Admin listener

Operators reach `http://127.0.0.1:24680/admin` (port-forward in a cluster). The page logs in with
PKCE against the public client `juggernaut-admin-ui`; scripts obtain a token with
`juggernaut admin login --issuer <issuer>` (device flow) and call `/admin/api/*` with it.
