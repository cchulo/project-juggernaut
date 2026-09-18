# Juggernaut admin UI

Preact + TypeScript + Vite. Built assets are embedded into `juggernaut-gateway` from
`internal/admin/ui/dist` and served under `/admin/` on the **admin listener only**
(default `127.0.0.1:24680`).

```sh
npm ci
npm run build      # writes ../../internal/admin/ui/dist
npm run dev        # proxies /admin/api to a locally running gateway
```

Login is Authorization Code + PKCE in the browser against the Keycloak client
`juggernaut-admin-ui`; the gateway validates the resulting token and requires the
`juggernaut-admin` realm role or the `juggernaut:users.admin` scope.
