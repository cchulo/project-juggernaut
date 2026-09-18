// Authorization Code + PKCE against the IdP, entirely in the browser. The
// gateway never sees the admin's password; it only validates the resulting
// bearer token and its admin role on every /admin/api call.

type OIDCConfig = { issuer: string; clientId: string; scope: string };

const KEY = "juggernaut.admin.token";

async function discover(): Promise<OIDCConfig & { authorization_endpoint: string; token_endpoint: string; end_session_endpoint?: string }> {
  const cfg: OIDCConfig = await (await fetch("/admin/api/oidc")).json();
  const disc = await (await fetch(`${cfg.issuer}/.well-known/openid-configuration`)).json();
  return { ...cfg, ...disc };
}

function b64url(bytes: ArrayBuffer | Uint8Array): string {
  const arr = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  return btoa(String.fromCharCode(...arr)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export async function login(): Promise<void> {
  const d = await discover();
  const verifier = b64url(crypto.getRandomValues(new Uint8Array(32)));
  const challenge = b64url(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier)));
  const state = b64url(crypto.getRandomValues(new Uint8Array(16)));
  sessionStorage.setItem("pkce", JSON.stringify({ verifier, state }));
  const url = new URL(d.authorization_endpoint);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("client_id", d.clientId);
  url.searchParams.set("redirect_uri", `${location.origin}/admin/callback`);
  url.searchParams.set("scope", d.scope);
  url.searchParams.set("code_challenge", challenge);
  url.searchParams.set("code_challenge_method", "S256");
  url.searchParams.set("state", state);
  location.assign(url.toString());
}

export async function handleCallback(): Promise<boolean> {
  const params = new URLSearchParams(location.search);
  const code = params.get("code");
  if (!code) return false;
  const saved = JSON.parse(sessionStorage.getItem("pkce") ?? "{}");
  if (params.get("state") !== saved.state) throw new Error("state mismatch");
  const d = await discover();
  const body = new URLSearchParams({
    grant_type: "authorization_code",
    client_id: d.clientId,
    code,
    redirect_uri: `${location.origin}/admin/callback`,
    code_verifier: saved.verifier,
  });
  const res = await fetch(d.token_endpoint, { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body });
  if (!res.ok) throw new Error(`token exchange failed: ${res.status}`);
  const tok = await res.json();
  sessionStorage.setItem(KEY, JSON.stringify({ access: tok.access_token, exp: Date.now() + tok.expires_in * 1000 }));
  sessionStorage.removeItem("pkce");
  history.replaceState({}, "", "/admin/");
  return true;
}

export function token(): string | null {
  const raw = sessionStorage.getItem(KEY);
  if (!raw) return null;
  const t = JSON.parse(raw);
  if (Date.now() > t.exp - 10_000) {
    sessionStorage.removeItem(KEY);
    return null;
  }
  return t.access;
}

export function logout(): void {
  sessionStorage.removeItem(KEY);
  location.assign("/admin/");
}
