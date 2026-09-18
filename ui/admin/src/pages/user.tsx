import { useEffect, useState } from "preact/hooks";
import { api, User, Pod, KeycloakSession } from "../api";

export function UserPage({ id }: { path: string; id?: string }) {
  const [u, setU] = useState<User | null>(null);
  const [allGroups, setAllGroups] = useState<string[]>([]);
  const [sessions, setSessions] = useState<{ keycloakSessions: KeycloakSession[]; pods: Pod[] } | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [pw, setPw] = useState("");

  const load = async () => {
    if (!id) return;
    try {
      setU(await api.user(id));
      setSessions(await api.sessions(id));
    } catch (e) { setErr(String(e)); }
  };
  useEffect(() => { load(); api.config().then((c) => setAllGroups(c.groups.map((g) => g.name))); }, [id]);

  if (!u) return <p class="muted">{err ?? "Loading…"}</p>;
  const act = (fn: () => Promise<unknown>) => fn().then(load).catch((e) => setErr(String(e)));

  return (
    <>
      <h2>{u.username} {!u.enabled && <span class="badge">disabled</span>}</h2>
      {err && <p class="muted">{err}</p>}
      <p class="muted">{u.firstName} {u.lastName} · {u.email} · id {u.id}</p>
      <div class="row">
        <button onClick={() => act(() => api.patchUser(u.id, { enabled: !u.enabled }))} class={u.enabled ? "danger" : "primary"}>
          {u.enabled ? "Disable (kills sessions)" : "Enable"}
        </button>
        <button class="danger" onClick={() => act(() => api.killSessions(u.id))}>Kill all sessions</button>
      </div>
      <h3>Groups (map to server access)</h3>
      <div class="row">
        {allGroups.map((g) => (
          <label class="badge">
            <input type="checkbox" checked={u.groups?.includes(g)}
              onChange={(e) => {
                const next = new Set(u.groups ?? []);
                (e.target as HTMLInputElement).checked ? next.add(g) : next.delete(g);
                act(() => api.setGroups(u.id, Array.from(next)));
              }} /> {g}
          </label>
        ))}
      </div>
      <h3>Credentials</h3>
      <div class="row">
        <input placeholder="temporary password" value={pw} onInput={(e) => setPw((e.target as HTMLInputElement).value)} />
        <button onClick={() => act(() => api.resetPassword(u.id, pw, true)).then(() => setPw(""))}>Set temporary password</button>
        <button onClick={() => act(() => api.resetPassword(u.id))}>Send reset email</button>
      </div>
      <h3>Session pods</h3>
      <table>
        <thead><tr><th>Adapter</th><th>Phase</th><th>Pod</th><th>Created</th><th>Last active</th><th>In flight</th></tr></thead>
        <tbody>
          {(sessions?.pods ?? []).map((p) => (
            <tr key={p.id}><td>{p.adapter}</td><td>{p.phase}</td><td>{p.podName}</td><td class="muted">{p.createdAt}</td><td class="muted">{p.lastActiveAt}</td><td>{p.inFlight}</td></tr>
          ))}
          {!sessions?.pods?.length && <tr><td colSpan={6} class="muted">none</td></tr>}
        </tbody>
      </table>
      <h3>Keycloak sessions</h3>
      <table>
        <thead><tr><th>Clients</th><th>Started</th><th>Last access</th><th>IP</th></tr></thead>
        <tbody>
          {(sessions?.keycloakSessions ?? []).map((s) => (
            <tr key={s.id}><td>{s.clients?.join(", ")}</td><td class="muted">{s.start}</td><td class="muted">{s.lastAccess}</td><td>{s.ipAddress}</td></tr>
          ))}
          {!sessions?.keycloakSessions?.length && <tr><td colSpan={4} class="muted">none</td></tr>}
        </tbody>
      </table>
    </>
  );
}
