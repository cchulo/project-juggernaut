import { useEffect, useState } from "preact/hooks";
import { route } from "preact-router";
import { api, User } from "../api";

export function UsersPage(_: { path: string }) {
  const [users, setUsers] = useState<User[]>([]);
  const [search, setSearch] = useState("");
  const [groups, setGroups] = useState<string[]>([]);
  const [creating, setCreating] = useState(false);
  const [form, setForm] = useState({ username: "", email: "", firstName: "", lastName: "", groups: [] as string[], temporaryPassword: "" });
  const [err, setErr] = useState<string | null>(null);

  const load = () => api.users(search).then(setUsers).catch((e) => setErr(String(e)));
  useEffect(() => { load(); api.config().then((c) => setGroups(c.groups.map((g) => g.name))); }, []);

  const create = async (e: Event) => {
    e.preventDefault();
    try {
      const u = await api.createUser({ ...form, sendResetEmail: !form.temporaryPassword });
      setCreating(false);
      route(`/admin/users/${u.id}`);
    } catch (e) { setErr(String(e)); }
  };

  return (
    <>
      <h2>Users</h2>
      <div class="row">
        <input placeholder="search" value={search} onInput={(e) => setSearch((e.target as HTMLInputElement).value)} onKeyDown={(e) => e.key === "Enter" && load()} />
        <button onClick={load}>Search</button>
        <span style="flex:1" />
        <button class="primary" onClick={() => setCreating(!creating)}>New user</button>
      </div>
      {err && <p class="muted">{err}</p>}
      {creating && (
        <form onSubmit={create} class="row">
          <input required placeholder="username" value={form.username} onInput={(e) => setForm({ ...form, username: (e.target as HTMLInputElement).value })} />
          <input placeholder="email" value={form.email} onInput={(e) => setForm({ ...form, email: (e.target as HTMLInputElement).value })} />
          <input placeholder="first name" value={form.firstName} onInput={(e) => setForm({ ...form, firstName: (e.target as HTMLInputElement).value })} />
          <input placeholder="last name" value={form.lastName} onInput={(e) => setForm({ ...form, lastName: (e.target as HTMLInputElement).value })} />
          <select multiple onChange={(e) => setForm({ ...form, groups: Array.from((e.target as HTMLSelectElement).selectedOptions).map((o) => o.value) })}>
            {groups.map((g) => <option value={g}>{g}</option>)}
          </select>
          <input placeholder="temporary password (blank = email reset link)" value={form.temporaryPassword} onInput={(e) => setForm({ ...form, temporaryPassword: (e.target as HTMLInputElement).value })} />
          <button class="primary" type="submit">Create</button>
        </form>
      )}
      <table>
        <thead><tr><th>Username</th><th>Email</th><th>Enabled</th><th>Created</th></tr></thead>
        <tbody>
          {users.map((u) => (
            <tr key={u.id} style="cursor:pointer" onClick={() => route(`/admin/users/${u.id}`)}>
              <td>{u.username}</td><td>{u.email}</td><td>{u.enabled ? "yes" : "no"}</td><td class="muted">{u.createdAt?.slice(0, 10)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </>
  );
}
