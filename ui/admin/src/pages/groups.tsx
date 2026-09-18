import { useEffect, useState } from "preact/hooks";
import { api, Group } from "../api";

export function GroupsPage(_: { path: string }) {
  const [groups, setGroups] = useState<Group[]>([]);
  useEffect(() => { api.groups().then(setGroups); }, []);
  return (
    <>
      <h2>Groups</h2>
      <p class="muted">Defined in juggernaut.yaml (authorization.groups). Membership is managed per user; a group missing in Keycloak must be created there.</p>
      <table>
        <thead><tr><th>Group</th><th>Server types</th><th>Admin</th><th>In Keycloak</th></tr></thead>
        <tbody>
          {groups.map((g) => (
            <tr key={g.name}><td>{g.name}</td><td>{g.serverTypes.join(", ")}</td><td>{g.admin ? "yes" : ""}</td><td>{g.inKeycloak ? "yes" : <span class="badge">missing</span>}</td></tr>
          ))}
        </tbody>
      </table>
    </>
  );
}
