import { useEffect, useState } from "preact/hooks";
import Router, { Link } from "preact-router";
import { handleCallback, login, logout, token } from "./auth";
import { api } from "./api";
import { UsersPage } from "./pages/users";
import { UserPage } from "./pages/user";
import { GroupsPage } from "./pages/groups";

export function App() {
  const [ready, setReady] = useState(false);
  const [me, setMe] = useState<{ username: string } | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    (async () => {
      try {
        if (location.pathname.endsWith("/callback")) await handleCallback();
        if (!token()) {
          await login();
          return;
        }
        setMe(await api.me());
        setReady(true);
      } catch (e) {
        setError(String(e));
      }
    })();
  }, []);

  if (error) return <main><h1>Juggernaut admin</h1><p class="muted">{error}</p><button onClick={() => login()}>Log in again</button></main>;
  if (!ready) return <main><p class="muted">Signing in…</p></main>;
  return (
    <>
      <header>
        <strong>Juggernaut admin</strong>
        <Link href="/admin/" activeClassName="active">Users</Link>
        <Link href="/admin/groups" activeClassName="active">Groups</Link>
        <span style="flex:1" />
        <span class="muted">{me?.username}</span>
        <button onClick={logout}>Sign out</button>
      </header>
      <main>
        <Router>
          <UsersPage path="/admin/" />
          <UserPage path="/admin/users/:id" />
          <GroupsPage path="/admin/groups" />
        </Router>
      </main>
    </>
  );
}
