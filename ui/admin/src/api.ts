import { token, login } from "./auth";

export type User = {
  id: string; username: string; email?: string; firstName?: string; lastName?: string;
  enabled: boolean; groups?: string[]; createdAt?: string;
};
export type Group = { name: string; keycloakId?: string; serverTypes: string[]; admin: boolean; inKeycloak: boolean };
export type Pod = { id: string; adapter: string; phase: string; podName: string; createdAt: string; lastActiveAt?: string; inFlight: number };
export type KeycloakSession = { id: string; clients?: string[]; start: string; lastAccess: string; ipAddress?: string };

async function call<T>(method: string, path: string, body?: unknown): Promise<T> {
  const t = token();
  if (!t) {
    await login();
    throw new Error("redirecting to login");
  }
  const res = await fetch(`/admin/api${path}`, {
    method,
    headers: { Authorization: `Bearer ${t}`, ...(body ? { "Content-Type": "application/json" } : {}) },
    body: body ? JSON.stringify(body) : undefined,
  });
  if (res.status === 401) {
    await login();
    throw new Error("redirecting to login");
  }
  if (!res.ok) throw new Error(`${method} ${path}: ${res.status} ${await res.text()}`);
  if (res.status === 204 || res.status === 202) return undefined as T;
  const text = await res.text();
  return (text ? JSON.parse(text) : undefined) as T;
}

export const api = {
  me: () => call<{ subject: string; username: string; groups: string[] }>("GET", "/me"),
  config: () => call<{ groups: { name: string; serverTypes: string[]; admin: boolean }[]; serverTypes: string[] }>("GET", "/config"),
  users: (search = "", first = 0, max = 50) => call<User[]>("GET", `/users?search=${encodeURIComponent(search)}&first=${first}&max=${max}`),
  user: (id: string) => call<User>("GET", `/users/${id}`),
  createUser: (u: Partial<User> & { username: string; temporaryPassword?: string; sendResetEmail?: boolean }) => call<User>("POST", "/users", u),
  patchUser: (id: string, patch: Partial<Pick<User, "enabled" | "email" | "firstName" | "lastName">>) => call<void>("PATCH", `/users/${id}`, patch),
  setGroups: (id: string, groups: string[]) => call<void>("PUT", `/users/${id}/groups`, { groups }),
  resetPassword: (id: string, value?: string, temporary = true) => call<void>("POST", `/users/${id}/reset-password`, { value, temporary }),
  sessions: (id: string) => call<{ keycloakSessions: KeycloakSession[]; pods: Pod[] }>("GET", `/users/${id}/sessions`),
  killSessions: (id: string) => call<void>("DELETE", `/users/${id}/sessions`),
  groups: () => call<Group[]>("GET", "/groups"),
};
