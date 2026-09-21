package admin

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cchulo/project-juggernaut/internal/adapters/identity/static"
	"github.com/cchulo/project-juggernaut/internal/config"
	"github.com/cchulo/project-juggernaut/internal/core"
	"github.com/cchulo/project-juggernaut/internal/core/contracts"
	"github.com/cchulo/project-juggernaut/internal/core/contracts/contracttest"
)

type fakeDir struct {
	users     map[string]*contracts.User
	loggedOut []string
	groups    map[string][]string
}

func (f *fakeDir) ListUsers(context.Context, string, int, int) ([]contracts.User, error) {
	var out []contracts.User
	for _, u := range f.users {
		out = append(out, *u)
	}
	return out, nil
}
func (f *fakeDir) GetUser(_ context.Context, id string) (*contracts.User, error) {
	u, ok := f.users[id]
	if !ok {
		return nil, contracts.ErrNotFound
	}
	cp := *u
	cp.Groups = f.groups[id]
	return &cp, nil
}
func (f *fakeDir) CreateUser(_ context.Context, u contracts.User, _ string, _ bool) (*contracts.User, error) {
	u.ID = "id-" + u.Username
	u.Enabled = true
	f.users[u.ID] = &u
	f.groups[u.ID] = u.Groups
	return &u, nil
}
func (f *fakeDir) UpdateUser(_ context.Context, id string, enabled *bool, _, _, _ *string) error {
	if enabled != nil {
		f.users[id].Enabled = *enabled
	}
	return nil
}
func (f *fakeDir) SetGroups(_ context.Context, id string, groups []string) error {
	f.groups[id] = groups
	return nil
}
func (f *fakeDir) ResetPassword(context.Context, string, string, bool) error { return nil }
func (f *fakeDir) Sessions(context.Context, string) ([]contracts.IdPSession, error) {
	return []contracts.IdPSession{{ID: "kc-1"}}, nil
}
func (f *fakeDir) Logout(_ context.Context, id string) error {
	f.loggedOut = append(f.loggedOut, id)
	return nil
}
func (f *fakeDir) Groups(context.Context) ([]contracts.Group, error) {
	return []contracts.Group{{ID: "g1", Name: "engineering"}}, nil
}
func (f *fakeDir) StatusOf(error) int { return http.StatusBadGateway }

type fakeSessions struct{ released []string }

func (f *fakeSessions) EnsurePod(context.Context, *core.Principal, string) (*contracts.Pod, *config.Server, error) {
	return nil, nil, nil
}
func (f *fakeSessions) Release(context.Context, core.PodKey) error { return nil }
func (f *fakeSessions) ReleaseAll(_ context.Context, subject string) error {
	f.released = append(f.released, subject)
	return nil
}
func (f *fakeSessions) SessionsFor(context.Context, string) ([]contracts.SessionView, error) {
	return []contracts.SessionView{{ID: "jira-1", Adapter: "jira", Phase: "Ready"}}, nil
}

func newAdmin(t *testing.T) (*httptest.Server, *fakeDir, *fakeSessions) {
	t.Helper()
	cfg := strings.Replace(contracttest.LaptopConfig, "  broker: { mode: none }", "  broker: { mode: none }\n  keycloakAdmin: { realm: r, clientId: c, clientSecretRef: { env: X } }", 1)
	cfg = strings.Replace(cfg, "type: static", "type: static\n  issuer: https://idp/realms/r\n  audience: gw", 1)
	// static + keycloakAdmin is rejected by validation for real deployments; bypass by parsing then patching.
	cfg = strings.Replace(cfg, "\n  keycloakAdmin: { realm: r, clientId: c, clientSecretRef: { env: X } }", "", 1)
	ctx := contracttest.Context(t, cfg, nil, nil)
	ctx.Cfg().Identity.KeycloakAdmin = &config.KeycloakAdmin{Realm: "r", ClientID: "c", AdminRole: "juggernaut-admin"}
	id, _ := static.New(ctx)
	dir := &fakeDir{users: map[string]*contracts.User{}, groups: map[string][]string{}}
	sess := &fakeSessions{}
	s := &Server{Store: ctx.Config, Identity: id, Dir: dir, Sessions: sess, Log: slog.Default()}
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)
	return ts, dir, sess
}

func call(t *testing.T, ts *httptest.Server, method, path, token, body string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest(method, ts.URL+path, strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var sb strings.Builder
	buf := make([]byte, 4096)
	for {
		n, err := resp.Body.Read(buf)
		sb.Write(buf[:n])
		if err != nil {
			break
		}
	}
	return resp.StatusCode, sb.String()
}

func TestAdminRequiresAdminRole(t *testing.T) {
	ts, _, _ := newAdmin(t)
	if st, _ := call(t, ts, http.MethodGet, "/admin/api/users", "", ""); st != http.StatusUnauthorized {
		t.Fatalf("no token: %d", st)
	}
	// alice-token has only juggernaut:mcp and no admin group.
	if st, _ := call(t, ts, http.MethodGet, "/admin/api/users", "alice-token", ""); st != http.StatusForbidden {
		t.Fatalf("non-admin: %d", st)
	}
	// admin-token seed has every scope, including users.admin.
	if st, _ := call(t, ts, http.MethodGet, "/admin/api/users", "admin-token", ""); st != http.StatusOK {
		t.Fatalf("admin: %d", st)
	}
	if st, body := call(t, ts, http.MethodGet, "/admin/api/oidc", "", ""); st != http.StatusOK || !strings.Contains(body, "juggernaut-admin-ui") {
		t.Fatalf("oidc config must be public: %d %s", st, body)
	}
}

func TestCreateDisableAndGroups(t *testing.T) {
	ts, dir, sess := newAdmin(t)
	st, body := call(t, ts, http.MethodPost, "/admin/api/users", "admin-token", `{"username":"carol","groups":["engineering"]}`)
	if st != http.StatusCreated {
		t.Fatalf("create: %d %s", st, body)
	}
	var u map[string]any
	_ = json.Unmarshal([]byte(body), &u)
	id := u["id"].(string)
	if st, body := call(t, ts, http.MethodPost, "/admin/api/users", "admin-token", `{"username":"dave","groups":["not-in-config"]}`); st != http.StatusBadRequest {
		t.Fatalf("unknown group must be refused: %d %s", st, body)
	}
	if st, _ := call(t, ts, http.MethodPut, "/admin/api/users/"+id+"/groups", "admin-token", `{"groups":["product"]}`); st != http.StatusOK || dir.groups[id][0] != "product" {
		t.Fatalf("set groups: %d %v", st, dir.groups[id])
	}
	if len(sess.released) != 1 || sess.released[0] != id {
		t.Fatal("group change must recycle the user's pods")
	}
	if st, _ := call(t, ts, http.MethodPatch, "/admin/api/users/"+id, "admin-token", `{"enabled":false}`); st != http.StatusOK {
		t.Fatalf("disable: %d", st)
	}
	if dir.users[id].Enabled || len(dir.loggedOut) != 1 || len(sess.released) != 2 {
		t.Fatalf("disable must log out and kill pods: enabled=%v loggedOut=%v released=%v", dir.users[id].Enabled, dir.loggedOut, sess.released)
	}
	if st, body := call(t, ts, http.MethodGet, "/admin/api/users/"+id+"/sessions", "admin-token", ""); st != http.StatusOK || !strings.Contains(body, "jira-1") || !strings.Contains(body, "kc-1") {
		t.Fatalf("sessions view: %d %s", st, body)
	}
	if st, body := call(t, ts, http.MethodGet, "/admin/api/groups", "admin-token", ""); st != http.StatusOK || !strings.Contains(body, `"inKeycloak":true`) || !strings.Contains(body, `"name":"product"`) {
		t.Fatalf("groups: %d %s", st, body)
	}
}
