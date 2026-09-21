package admin

import (
	"embed"
	"encoding/json"
	"io/fs"
	"log/slog"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/cchulo/project-juggernaut/internal/config"
	"github.com/cchulo/project-juggernaut/internal/core"
	"github.com/cchulo/project-juggernaut/internal/core/contracts"
)

//go:embed ui/dist
var uiFS embed.FS

// User is the API view of a directory user.
type User = contracts.User

// Server is the admin listener's handler. It depends on contracts only.
type Server struct {
	Store    *config.Store
	Identity contracts.IdentityProvider
	Dir      contracts.Directory
	Sessions contracts.SessionManager
	Log      *slog.Logger
	// OnAction receives audit records of admin mutations.
	OnAction func(actor, action, target string)
}

// Handler mounts the API under /admin/api and the SPA under /admin.
func (s *Server) Handler() http.Handler {
	r := chi.NewRouter()
	r.Route("/admin/api", func(r chi.Router) {
		r.Use(s.requireAdmin)
		r.Get("/me", s.me)
		r.Get("/config", s.uiConfig)
		r.Get("/users", s.listUsers)
		r.Post("/users", s.createUser)
		r.Get("/users/{id}", s.getUser)
		r.Patch("/users/{id}", s.patchUser)
		r.Put("/users/{id}/groups", s.setGroups)
		r.Post("/users/{id}/reset-password", s.resetPassword)
		r.Get("/users/{id}/sessions", s.userSessions)
		r.Delete("/users/{id}/sessions", s.killSessions)
		r.Get("/groups", s.groups)
	})
	// /admin/api/oidc is unauthenticated: the SPA needs issuer + client id to start PKCE.
	r.Get("/admin/api/oidc", s.oidcConfig)
	sub, _ := fs.Sub(uiFS, "ui/dist")
	static := http.FileServer(http.FS(sub))
	r.Get("/admin", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/admin/", http.StatusFound) })
	r.Get("/admin/*", func(w http.ResponseWriter, req *http.Request) {
		p := strings.TrimPrefix(req.URL.Path, "/admin/")
		if p == "" || p == "callback" || !strings.Contains(p, ".") {
			req.URL.Path = "/" // SPA routes
		} else {
			req.URL.Path = "/" + p
		}
		w.Header().Set("Cache-Control", "no-store")
		static.ServeHTTP(w, req)
	})
	return r
}

// requireAdmin validates the bearer token and the admin role/scope.
func (s *Server) requireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg := s.Store.Get().Config
		req := contracts.RequestInfoFrom(r)
		if _, ok := req.Bearer(); !ok {
			w.Header().Set("WWW-Authenticate", `Bearer realm="juggernaut-admin"`)
			http.Error(w, "admin token required", http.StatusUnauthorized)
			return
		}
		p, err := s.Identity.Resolve(r.Context(), req)
		if err != nil {
			http.Error(w, "invalid token", http.StatusUnauthorized)
			return
		}
		role := "juggernaut-admin"
		if cfg.Identity.KeycloakAdmin != nil && cfg.Identity.KeycloakAdmin.AdminRole != "" {
			role = cfg.Identity.KeycloakAdmin.AdminRole
		}
		if !p.HasScope(cfg.Identity.Scopes.UsersAdmin) && !p.InGroup(role) {
			http.Error(w, "admin role required", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r.WithContext(core.WithPrincipal(r.Context(), p)))
	})
}

func (s *Server) oidcConfig(w http.ResponseWriter, _ *http.Request) {
	cfg := s.Store.Get().Config
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":   cfg.Identity.Issuer,
		"clientId": "juggernaut-admin-ui",
		"scope":    "openid profile " + cfg.Identity.Scopes.UsersAdmin,
	})
}

func (s *Server) me(w http.ResponseWriter, r *http.Request) {
	p := core.PrincipalFrom(r.Context())
	writeJSON(w, http.StatusOK, map[string]any{"subject": p.Subject, "username": p.Username, "groups": p.Groups})
}

func (s *Server) uiConfig(w http.ResponseWriter, _ *http.Request) {
	cfg := s.Store.Get().Config
	type g struct {
		Name        string   `json:"name"`
		ServerTypes []string `json:"serverTypes"`
		Admin       bool     `json:"admin"`
	}
	var groups []g
	for _, grp := range cfg.Authorization.Groups {
		groups = append(groups, g{grp.Name, grp.ServerTypes, grp.Admin})
	}
	writeJSON(w, http.StatusOK, map[string]any{"groups": groups, "serverTypes": cfg.ServerNames()})
}

func (s *Server) listUsers(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	first, max := atoi(q.Get("first"), 0), atoi(q.Get("max"), 50)
	users, err := s.Dir.ListUsers(r.Context(), q.Get("search"), first, max)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, users)
}

func (s *Server) getUser(w http.ResponseWriter, r *http.Request) {
	u, err := s.Dir.GetUser(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, u)
}

func (s *Server) createUser(w http.ResponseWriter, r *http.Request) {
	var in struct {
		User
		TemporaryPassword string `json:"temporaryPassword"`
		SendResetEmail    *bool  `json:"sendResetEmail"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.Username == "" {
		http.Error(w, "username required", http.StatusBadRequest)
		return
	}
	if err := s.onlyKnownGroups(in.Groups); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	send := in.SendResetEmail == nil || *in.SendResetEmail
	u, err := s.Dir.CreateUser(r.Context(), in.User, in.TemporaryPassword, send)
	if err != nil {
		s.fail(w, err)
		return
	}
	s.audit(r, "user.create", u.ID)
	writeJSON(w, http.StatusCreated, u)
}

func (s *Server) patchUser(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Enabled   *bool   `json:"enabled"`
		Email     *string `json:"email"`
		FirstName *string `json:"firstName"`
		LastName  *string `json:"lastName"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		http.Error(w, "bad body", http.StatusBadRequest)
		return
	}
	id := chi.URLParam(r, "id")
	if err := s.Dir.UpdateUser(r.Context(), id, in.Enabled, in.Email, in.FirstName, in.LastName); err != nil {
		s.fail(w, err)
		return
	}
	if in.Enabled != nil && !*in.Enabled {
		// Disabling a user ends their pods immediately; the IdP disable alone
		// would let a valid JWT keep working until expiry.
		_ = s.Dir.Logout(r.Context(), id)
		if s.Sessions != nil {
			_ = s.Sessions.ReleaseAll(r.Context(), id)
		}
		s.audit(r, "user.disable", id)
	} else {
		s.audit(r, "user.update", id)
	}
	w.WriteHeader(http.StatusOK)
}

func (s *Server) setGroups(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Groups []string `json:"groups"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		http.Error(w, "bad body", http.StatusBadRequest)
		return
	}
	if err := s.onlyKnownGroups(in.Groups); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	id := chi.URLParam(r, "id")
	if err := s.Dir.SetGroups(r.Context(), id, in.Groups); err != nil {
		s.fail(w, err)
		return
	}
	// Group changes alter grants; running pods for revoked types are killed.
	if s.Sessions != nil {
		_ = s.Sessions.ReleaseAll(r.Context(), id)
	}
	s.audit(r, "user.groups", id)
	w.WriteHeader(http.StatusOK)
}

func (s *Server) resetPassword(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Value     string `json:"value"`
		Temporary *bool  `json:"temporary"`
	}
	_ = json.NewDecoder(r.Body).Decode(&in)
	id := chi.URLParam(r, "id")
	if err := s.Dir.ResetPassword(r.Context(), id, in.Value, in.Temporary == nil || *in.Temporary); err != nil {
		s.fail(w, err)
		return
	}
	s.audit(r, "user.reset-password", id)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) userSessions(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	kc, err := s.Dir.Sessions(r.Context(), id)
	if err != nil {
		s.fail(w, err)
		return
	}
	var pods []contracts.SessionView
	if s.Sessions != nil {
		pods, _ = s.Sessions.SessionsFor(r.Context(), id)
	}
	writeJSON(w, http.StatusOK, map[string]any{"keycloakSessions": kc, "pods": pods})
}

func (s *Server) killSessions(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := s.Dir.Logout(r.Context(), id); err != nil {
		s.fail(w, err)
		return
	}
	if s.Sessions != nil {
		_ = s.Sessions.ReleaseAll(r.Context(), id)
	}
	s.audit(r, "user.kill-sessions", id)
	w.WriteHeader(http.StatusAccepted)
}

func (s *Server) groups(w http.ResponseWriter, r *http.Request) {
	cfg := s.Store.Get().Config
	kc, err := s.Dir.Groups(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	type view struct {
		Name        string   `json:"name"`
		KeycloakID  string   `json:"keycloakId,omitempty"`
		ServerTypes []string `json:"serverTypes"`
		Admin       bool     `json:"admin"`
		InKeycloak  bool     `json:"inKeycloak"`
	}
	byName := map[string]contracts.Group{}
	for _, g := range kc {
		byName[g.Name] = g
	}
	var out []view
	for _, g := range cfg.Authorization.Groups {
		v := view{Name: g.Name, ServerTypes: g.ServerTypes, Admin: g.Admin}
		if k, ok := byName[g.Name]; ok {
			v.KeycloakID, v.InKeycloak = k.ID, true
		}
		out = append(out, v)
	}
	writeJSON(w, http.StatusOK, out)
}

// onlyKnownGroups restricts assignment to groups named in authorization.groups,
// so the UI cannot hand out Keycloak groups Juggernaut does not know about.
func (s *Server) onlyKnownGroups(groups []string) error {
	cfg := s.Store.Get().Config
	for _, g := range groups {
		known := false
		for _, cg := range cfg.Authorization.Groups {
			if cg.Name == g {
				known = true
			}
		}
		if !known {
			return errUnknownGroup(g)
		}
	}
	return nil
}

type errUnknownGroup string

func (e errUnknownGroup) Error() string { return "group not in juggernaut.yaml: " + string(e) }

func (s *Server) audit(r *http.Request, action, target string) {
	if s.OnAction == nil {
		return
	}
	p := core.PrincipalFrom(r.Context())
	s.OnAction(p.Subject, action, target)
}

func (s *Server) fail(w http.ResponseWriter, err error) {
	s.Log.Warn("admin api error", "err", err)
	http.Error(w, err.Error(), s.Dir.StatusOf(err))
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func atoi(s string, def int) int {
	if s == "" {
		return def
	}
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return def
		}
		n = n*10 + int(c-'0')
	}
	return n
}
