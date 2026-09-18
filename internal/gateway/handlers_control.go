package gateway

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/cchulo/project-juggernaut/internal/auth"
	"github.com/cchulo/project-juggernaut/internal/authz"
	"github.com/cchulo/project-juggernaut/internal/config"
	"github.com/cchulo/project-juggernaut/internal/session"
)

// AdapterView is the API shape of a server type (microsoft/mcp-gateway "Adapter").
type AdapterView struct {
	Name             string          `json:"name"`
	Description      string          `json:"description,omitempty"`
	Image            string          `json:"image"`
	Transport        string          `json:"transport"`
	TokenMode        string          `json:"tokenMode"`
	Egress           []config.Egress `json:"egress,omitempty"`
	IdleTimeout      string          `json:"idleTimeout,omitempty"`
	MaxSessionAge    string          `json:"maxSessionAge,omitempty"`
	RuntimeClassName string          `json:"runtimeClassName,omitempty"`
	ConfigHash       string          `json:"configHash"`
}

func adapterView(l *config.Loaded, s *config.Server) AdapterView {
	c := l.Config
	return AdapterView{
		Name: s.Name, Description: s.Description, Image: s.Image, Transport: string(s.Transport),
		TokenMode:        string(s.Token.Mode),
		Egress:           s.Egress,
		IdleTimeout:      s.IdleTimeout.Or(c.Gateway.IdleTimeout.Duration).String(),
		MaxSessionAge:    s.MaxSessionAge.Or(c.Gateway.MaxSessionAge.Duration).String(),
		RuntimeClassName: s.RuntimeClassName,
		ConfigHash:       l.Hash,
	}
}

func (s *Server) listAdapters(w http.ResponseWriter, r *http.Request) {
	l := s.Store.Get()
	p := auth.PrincipalFrom(r.Context())
	g := authz.Compute(l.Config, p, "")
	out := []AdapterView{}
	for i := range l.Config.Servers {
		if g.Allows(l.Config.Servers[i].Name) {
			out = append(out, adapterView(l, &l.Config.Servers[i]))
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) getAdapter(w http.ResponseWriter, r *http.Request) {
	l := s.Store.Get()
	p := auth.PrincipalFrom(r.Context())
	name := chi.URLParam(r, "name")
	srv := l.Config.Server(name)
	if srv == nil || !authz.Compute(l.Config, p, "").Allows(name) {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, adapterView(l, srv))
}

func (s *Server) adapterStatus(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	l := s.Store.Get()
	srv := l.Config.Server(name)
	if srv == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	pods, err := s.Table.ListPods(r.Context(), "")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	counts := map[session.Phase]int{}
	for _, p := range pods {
		if p.Key.ServerType == name {
			counts[p.Phase]++
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"name": name, "pods": counts, "maxPods": srv.MaxPods})
}

func (s *Server) adapterLogs(w http.ResponseWriter, r *http.Request) {
	p := auth.PrincipalFrom(r.Context())
	l := s.Store.Get()
	name := chi.URLParam(r, "name")
	subject := p.Subject
	if u := r.URL.Query().Get("user"); u != "" && u != p.Subject {
		if !authz.Compute(l.Config, p, "").Admin {
			http.Error(w, "admin scope required to read other users' logs", http.StatusForbidden)
			return
		}
		subject = u
	}
	logs, err := s.Backend.Logs(r.Context(), session.PodKey{Subject: subject, ServerType: name}, queryInt(r, "tailLines", 500))
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte(logs))
}

// listTools/getTool need a live pod to enumerate tools; milestone 0 returns the
// static exposure rules per adapter. Milestone 3 fills them from the router's cache.
func (s *Server) listTools(w http.ResponseWriter, r *http.Request) {
	l := s.Store.Get()
	p := auth.PrincipalFrom(r.Context())
	g := authz.Compute(l.Config, p, "")
	type toolView struct {
		Name    string `json:"name"`
		Adapter string `json:"adapter"`
		Rule    string `json:"rule"`
	}
	out := []toolView{}
	sep := l.Config.Gateway.Tools.NamespaceSeparator
	for _, srv := range l.Config.Servers {
		if !g.Allows(srv.Name) || srv.Tools.Expose == nil || srv.Tools.Expose.Mode != "allow" {
			continue
		}
		for _, n := range srv.Tools.Expose.Names {
			if exposed, ok := g.ToolVisible(&srv, n); ok {
				out = append(out, toolView{Name: srv.Name + sep + exposed, Adapter: srv.Name, Rule: "allowlist"})
			}
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) getTool(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "tool metadata is served by the router in milestone 3", http.StatusNotImplemented)
}

// SessionView is the API shape of a session pod.
type SessionView struct {
	ID           string    `json:"id"`
	Adapter      string    `json:"adapter"`
	User         string    `json:"user"`
	Phase        string    `json:"phase"`
	PodName      string    `json:"podName"`
	CreatedAt    time.Time `json:"createdAt"`
	LastActiveAt time.Time `json:"lastActiveAt,omitempty"`
	InFlight     int       `json:"inFlight"`
}

func (s *Server) sessionViews(r *http.Request, subject string) ([]SessionView, error) {
	pods, err := s.Table.ListPods(r.Context(), subject)
	if err != nil {
		return nil, err
	}
	out := make([]SessionView, 0, len(pods))
	for _, p := range pods {
		la, _ := s.Table.LastActive(r.Context(), p.Name)
		inflight, _ := s.Table.InFlight(r.Context(), p.Name, 0)
		out = append(out, SessionView{
			ID: p.Name, Adapter: p.Key.ServerType, User: p.Key.Subject, Phase: string(p.Phase),
			PodName: p.Name, CreatedAt: p.CreatedAt, LastActiveAt: la, InFlight: inflight,
		})
	}
	return out, nil
}

func (s *Server) listSessions(w http.ResponseWriter, r *http.Request) {
	p := auth.PrincipalFrom(r.Context())
	views, err := s.sessionViews(r, p.Subject)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, views)
}

func (s *Server) getSession(w http.ResponseWriter, r *http.Request) {
	p := auth.PrincipalFrom(r.Context())
	id := chi.URLParam(r, "id")
	views, err := s.sessionViews(r, p.Subject)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	for _, v := range views {
		if v.ID == id {
			writeJSON(w, http.StatusOK, v)
			return
		}
	}
	http.Error(w, "not found", http.StatusNotFound)
}

func (s *Server) deleteSession(w http.ResponseWriter, r *http.Request) {
	p := auth.PrincipalFrom(r.Context())
	id := chi.URLParam(r, "id")
	serverType, _, ok := strings.Cut(id, "-")
	if !ok {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	key := session.PodKey{Subject: p.Subject, ServerType: serverType}
	if _, err := s.Table.GetPod(r.Context(), key); errors.Is(err, session.ErrNotFound) {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if err := s.sessions.Release(r.Context(), key); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusAccepted)
}

func (s *Server) requireAdmin(w http.ResponseWriter, r *http.Request) bool {
	p := auth.PrincipalFrom(r.Context())
	if !authz.Compute(s.Store.Get().Config, p, "").Admin {
		http.Error(w, "admin required", http.StatusForbidden)
		return false
	}
	return true
}

func (s *Server) userSessions(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	views, err := s.sessionViews(r, chi.URLParam(r, "sub"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, views)
}

func (s *Server) deleteUserSessions(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	if err := s.sessions.ReleaseAll(r.Context(), chi.URLParam(r, "sub")); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusAccepted)
}
