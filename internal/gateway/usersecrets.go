package gateway

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/cchulo/project-juggernaut/internal/config"
	"github.com/cchulo/project-juggernaut/internal/core"
	"github.com/cchulo/project-juggernaut/internal/core/contracts"
)

// UserSecretHeaders are the headers the gateway forwards to a pod for one
// request: plaintext items (tier A / header source) and the tier-B sealed
// blob. Plaintext values live only for the request; callers Zero them.
type UserSecretHeaders struct {
	Plain  map[string]string // secret name → value
	Sealed string            // base64 blob sealed to the pod key, or ""
}

// ErrMissingUserSecret names a required secret the caller did not supply.
type ErrMissingUserSecret struct {
	Adapter, Name string
	Sources       []string
}

func (e *ErrMissingUserSecret) Error() string {
	return fmt.Sprintf("adapter %s requires user secret %s (sources: %s)", e.Adapter, e.Name, strings.Join(e.Sources, ", "))
}

// ResolveUserSecrets collects the secrets a server type declares for the
// calling user, in the order of servers[].userSecrets.sources:
//
//	header  X-Juggernaut-Secret-<NAME> sent by the client
//	store   the sealed vault entry, opened with X-Juggernaut-Vault-Key for this request only
//	sealed  X-Juggernaut-Sealed-Secrets-<adapter>, forwarded blindly to the pod
//
// Anything not declared is dropped. A required item missing from every source
// is an error before any pod is spawned.
func (s *Server) ResolveUserSecrets(ctx context.Context, hdr http.Header, p *core.Principal, srv *config.Server) (*UserSecretHeaders, error) {
	out := &UserSecretHeaders{Plain: map[string]string{}}
	if srv.UserSecrets == nil {
		return out, nil
	}
	cfg := s.Store.Get().Config.Gateway.UserSecrets
	declared := map[string]config.UserSecretItem{}
	for _, it := range srv.UserSecrets.Items {
		declared[it.Name] = it
	}
	var storeErr error
	for _, src := range srv.UserSecrets.Sources {
		switch src {
		case "header":
			for name := range declared {
				if v := hdr.Get(cfg.SecretHeaderPrefix + name); v != "" {
					if _, have := out.Plain[name]; !have {
						out.Plain[name] = v
					}
				}
			}
		case "store":
			if s.SecretStore == nil {
				continue
			}
			keyB64 := hdr.Get(cfg.VaultKeyHeader)
			if keyB64 == "" {
				continue
			}
			key, err := base64.RawURLEncoding.DecodeString(keyB64)
			if err != nil || len(key) != 32 {
				storeErr = errors.New("vault key header is not 32 base64url bytes")
				continue
			}
			entry, err := s.SecretStore.Get(ctx, p.Subject, srv.Name)
			if errors.Is(err, contracts.ErrNotFound) {
				core.Zero(key)
				continue
			}
			if err != nil {
				core.Zero(key)
				return nil, err
			}
			vals, err := core.OpenEntry(key, p.Subject, srv.Name, entry)
			core.Zero(key)
			if err != nil {
				storeErr = err
				continue
			}
			for name, v := range vals {
				if _, ok := declared[name]; ok {
					if _, have := out.Plain[name]; !have {
						out.Plain[name] = v
					}
				}
			}
			core.ZeroMap(vals)
		case "sealed":
			if v := hdr.Get(cfg.SealedHeaderPrefix + srv.Name); v != "" {
				out.Sealed = v
			}
		}
	}
	for _, it := range srv.UserSecrets.Items {
		if !it.Required {
			continue
		}
		if _, ok := out.Plain[it.Name]; ok || out.Sealed != "" {
			continue
		}
		if storeErr != nil {
			return nil, fmt.Errorf("%w (vault: %v)", &ErrMissingUserSecret{Adapter: srv.Name, Name: it.Name, Sources: srv.UserSecrets.Sources}, storeErr)
		}
		return nil, &ErrMissingUserSecret{Adapter: srv.Name, Name: it.Name, Sources: srv.UserSecrets.Sources}
	}
	return out, nil
}

// Headers renders the resolved secrets as the headers the wrapper understands.
func (u *UserSecretHeaders) Headers(cfg config.UserSecretsGateway) http.Header {
	h := http.Header{}
	for name, v := range u.Plain {
		h.Set(cfg.SecretHeaderPrefix+name, v)
	}
	if u.Sealed != "" {
		h.Set(strings.TrimSuffix(cfg.SealedHeaderPrefix, "-"), u.Sealed)
	}
	return h
}

// --- /me/secrets: the user's own vault entries (ciphertext only) -------------

func (s *Server) meSecretsList(w http.ResponseWriter, r *http.Request) {
	if s.SecretStore == nil {
		http.Error(w, "user secret store not configured", http.StatusNotImplemented)
		return
	}
	p := core.PrincipalFrom(r.Context())
	adapters, err := s.SecretStore.List(r.Context(), p.Subject)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	type view struct {
		Adapter string            `json:"adapter"`
		Entry   *core.SealedEntry `json:"entry"`
	}
	out := []view{}
	for _, a := range adapters {
		e, err := s.SecretStore.Get(r.Context(), p.Subject, a)
		if err == nil {
			out = append(out, view{Adapter: a, Entry: e})
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) meSecretsPut(w http.ResponseWriter, r *http.Request) {
	if s.SecretStore == nil {
		http.Error(w, "user secret store not configured", http.StatusNotImplemented)
		return
	}
	p := core.PrincipalFrom(r.Context())
	adapter := chi.URLParam(r, "adapter")
	srv := s.Store.Get().Config.Server(adapter)
	if srv == nil || srv.UserSecrets == nil {
		http.Error(w, "adapter does not declare userSecrets", http.StatusNotFound)
		return
	}
	var e core.SealedEntry
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&e); err != nil {
		http.Error(w, "bad sealed entry", http.StatusBadRequest)
		return
	}
	if e.Version != core.VaultVersion || len(e.Ciphertext) == 0 || len(e.WrappedDEK) == 0 || len(e.Salt) == 0 {
		http.Error(w, "sealed entry is incomplete", http.StatusBadRequest)
		return
	}
	declared := map[string]bool{}
	for _, it := range srv.UserSecrets.Items {
		declared[it.Name] = true
	}
	for _, n := range e.Names {
		if !declared[n] {
			http.Error(w, "entry names undeclared secret "+n, http.StatusBadRequest)
			return
		}
	}
	if err := s.SecretStore.Put(r.Context(), p.Subject, adapter, &e); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.audit("user_secrets.put", p.Subject, adapter, e.Names)
	// A new credential must reach the child: recycle the user's pod for this adapter.
	_ = s.sessions.Release(r.Context(), core.PodKey{Subject: p.Subject, ServerType: adapter})
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) meSecretsDelete(w http.ResponseWriter, r *http.Request) {
	if s.SecretStore == nil {
		http.Error(w, "user secret store not configured", http.StatusNotImplemented)
		return
	}
	p := core.PrincipalFrom(r.Context())
	adapter := chi.URLParam(r, "adapter")
	if err := s.SecretStore.Delete(r.Context(), p.Subject, adapter); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.audit("user_secrets.delete", p.Subject, adapter, nil)
	_ = s.sessions.Release(r.Context(), core.PodKey{Subject: p.Subject, ServerType: adapter})
	w.WriteHeader(http.StatusNoContent)
}

// adapterSessionKey returns the pod's ephemeral public key so a client can
// seal secrets to it (tier B). Only the pod's owner can ask, and asking
// spawns the pod if needed.
func (s *Server) adapterSessionKey(w http.ResponseWriter, r *http.Request) {
	p := core.PrincipalFrom(r.Context())
	name := chi.URLParam(r, "name")
	pod, _, err := s.sessions.EnsurePod(r.Context(), p, name)
	if err != nil {
		s.writeEnsureError(w, err)
		return
	}
	key, err := s.proxy.SessionKey(r.Context(), pod)
	if err != nil {
		http.Error(w, "pod did not return a session key: "+err.Error(), http.StatusBadGateway)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"adapter": name, "pod": pod.Name, "publicKey": key, "algorithm": "x25519-nacl-box"})
}

func (s *Server) audit(action, subject, adapter string, names []string) {
	if s.Hooks.OnAdminAction != nil {
		s.Hooks.OnAdminAction(subject, action, adapter+" "+strings.Join(names, ","))
	}
}
