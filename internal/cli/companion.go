package cli

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/cchulo/project-juggernaut/internal/core"
)

// Companion is the tier-B local proxy (`juggernaut connect`): MCP clients talk
// to it on loopback with no credentials in their config; it adds the user's
// bearer token and, for every adapter the user has secrets for, a blob sealed
// to that adapter's current pod key. The gateway forwards the blob without
// being able to read it.
type Companion struct {
	Gateway *Gateway
	Subject string
	UserKey []byte
	// Adapters with secrets; filled by Refresh.
	Log *slog.Logger

	mu      sync.Mutex
	plain   map[string]map[string]string // adapter → secrets (decrypted, in memory only)
	podKeys map[string]podKey
	prefix  string
}

type podKey struct {
	key     *[32]byte
	pod     string
	fetched time.Time
}

// NewCompanion builds the proxy.
func NewCompanion(g *Gateway, subject string, userKey []byte, sealedPrefix string, log *slog.Logger) *Companion {
	return &Companion{Gateway: g, Subject: subject, UserKey: userKey, Log: log,
		plain: map[string]map[string]string{}, podKeys: map[string]podKey{}, prefix: sealedPrefix}
}

// Refresh downloads and decrypts the user's entries.
func (c *Companion) Refresh(ctx context.Context) error {
	entries, err := c.Gateway.List(ctx)
	if err != nil {
		return err
	}
	fresh := map[string]map[string]string{}
	for _, e := range entries {
		vals, err := core.OpenEntry(c.UserKey, c.Subject, e.Adapter, e.Entry)
		if err != nil {
			return fmt.Errorf("entry %s: %w", e.Adapter, err)
		}
		fresh[e.Adapter] = vals
	}
	c.mu.Lock()
	for _, old := range c.plain {
		core.ZeroMap(old)
	}
	c.plain = fresh
	c.mu.Unlock()
	return nil
}

func (c *Companion) sealedHeaders(ctx context.Context, adapters []string) (http.Header, error) {
	h := http.Header{}
	for _, a := range adapters {
		c.mu.Lock()
		vals, ok := c.plain[a]
		pk, cached := c.podKeys[a]
		c.mu.Unlock()
		if !ok {
			continue
		}
		if !cached || time.Since(pk.fetched) > 5*time.Minute {
			key, pod, err := c.Gateway.SessionKey(ctx, a)
			if err != nil {
				return nil, fmt.Errorf("adapter %s: %w", a, err)
			}
			pk = podKey{key: key, pod: pod, fetched: time.Now()}
			c.mu.Lock()
			c.podKeys[a] = pk
			c.mu.Unlock()
		}
		blob, err := core.SealToPod(pk.key, vals)
		if err != nil {
			return nil, err
		}
		h.Set(c.prefix+a, base64.RawURLEncoding.EncodeToString(blob))
	}
	return h, nil
}

// ServeHTTP forwards /mcp and /adapters/{name}/mcp to the gateway.
func (c *Companion) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var adapters []string
	c.mu.Lock()
	for a := range c.plain {
		adapters = append(adapters, a)
	}
	c.mu.Unlock()
	if strings.HasPrefix(r.URL.Path, "/adapters/") {
		parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/adapters/"), "/")
		adapters = []string{parts[0]}
	}
	sealed, err := c.sealedHeaders(r.Context(), adapters)
	if err != nil {
		http.Error(w, "companion: "+err.Error(), http.StatusBadGateway)
		return
	}
	req, err := http.NewRequestWithContext(r.Context(), r.Method, strings.TrimRight(c.Gateway.URL, "/")+r.URL.RequestURI(), r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	for k, vv := range r.Header {
		if strings.HasPrefix(strings.ToLower(k), "x-juggernaut-") || strings.EqualFold(k, "Authorization") {
			continue // never trust the local client's own credentials headers
		}
		req.Header[k] = vv
	}
	req.Header.Set("Authorization", "Bearer "+c.Gateway.Token)
	for k, vv := range sealed {
		req.Header[k] = vv
	}
	resp, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		http.Error(w, "gateway: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		// A re-spawned pod has a new key; drop the cache so the next call reseals.
		c.mu.Lock()
		for _, a := range adapters {
			delete(c.podKeys, a)
		}
		c.mu.Unlock()
	}
	for k, vv := range resp.Header {
		w.Header()[k] = vv
	}
	w.WriteHeader(resp.StatusCode)
	if f, ok := w.(http.Flusher); ok && strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream") {
		buf := make([]byte, 32*1024)
		for {
			n, rerr := resp.Body.Read(buf)
			if n > 0 {
				_, _ = w.Write(buf[:n])
				f.Flush()
			}
			if rerr != nil {
				return
			}
		}
	}
	_, _ = io.Copy(w, resp.Body)
}
