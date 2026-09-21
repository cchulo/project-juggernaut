package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/cchulo/project-juggernaut/internal/core"
)

// Gateway is a minimal authenticated client for /me/secrets.
type Gateway struct {
	URL   string
	Token string
	HTTP  *http.Client
}

func (g *Gateway) do(ctx context.Context, method, path string, body any) ([]byte, int, error) {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, 0, err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(g.URL, "/")+path, rd)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Authorization", "Bearer "+g.Token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	hc := g.HTTP
	if hc == nil {
		hc = http.DefaultClient
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return out, resp.StatusCode, nil
}

// SecretEntry is one adapter's blob as returned by GET /me/secrets.
type SecretEntry struct {
	Adapter string            `json:"adapter"`
	Entry   *core.SealedEntry `json:"entry"`
}

// List fetches the user's sealed entries.
func (g *Gateway) List(ctx context.Context) ([]SecretEntry, error) {
	b, st, err := g.do(ctx, http.MethodGet, "/me/secrets", nil)
	if err != nil {
		return nil, err
	}
	if st != http.StatusOK {
		return nil, fmt.Errorf("GET /me/secrets: %d %s", st, strings.TrimSpace(string(b)))
	}
	var out []SecretEntry
	return out, json.Unmarshal(b, &out)
}

// Put uploads a sealed entry.
func (g *Gateway) Put(ctx context.Context, adapter string, e *core.SealedEntry) error {
	b, st, err := g.do(ctx, http.MethodPut, "/me/secrets/"+adapter, e)
	if err != nil {
		return err
	}
	if st != http.StatusNoContent {
		return fmt.Errorf("PUT /me/secrets/%s: %d %s", adapter, st, strings.TrimSpace(string(b)))
	}
	return nil
}

// Delete removes an entry.
func (g *Gateway) Delete(ctx context.Context, adapter string) error {
	b, st, err := g.do(ctx, http.MethodDelete, "/me/secrets/"+adapter, nil)
	if err != nil {
		return err
	}
	if st != http.StatusNoContent {
		return fmt.Errorf("DELETE /me/secrets/%s: %d %s", adapter, st, strings.TrimSpace(string(b)))
	}
	return nil
}

// SessionKey fetches the pod's public key for tier-B sealing.
func (g *Gateway) SessionKey(ctx context.Context, adapter string) (*[32]byte, string, error) {
	b, st, err := g.do(ctx, http.MethodGet, "/adapters/"+adapter+"/session-key", nil)
	if err != nil {
		return nil, "", err
	}
	if st != http.StatusOK {
		return nil, "", fmt.Errorf("session-key: %d %s", st, strings.TrimSpace(string(b)))
	}
	var body struct {
		PublicKey string `json:"publicKey"`
		Pod       string `json:"pod"`
	}
	if err := json.Unmarshal(b, &body); err != nil {
		return nil, "", err
	}
	raw, err := decodeB64(body.PublicKey)
	if err != nil || len(raw) != 32 {
		return nil, "", fmt.Errorf("session-key: bad public key")
	}
	var k [32]byte
	copy(k[:], raw)
	return &k, body.Pod, nil
}

// SetSecrets seals values for (subject, adapter) locally and uploads them.
// Existing names not in values are kept (merge), so `set` can add one credential at a time.
func SetSecrets(ctx context.Context, g *Gateway, vault *VaultFile, userKey []byte, subject, adapter string, values map[string]string) error {
	merged := map[string]string{}
	entries, err := g.List(ctx)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if e.Adapter != adapter {
			continue
		}
		old, err := core.OpenEntry(userKey, subject, adapter, e.Entry)
		if err != nil {
			return fmt.Errorf("existing entry for %s: %w", adapter, err)
		}
		for k, v := range old {
			merged[k] = v
		}
		core.ZeroMap(old)
	}
	for k, v := range values {
		merged[k] = v
	}
	sealed, err := core.SealEntry(userKey, vault.Salt, vault.Argon, subject, adapter, merged)
	core.ZeroMap(merged)
	if err != nil {
		return err
	}
	return g.Put(ctx, adapter, sealed)
}

// Rotate re-encrypts every entry under a new passphrase and rewrites the vault file.
func Rotate(ctx context.Context, g *Gateway, vault *VaultFile, oldKey []byte, subject, newPassphrase string, cacheKey bool) error {
	entries, err := g.List(ctx)
	if err != nil {
		return err
	}
	newSalt := core.NewSalt()
	newKey := core.DeriveUserKey(newPassphrase, newSalt, core.DefaultArgon)
	defer core.Zero(newKey)
	for _, e := range entries {
		vals, err := core.OpenEntry(oldKey, subject, e.Adapter, e.Entry)
		if err != nil {
			return fmt.Errorf("entry %s: %w", e.Adapter, err)
		}
		sealed, err := core.SealEntry(newKey, newSalt, core.DefaultArgon, subject, e.Adapter, vals)
		core.ZeroMap(vals)
		if err != nil {
			return err
		}
		if err := g.Put(ctx, e.Adapter, sealed); err != nil {
			return err
		}
	}
	vault.Salt, vault.Argon, vault.Key = newSalt, core.DefaultArgon, ""
	if cacheKey {
		vault.Key = encodeB64(newKey)
	}
	p, err := vaultPath()
	if err != nil {
		return err
	}
	b, _ := json.MarshalIndent(vault, "", "  ")
	return writeFile0600(p, b)
}
