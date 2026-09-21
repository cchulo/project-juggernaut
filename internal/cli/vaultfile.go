// Package cli holds the user-side vault and the local companion used by the
// juggernaut binary. The vault key never leaves this machine: it is derived
// from the passphrase once and kept in a 0600 file under the user's config
// directory (an OS keychain backend can replace the file later).
package cli

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/cchulo/project-juggernaut/internal/core"
)

// VaultFile is what `juggernaut secrets init` writes.
type VaultFile struct {
	Version int              `json:"version"`
	Subject string           `json:"subject,omitempty"`
	Salt    []byte           `json:"salt"`
	Argon   core.ArgonParams `json:"argon"`
	// Key is K_user, base64url. Present only when the user chose to cache it
	// (the default); otherwise the passphrase is asked for each command.
	Key string `json:"key,omitempty"`
}

// Dir is the user's config directory.
func Dir() (string, error) {
	if d := os.Getenv("JUGGERNAUT_HOME"); d != "" {
		return d, nil
	}
	base, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "juggernaut"), nil
}

func vaultPath() (string, error) {
	d, err := Dir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, "vault.json"), nil
}

// InitVault creates the vault file from a passphrase.
func InitVault(passphrase string, cacheKey bool) (*VaultFile, error) {
	p, err := vaultPath()
	if err != nil {
		return nil, err
	}
	if _, err := os.Stat(p); err == nil {
		return nil, fmt.Errorf("%s already exists; use `secrets rotate` to change the passphrase", p)
	}
	v := &VaultFile{Version: 1, Salt: core.NewSalt(), Argon: core.DefaultArgon}
	if cacheKey {
		k := core.DeriveUserKey(passphrase, v.Salt, v.Argon)
		v.Key = base64.RawURLEncoding.EncodeToString(k)
		core.Zero(k)
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return nil, err
	}
	b, _ := json.MarshalIndent(v, "", "  ")
	return v, os.WriteFile(p, b, 0o600)
}

// LoadVault reads the vault file.
func LoadVault() (*VaultFile, error) {
	p, err := vaultPath()
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return nil, fmt.Errorf("no vault at %s; run `juggernaut secrets init`", p)
	}
	var v VaultFile
	if err := json.Unmarshal(b, &v); err != nil {
		return nil, err
	}
	return &v, nil
}

// UserKey returns K_user, from the cache or by deriving it from a passphrase.
func (v *VaultFile) UserKey(passphrase string) ([]byte, error) {
	if v.Key != "" {
		k, err := base64.RawURLEncoding.DecodeString(v.Key)
		if err != nil || len(k) != 32 {
			return nil, errors.New("vault file: bad cached key")
		}
		return k, nil
	}
	if passphrase == "" {
		return nil, errors.New("vault key is not cached; pass --passphrase or set JUGGERNAUT_VAULT_PASSPHRASE")
	}
	return core.DeriveUserKey(passphrase, v.Salt, v.Argon), nil
}
