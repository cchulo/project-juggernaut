package config

import (
	"fmt"
	"os"
	"strings"
)

// Resolve returns the secret value a SecretRef points to.
// Values are read at call time so rotated files/env are picked up on reload.
func (r *SecretRef) Resolve() (string, error) {
	if r == nil {
		return "", nil
	}
	switch {
	case r.Env != "":
		v, ok := os.LookupEnv(r.Env)
		if !ok {
			return "", fmt.Errorf("secret env %s is not set", r.Env)
		}
		return v, nil
	case r.File != "":
		b, err := os.ReadFile(r.File)
		if err != nil {
			return "", fmt.Errorf("secret file %s: %w", r.File, err)
		}
		return strings.TrimRight(string(b), "\r\n"), nil
	}
	return "", fmt.Errorf("empty secret reference")
}

// IsSet reports whether the reference names a source.
func (r *SecretRef) IsSet() bool { return r != nil && (r.Env != "" || r.File != "") }
