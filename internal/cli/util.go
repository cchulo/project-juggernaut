package cli

import (
	"encoding/base64"
	"os"
)

func decodeB64(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }
func encodeB64(b []byte) string          { return base64.RawURLEncoding.EncodeToString(b) }

func writeFile0600(path string, b []byte) error { return os.WriteFile(path, b, 0o600) }
