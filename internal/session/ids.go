// Package session defines the routing table that maps gateway MCP session ids to
// session pods, and the identifiers used for both.
package session

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"strings"
)

// IDPrefix marks gateway-issued Mcp-Session-Id values.
const IDPrefix = "jg_"

// NewMcpSessionID returns a 128-bit random, URL-safe session id ("jg_" + 26 chars).
func NewMcpSessionID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("crypto/rand unavailable: " + err.Error())
	}
	return IDPrefix + strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b[:]))
}

// IsMcpSessionID reports whether s has the gateway's shape.
func IsMcpSessionID(s string) bool {
	return strings.HasPrefix(s, IDPrefix) && len(s) == len(IDPrefix)+26
}

// UserHash returns a short stable hash of a subject for use in pod names and labels.
// It is not secret; it only keeps subjects (which may be emails) out of object names.
func UserHash(subject string) string {
	sum := sha256.Sum256([]byte(subject))
	return hex.EncodeToString(sum[:4])
}

// PodKey identifies a session pod: one per (user, server type).
type PodKey struct {
	Subject    string
	ServerType string
}

// Name is the pod/session object name: <serverType>-<userHash8>.
func (k PodKey) Name() string { return k.ServerType + "-" + UserHash(k.Subject) }
