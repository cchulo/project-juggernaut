package netpol

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"

	jugv1 "github.com/cchulo/project-juggernaut/api/v1alpha1"
)

// Allowlist is what juggernaut-egress enforces: for each session pod IP, the
// host:port pairs it may CONNECT to. It is published by the controller as a
// ConfigMap and mounted into the proxy, which re-reads it on change.
type Allowlist struct {
	// Entries maps pod IP → allowed destinations.
	Entries map[string]AllowEntry `json:"entries"`
}

// AllowEntry is one pod's allowlist.
type AllowEntry struct {
	Session    string   `json:"session"`
	ServerType string   `json:"serverType"`
	Hosts      []string `json:"hosts"` // host:port, host may be *.example.com
}

// EntryFor derives the allow entry of a session from its server type.
func EntryFor(sess *jugv1.Session, st *jugv1.ServerType) AllowEntry {
	e := AllowEntry{Session: sess.Name, ServerType: st.Name}
	for _, r := range st.Spec.Egress {
		for _, p := range r.Ports {
			e.Hosts = append(e.Hosts, fmt.Sprintf("%s:%d", r.Host, p))
		}
	}
	return e
}

// Marshal renders the allowlist as JSON for the ConfigMap.
func (a *Allowlist) Marshal() ([]byte, error) { return json.MarshalIndent(a, "", "  ") }

// ParseAllowlist parses ConfigMap contents.
func ParseAllowlist(b []byte) (*Allowlist, error) {
	var a Allowlist
	if len(b) == 0 {
		return &Allowlist{Entries: map[string]AllowEntry{}}, nil
	}
	if err := json.Unmarshal(b, &a); err != nil {
		return nil, err
	}
	if a.Entries == nil {
		a.Entries = map[string]AllowEntry{}
	}
	return &a, nil
}

// Allows reports whether srcIP may connect to host:port.
func (a *Allowlist) Allows(srcIP net.IP, host string, port int) (AllowEntry, bool) {
	e, ok := a.Entries[srcIP.String()]
	if !ok {
		return AllowEntry{}, false
	}
	want := fmt.Sprintf("%s:%d", strings.ToLower(strings.TrimSuffix(host, ".")), port)
	for _, h := range e.Hosts {
		if h == want {
			return e, true
		}
		if strings.HasPrefix(h, "*.") {
			suffix := h[1:] // ".example.com:443"
			if strings.HasSuffix(want, suffix) && strings.Count(strings.TrimSuffix(want, suffix), ".") == 0 {
				return e, true
			}
		}
	}
	return e, false
}
