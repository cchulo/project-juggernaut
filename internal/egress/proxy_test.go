package egress

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cchulo/project-juggernaut/internal/netpol"
)

// connectVia sends a CONNECT for target through the proxy and returns the status line.
func connectVia(t *testing.T, proxyAddr, target string) (string, net.Conn) {
	t.Helper()
	c, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.WriteString(c, "CONNECT "+target+" HTTP/1.1\r\nHost: "+target+"\r\n\r\n")
	line, err := bufio.NewReader(c).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(line), c
}

func TestAllowlistEnforcement(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("hi")) }))
	defer upstream.Close()
	_, upPort, _ := net.SplitHostPort(upstream.Listener.Addr().String())

	dir := t.TempDir()
	path := filepath.Join(dir, "allowlist.json")
	al := netpol.Allowlist{Entries: map[string]netpol.AllowEntry{
		"127.0.0.1": {Session: "jira-abc", Hosts: []string{"allowed.test:" + upPort}},
	}}
	b, _ := al.Marshal()
	_ = os.WriteFile(path, b, 0o600)

	// A resolver that maps allowed.test → loopback and denied.test → metadata.
	resolver := &net.Resolver{PreferGo: true, Dial: func(context.Context, string, string) (net.Conn, error) {
		return nil, io.EOF
	}}
	_ = resolver
	p := &Proxy{AllowlistPath: path, Log: slog.Default(), Dialer: &net.Dialer{Timeout: time.Second}, Resolver: net.DefaultResolver}
	p.lookup = func(_ context.Context, host string) ([]net.IP, error) {
		switch host {
		case "allowed.test":
			return []net.IP{net.ParseIP("127.0.0.1")}, nil
		case "meta.test":
			return []net.IP{net.ParseIP("169.254.169.254")}, nil
		}
		return nil, io.EOF
	}
	p.DenyCIDRs, _ = ParseCIDRs([]string{"169.254.169.254/32"})
	if err := p.LoadAllowlist(); err != nil {
		t.Fatal(err)
	}
	// Loopback is normally denied as a destination; allow it for this test's upstream.
	p.allowLoopback = true
	srv := httptest.NewServer(p)
	defer srv.Close()
	_, proxyPort, _ := net.SplitHostPort(srv.Listener.Addr().String())
	proxyAddr := "127.0.0.1:" + proxyPort

	status, c := connectVia(t, proxyAddr, "allowed.test:"+upPort)
	if !strings.Contains(status, "200") {
		t.Fatalf("allowlisted CONNECT: %s", status)
	}
	_, _ = io.WriteString(c, "GET / HTTP/1.1\r\nHost: allowed.test\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "hi" {
		t.Fatalf("tunnel body: %q", body)
	}
	c.Close()

	if status, c := connectVia(t, proxyAddr, "other.test:443"); !strings.Contains(status, "403") {
		t.Fatalf("non-allowlisted host must be 403: %s", status)
	} else {
		c.Close()
	}
	if status, c := connectVia(t, proxyAddr, "allowed.test:9999"); !strings.Contains(status, "403") {
		t.Fatalf("non-allowlisted port must be 403: %s", status)
	} else {
		c.Close()
	}
	// A permitted name that resolves into a denied CIDR is refused.
	al.Entries["127.0.0.1"] = netpol.AllowEntry{Session: "jira-abc", Hosts: []string{"meta.test:80"}}
	b, _ = al.Marshal()
	_ = os.WriteFile(path, b, 0o600)
	_ = p.LoadAllowlist()
	if status, c := connectVia(t, proxyAddr, "meta.test:80"); !strings.Contains(status, "403") {
		t.Fatalf("resolution into a denied CIDR must be 403: %s", status)
	} else {
		c.Close()
	}
	// Plain HTTP (non-CONNECT) is refused.
	resp2, _ := http.Get(srv.URL + "/anything")
	if resp2.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("non-CONNECT must be 405, got %d", resp2.StatusCode)
	}
	if p.Allowed.Load() != 1 || p.Denied.Load() < 4 {
		t.Fatalf("counters: allowed=%d denied=%d", p.Allowed.Load(), p.Denied.Load())
	}
	var parsed map[string]any
	_ = json.Unmarshal(b, &parsed)
}
