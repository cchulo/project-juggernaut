// Package egress is the fallback hostname-level egress enforcer for clusters
// whose CNI cannot express FQDN policies. Session pods are given no DNS and a
// NetworkPolicy that only reaches this proxy; the proxy accepts CONNECT
// requests, checks (source pod IP, host, port) against the allowlist the
// controller publishes, resolves the name itself, and refuses destinations in
// denied CIDRs even if a permitted name resolves there (DNS rebinding).
package egress

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fsnotify/fsnotify"

	"github.com/cchulo/project-juggernaut/internal/netpol"
)

// Proxy is the CONNECT proxy.
type Proxy struct {
	AllowlistPath string
	DenyCIDRs     []*net.IPNet
	Log           *slog.Logger
	Dialer        *net.Dialer
	Resolver      *net.Resolver

	allow atomic.Pointer[netpol.Allowlist]
	mu    sync.Mutex
	// lookup overrides name resolution (tests); nil uses Resolver.
	lookup func(ctx context.Context, host string) ([]net.IP, error)
	// allowLoopback permits loopback destinations (tests only).
	allowLoopback bool
	// Metrics counters (exported by the metrics handler).
	Allowed, Denied atomic.Int64
}

// LoadAllowlist reads the allowlist file into memory.
func (p *Proxy) LoadAllowlist() error {
	b, err := os.ReadFile(p.AllowlistPath)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	a, err := netpol.ParseAllowlist(b)
	if err != nil {
		return err
	}
	p.allow.Store(a)
	p.Log.Info("allowlist loaded", "pods", len(a.Entries))
	return nil
}

// Watch reloads the allowlist when the mounted ConfigMap changes.
func (p *Proxy) Watch(ctx context.Context) error {
	w, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	defer w.Close()
	if err := w.Add(filepath.Dir(p.AllowlistPath)); err != nil {
		return err
	}
	tick := time.NewTicker(10 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-w.Events:
			_ = p.LoadAllowlist()
		case <-tick.C:
			_ = p.LoadAllowlist()
		}
	}
}

// ServeHTTP handles CONNECT only; everything else is refused so plain HTTP
// cannot be tunnelled to arbitrary hosts.
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodConnect {
		p.Denied.Add(1)
		http.Error(w, "only CONNECT is allowed", http.StatusMethodNotAllowed)
		return
	}
	srcHost, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		http.Error(w, "bad remote", http.StatusBadRequest)
		return
	}
	src := net.ParseIP(srcHost)
	host, portStr, err := net.SplitHostPort(r.Host)
	if err != nil {
		http.Error(w, "bad target", http.StatusBadRequest)
		return
	}
	port, _ := strconv.Atoi(portStr)
	a := p.allow.Load()
	if a == nil {
		http.Error(w, "allowlist not loaded", http.StatusServiceUnavailable)
		return
	}
	entry, ok := a.Allows(src, host, port)
	if !ok {
		p.Denied.Add(1)
		p.Log.Warn("egress denied", "src", src, "host", host, "port", port, "session", entry.Session)
		http.Error(w, "destination not in allowlist", http.StatusForbidden)
		return
	}
	// Resolve here; the pod has no resolver.
	ips, err := p.resolve(r.Context(), host)
	if err != nil || len(ips) == 0 {
		http.Error(w, "resolve failed", http.StatusBadGateway)
		return
	}
	var target net.IP
	for _, ip := range ips {
		if !p.denied(ip) {
			target = ip
			break
		}
	}
	if target == nil {
		p.Denied.Add(1)
		p.Log.Warn("egress denied: resolved into denied CIDR", "host", host, "session", entry.Session)
		http.Error(w, "destination resolves to a denied address", http.StatusForbidden)
		return
	}
	upstream, err := p.Dialer.DialContext(r.Context(), "tcp", net.JoinHostPort(target.String(), portStr))
	if err != nil {
		http.Error(w, "dial failed", http.StatusBadGateway)
		return
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		upstream.Close()
		http.Error(w, "hijack unsupported", http.StatusInternalServerError)
		return
	}
	conn, rw, err := hj.Hijack()
	if err != nil {
		upstream.Close()
		return
	}
	p.Allowed.Add(1)
	_, _ = rw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
	_ = rw.Flush()
	p.Log.Debug("egress allowed", "src", src, "host", host, "port", port, "session", entry.Session)
	pipe(conn, rw, upstream)
}

func (p *Proxy) resolve(ctx context.Context, host string) ([]net.IP, error) {
	if p.lookup != nil {
		return p.lookup(ctx, host)
	}
	addrs, err := p.Resolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	out := make([]net.IP, 0, len(addrs))
	for _, a := range addrs {
		out = append(out, a.IP)
	}
	return out, nil
}

func (p *Proxy) denied(ip net.IP) bool {
	for _, n := range p.DenyCIDRs {
		if n.Contains(ip) {
			return true
		}
	}
	if ip.IsLoopback() {
		return !p.allowLoopback
	}
	return ip.IsLinkLocalUnicast() || ip.IsPrivate() || ip.IsUnspecified()
}

func pipe(client net.Conn, clientRW *bufio.ReadWriter, upstream net.Conn) {
	defer client.Close()
	defer upstream.Close()
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(upstream, clientRW); done <- struct{}{} }()
	go func() { _, _ = io.Copy(client, upstream); done <- struct{}{} }()
	<-done
}

// ParseCIDRs parses deny CIDRs from config.
func ParseCIDRs(list []string) ([]*net.IPNet, error) {
	var out []*net.IPNet
	for _, s := range list {
		_, n, err := net.ParseCIDR(s)
		if err != nil {
			return nil, fmt.Errorf("cidr %q: %w", s, err)
		}
		out = append(out, n)
	}
	return out, nil
}
