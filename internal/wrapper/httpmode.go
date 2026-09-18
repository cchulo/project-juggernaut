package wrapper

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// httpMode fronts an HTTP-transport MCP server (Streamable HTTP or legacy SSE)
// running in the same pod: the wrapper starts the server process, reverse
// proxies /mcp to it on loopback, and rewrites the per-user token into the
// header the server expects. The server never listens on the pod network, so
// the per-pod secret check stays the only way in.
type httpMode struct {
	cfg *Config
	log interface {
		Info(string, ...any)
		Warn(string, ...any)
	}
	redactor *Redactor
	mu       sync.Mutex
	cmd      *exec.Cmd
	proxy    *httputil.ReverseProxy
	started  time.Time
}

func newHTTPMode(cfg *Config, log interface {
	Info(string, ...any)
	Warn(string, ...any)
}, r *Redactor) (*httpMode, error) {
	target, err := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", cfg.HTTPPort))
	if err != nil {
		return nil, err
	}
	m := &httpMode{cfg: cfg, log: log, redactor: r}
	rp := httputil.NewSingleHostReverseProxy(target)
	base := rp.Director
	rp.Director = func(req *http.Request) {
		base(req)
		// The gateway sent the downstream token as Authorization; move it to
		// the header the server expects (usually the same) and drop pod headers.
		tok := req.Header.Get("Authorization")
		req.Header.Del(HeaderPodToken)
		req.Header.Del(HeaderSubject)
		if cfg.Token.Mode == "header" && tok != "" {
			h := cfg.Token.Header
			if h == "" {
				h = "Authorization"
			}
			if h != "Authorization" {
				req.Header.Del("Authorization")
				val := strings.TrimSpace(strings.TrimPrefix(tok, "Bearer"))
				if cfg.Token.Scheme != "" {
					val = cfg.Token.Scheme + " " + val
				}
				req.Header.Set(h, val)
			}
		}
		if cfg.HTTPPath != "" {
			req.URL.Path = cfg.HTTPPath
		}
		req.Host = target.Host
	}
	rp.FlushInterval = -1 // stream SSE immediately
	m.proxy = rp
	return m, nil
}

// ensureStarted launches the HTTP server process once.
func (m *httpMode) ensureStarted(ctx context.Context, staticToken string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cmd != nil {
		return nil
	}
	if len(m.cfg.Command) == 0 {
		return fmt.Errorf("wrapper: http transport requires command")
	}
	cmd := exec.CommandContext(context.WithoutCancel(ctx), m.cfg.Command[0], append(m.cfg.Command[1:], m.cfg.Args...)...)
	cmd.Env = childEnv(m.cfg, staticToken)
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return err
	}
	cmd.Stdout = os.Stdout
	if err := cmd.Start(); err != nil {
		return err
	}
	go m.redactor.Pipe(stderr, nil)
	m.cmd = cmd
	m.started = time.Now()
	m.log.Info("http server child started", "pid", cmd.Process.Pid, "port", m.cfg.HTTPPort)
	// Wait for the port to accept connections, bounded by the startup timeout.
	deadline := time.Now().Add(m.cfg.StartupTimeout)
	for time.Now().Before(deadline) {
		resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d%s", m.cfg.HTTPPort, m.cfg.HTTPPath))
		if err == nil {
			resp.Body.Close()
			return nil
		}
		time.Sleep(200 * time.Millisecond)
	}
	return fmt.Errorf("http server did not open port %d within %s", m.cfg.HTTPPort, m.cfg.StartupTimeout)
}

func (m *httpMode) running() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.cmd != nil && m.cmd.ProcessState == nil
}

func (m *httpMode) stop() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cmd != nil && m.cmd.Process != nil {
		_ = m.cmd.Process.Kill()
	}
	m.cmd = nil
}
