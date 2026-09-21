package wrapper

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"sort"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Child owns the stdio MCP server process and the MCP client session to it.
// One child process is one upstream MCP session; the wrapper multiplexes the
// gateway's HTTP sessions onto it.
type Child struct {
	cfg      *Config
	log      *slog.Logger
	redactor *Redactor

	mu            sync.Mutex
	session       *mcp.ClientSession
	cmd           *exec.Cmd
	token         string    // token the child was started with (env mode)
	tokenExp      time.Time // expiry of that token, if known
	secretsFP     string    // fingerprint of the user secrets the child was started with
	restarts      []time.Time
	generation    int
	inflight      int
	restartAtIdle bool
}

// NewChild builds a child manager; the process starts lazily on first use.
func NewChild(cfg *Config, log *slog.Logger, r *Redactor) *Child {
	return &Child{cfg: cfg, log: log, redactor: r}
}

// ErrRestartBudget is returned when the child crashed too often.
var ErrRestartBudget = errors.New("child restart budget exhausted")

// Session returns a live client session, starting the child if needed.
// token is the per-user token for env/file modes (may be empty for none/static);
// secrets are the user's credentials for this request (name → value).
func (c *Child) Session(ctx context.Context, token string, tokenExp time.Time, secrets map[string]string) (*mcp.ClientSession, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	fp := fingerprint(secrets)
	if c.session != nil {
		// Rotation: the child only read env at start. If the token or a secret
		// changed and nothing is in flight, restart now; otherwise defer to idle.
		if (c.cfg.Token.Mode == "env" && token != "" && token != c.token) || (fp != "" && fp != c.secretsFP) {
			if c.inflight == 0 {
				c.log.Info("token rotated; restarting child at idle boundary")
				c.stopLocked()
			} else {
				c.restartAtIdle = true
				return c.session, nil
			}
		} else {
			return c.session, nil
		}
	}
	if !c.restartAllowedLocked() {
		return nil, ErrRestartBudget
	}
	if err := c.startLocked(ctx, token, tokenExp, secrets); err != nil {
		return nil, err
	}
	c.secretsFP = fp
	return c.session, nil
}

// fingerprint is a stable digest of the secret values (never logged).
func fingerprint(secrets map[string]string) string {
	if len(secrets) == 0 {
		return ""
	}
	keys := make([]string, 0, len(secrets))
	for k := range secrets {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	h := sha256.New()
	for _, k := range keys {
		h.Write([]byte(k))
		h.Write([]byte{0})
		h.Write([]byte(secrets[k]))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// Begin marks a request in flight; End releases it and applies a deferred restart.
func (c *Child) Begin() { c.mu.Lock(); c.inflight++; c.mu.Unlock() }

// End decrements in-flight and honours a pending rotation restart.
func (c *Child) End() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.inflight > 0 {
		c.inflight--
	}
	if c.inflight == 0 && c.restartAtIdle {
		c.restartAtIdle = false
		c.stopLocked()
	}
}

func (c *Child) restartAllowedLocked() bool {
	window := c.cfg.Restart.Window.Or(10 * time.Minute)
	cutoff := time.Now().Add(-window)
	kept := c.restarts[:0]
	for _, t := range c.restarts {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	c.restarts = kept
	max := c.cfg.Restart.MaxRestarts
	if max == 0 {
		max = 5
	}
	return len(c.restarts) <= max
}

func (c *Child) startLocked(ctx context.Context, token string, tokenExp time.Time, secrets map[string]string) error {
	if len(c.cfg.Command) == 0 {
		return errors.New("wrapper: no command configured")
	}
	cmd := exec.Command(c.cfg.Command[0], append(c.cfg.Command[1:], c.cfg.Args...)...)
	cmd.Env = childEnv(c.cfg, token)
	for _, it := range c.cfg.UserSecrets {
		v, ok := secrets[it.Name]
		if !ok {
			continue
		}
		c.redactor.Add(v)
		if it.Env != "" {
			cmd.Env = append(cmd.Env, it.Env+"="+v)
		}
		if it.File != "" {
			if err := writeTokenFile(it.File, v); err != nil {
				return fmt.Errorf("secret file %s: %w", it.File, err)
			}
		}
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return err
	}
	go c.redactor.Pipe(stderr, c.log.With("server", c.cfg.ServerName))
	if c.cfg.Token.Mode == "file" && token != "" {
		if err := writeTokenFile(c.cfg.Token.File, token); err != nil {
			return err
		}
	}
	c.redactor.Add(token)

	client := mcp.NewClient(&mcp.Implementation{Name: "juggernaut-wrapper", Version: "0.1"}, nil)
	startCtx, cancel := context.WithTimeout(ctx, c.cfg.StartupTimeout)
	defer cancel()
	sess, err := client.Connect(startCtx, &mcp.CommandTransport{Command: cmd}, nil)
	if err != nil {
		c.restarts = append(c.restarts, time.Now())
		return fmt.Errorf("start child: %w", err)
	}
	c.generation++
	c.session, c.cmd, c.token, c.tokenExp = sess, cmd, token, tokenExp
	c.log.Info("child started", "generation", c.generation, "pid", cmd.Process.Pid)
	gen := c.generation
	go c.waitExit(sess, gen)
	return nil
}

func (c *Child) waitExit(sess *mcp.ClientSession, gen int) {
	sess.Wait()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.generation != gen {
		return
	}
	c.log.Warn("child exited", "generation", gen)
	c.restarts = append(c.restarts, time.Now())
	c.session, c.cmd = nil, nil
}

func (c *Child) stopLocked() {
	if c.session != nil {
		_ = c.session.Close()
	}
	c.session, c.cmd = nil, nil
	c.generation++
}

// Close stops the child.
func (c *Child) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.stopLocked()
}

// Running reports whether the child is alive.
func (c *Child) Running() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.session != nil
}

// Healthy is false once the restart budget is exhausted so the pod restarts.
func (c *Child) Healthy() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.restartAllowedLocked()
}

func childEnv(cfg *Config, token string) []string {
	env := []string{"PATH=" + os.Getenv("PATH"), "HOME=/tmp", "TMPDIR=/tmp"}
	for _, k := range []string{"HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY", "SSL_CERT_FILE"} {
		if v, ok := os.LookupEnv(k); ok {
			env = append(env, k+"="+v)
		}
	}
	for k, v := range cfg.Env {
		env = append(env, k+"="+v)
	}
	switch cfg.Token.Mode {
	case "env":
		if token != "" {
			env = append(env, cfg.Token.Env+"="+token)
		}
	case "file":
		env = append(env, "JUGGERNAUT_TOKEN_FILE="+cfg.Token.File)
	}
	return env
}

func writeTokenFile(path, token string) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(token), 0o400); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
