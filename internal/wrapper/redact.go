package wrapper

import (
	"bufio"
	"io"
	"log/slog"
	"regexp"
	"strings"
	"sync"
)

var bearerRe = regexp.MustCompile(`(?i)bearer\s+[A-Za-z0-9._~+/=-]{16,}`)

// Redactor rewrites child stderr so tokens never reach pod logs.
type Redactor struct {
	mu      sync.RWMutex
	secrets []string
	enabled bool
}

// NewRedactor builds a redactor.
func NewRedactor(enabled bool) *Redactor { return &Redactor{enabled: enabled} }

// Add registers a secret value to scrub.
func (r *Redactor) Add(secret string) {
	if secret == "" {
		return
	}
	r.mu.Lock()
	r.secrets = append(r.secrets, secret)
	if len(r.secrets) > 16 {
		r.secrets = r.secrets[len(r.secrets)-16:]
	}
	r.mu.Unlock()
}

// Scrub returns the line with secrets replaced.
func (r *Redactor) Scrub(line string) string {
	if !r.enabled {
		return line
	}
	r.mu.RLock()
	for _, s := range r.secrets {
		line = strings.ReplaceAll(line, s, "[REDACTED]")
	}
	r.mu.RUnlock()
	return bearerRe.ReplaceAllString(line, "Bearer [REDACTED]")
}

// Pipe copies lines from the child's stderr into the logger, scrubbed.
func (r *Redactor) Pipe(src io.Reader, log *slog.Logger) {
	if log == nil {
		log = slog.Default()
	}
	sc := bufio.NewScanner(src)
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	for sc.Scan() {
		log.Info("child", "stderr", r.Scrub(sc.Text()))
	}
}
