// Package mcpproxy forwards Streamable HTTP traffic from the gateway to a session
// pod's wrapper. It rewrites the gateway-issued Mcp-Session-Id to the upstream
// session id, injects the per-pod shared secret and the per-user downstream
// token, streams SSE bodies through untouched, and never lets the client's own
// bearer token reach the pod.
package mcpproxy

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Headers used between the gateway and the wrapper.
const (
	HeaderPodToken   = "X-Juggernaut-Pod-Token"
	HeaderSubject    = "X-Juggernaut-Subject"
	HeaderSessionID  = "Mcp-Session-Id"
	HeaderProtocolV  = "MCP-Protocol-Version"
	HeaderServerType = "X-Juggernaut-Server-Type"
)

// Upstream describes where and how to forward one request.
type Upstream struct {
	Endpoint          string // http://ip:port
	Path              string // usually /mcp
	PodToken          string
	UpstreamSessionID string
	Subject           string
	ServerType        string
	// UserToken is injected as `<TokenHeader>: <TokenScheme> <UserToken>` when set.
	UserToken   string
	TokenHeader string
	TokenScheme string
}

// Result is what the proxy learned from the upstream response.
type Result struct {
	Status            int
	UpstreamSessionID string
}

// Proxy forwards Streamable HTTP requests.
type Proxy struct {
	Client *http.Client
	// MaxBody bounds the request body copied upstream.
	MaxBody int64
}

// New builds a proxy with sane transport settings for long-lived SSE streams.
func New(maxBody int64) *Proxy {
	tr := &http.Transport{
		MaxIdleConnsPerHost:   16,
		IdleConnTimeout:       90 * time.Second,
		ResponseHeaderTimeout: 0, // SSE may take a while to send headers on long calls
		DisableCompression:    true,
	}
	return &Proxy{Client: &http.Client{Transport: tr}, MaxBody: maxBody}
}

// Forward sends r to the upstream and streams the response back to w.
func (p *Proxy) Forward(ctx context.Context, w http.ResponseWriter, r *http.Request, up Upstream) (*Result, error) {
	target, err := url.Parse(strings.TrimRight(up.Endpoint, "/") + up.Path)
	if err != nil {
		return nil, err
	}
	var body io.Reader = r.Body
	if r.Body != nil && p.MaxBody > 0 {
		body = http.MaxBytesReader(w, r.Body, p.MaxBody)
	}
	req, err := http.NewRequestWithContext(ctx, r.Method, target.String(), body)
	if err != nil {
		return nil, err
	}
	copyHeaders(req.Header, r.Header)
	// The client's bearer token must not leave the gateway.
	req.Header.Del("Authorization")
	req.Header.Del("Cookie")
	req.Header.Set(HeaderPodToken, up.PodToken)
	req.Header.Set(HeaderSubject, up.Subject)
	req.Header.Set(HeaderServerType, up.ServerType)
	if up.UpstreamSessionID != "" {
		req.Header.Set(HeaderSessionID, up.UpstreamSessionID)
	} else {
		req.Header.Del(HeaderSessionID)
	}
	if up.UserToken != "" {
		h := up.TokenHeader
		if h == "" {
			h = "Authorization"
		}
		val := up.UserToken
		if up.TokenScheme != "" {
			val = up.TokenScheme + " " + val
		}
		req.Header.Set(h, val)
	}
	resp, err := p.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	res := &Result{Status: resp.StatusCode, UpstreamSessionID: resp.Header.Get(HeaderSessionID)}
	copyHeaders(w.Header(), resp.Header)
	// Never expose the upstream's session id or pod headers to the client; the
	// caller sets the gateway-issued id.
	w.Header().Del(HeaderSessionID)
	w.Header().Del(HeaderPodToken)
	w.WriteHeader(resp.StatusCode)

	if strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream") {
		flushCopy(w, resp.Body)
		return res, nil
	}
	_, _ = io.Copy(w, resp.Body)
	return res, nil
}

func copyHeaders(dst, src http.Header) {
	for k, vv := range src {
		switch strings.ToLower(k) {
		case "connection", "keep-alive", "transfer-encoding", "upgrade", "content-length", "host":
			continue
		}
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

// flushCopy copies an event stream and flushes after every chunk so clients see
// events as they happen.
func flushCopy(w http.ResponseWriter, r io.Reader) {
	f, _ := w.(http.Flusher)
	buf := make([]byte, 32*1024)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			if _, werr := w.Write(buf[:n]); werr != nil {
				return
			}
			if f != nil {
				f.Flush()
			}
		}
		if err != nil {
			return
		}
	}
}
