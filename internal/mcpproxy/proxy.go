// Package mcpproxy forwards Streamable HTTP traffic from the gateway to a session
// pod's wrapper. It rewrites the gateway-issued Mcp-Session-Id to the upstream
// session id, injects the per-pod shared secret and the per-user downstream
// token, streams SSE bodies through untouched, and never lets the client's own
// bearer token reach the pod.
package mcpproxy

import (
	"context"
	"encoding/json"
	"fmt"
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
	// NewSessionID is the gateway-issued id handed to the client if, and only
	// if, the upstream starts a session on this request (returns its own
	// Mcp-Session-Id). A stateless probe such as server/discover gets none.
	NewSessionID string
	Subject      string
	ServerType   string
	// UserToken is injected as `<TokenHeader>: <TokenScheme> <UserToken>` when set.
	UserToken   string
	TokenHeader string
	TokenScheme string
	// Extra headers to add (user secrets); nothing else from the client is forwarded.
	Extra http.Header
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
	// TLS is set for podAuth mtls.
	TLS *PodTLS
}

// New builds a proxy with sane transport settings for long-lived SSE streams.
// With tls, every connection is mutual TLS and the pod's SPIFFE identity is verified.
func New(maxBody int64, tls *PodTLS) *Proxy {
	tr := &http.Transport{
		MaxIdleConnsPerHost:   16,
		IdleConnTimeout:       90 * time.Second,
		ResponseHeaderTimeout: 0, // SSE may take a while to send headers on long calls
		DisableCompression:    true,
	}
	if tls != nil {
		tr.TLSClientConfig = tls.ClientConfig()
	}
	return &Proxy{Client: &http.Client{Transport: tr}, MaxBody: maxBody, TLS: tls}
}

// SessionKey asks the wrapper for its ephemeral public key (tier-B sealing).
func (p *Proxy) SessionKey(ctx context.Context, pod PodRef) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(pod.GetEndpoint(), "/")+"/session-key", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set(HeaderPodToken, pod.GetPodToken())
	resp, err := p.Client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("status %d", resp.StatusCode)
	}
	var body struct {
		PublicKey string `json:"publicKey"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return "", err
	}
	return body.PublicKey, nil
}

// PodRef is the subset of a routing-table pod the proxy needs.
type PodRef interface {
	GetEndpoint() string
	GetPodToken() string
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
	// The client's bearer token must not leave the gateway, and no client-supplied
	// X-Juggernaut-* header reaches a pod except through Upstream.Extra.
	req.Header.Del("Authorization")
	req.Header.Del("Cookie")
	for k := range req.Header {
		if strings.HasPrefix(strings.ToLower(k), "x-juggernaut-") {
			req.Header.Del(k)
		}
	}
	req.Header.Set(HeaderPodToken, up.PodToken)
	req.Header.Set(HeaderSubject, up.Subject)
	req.Header.Set(HeaderServerType, up.ServerType)
	if up.UpstreamSessionID != "" {
		req.Header.Set(HeaderSessionID, up.UpstreamSessionID)
	} else {
		req.Header.Del(HeaderSessionID)
	}
	for k, vv := range up.Extra {
		req.Header.Del(k)
		for _, v := range vv {
			req.Header.Add(k, v)
		}
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
	// Never expose the upstream's session id or pod headers to the client; the
	// client sees the gateway-issued id, and only when a session was started.
	copyHeaders(w.Header(), resp.Header)
	w.Header().Del(HeaderSessionID)
	w.Header().Del(HeaderPodToken)
	if res.UpstreamSessionID != "" && up.NewSessionID != "" {
		w.Header().Set(HeaderSessionID, up.NewSessionID)
	}
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
