// Package router implements the aggregated /mcp endpoint: one MCP server per
// client session that exposes every tool of every server type the caller is
// granted, namespaced <adapter>__<tool>, or, in lazy mode, the three meta-tools
// search_tools / describe_tool / execute.
package router

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/cchulo/project-juggernaut/internal/auth"
	"github.com/cchulo/project-juggernaut/internal/broker"
	"github.com/cchulo/project-juggernaut/internal/config"
	"github.com/cchulo/project-juggernaut/internal/mcpproxy"
	"github.com/cchulo/project-juggernaut/internal/session"
)

// podTransport adds the per-pod secret and the per-user downstream token to
// every request the router makes to a session pod. The token is fetched from
// the broker per request so rotation needs no reconnect.
type podTransport struct {
	base   http.RoundTripper
	pod    *session.Pod
	srv    *config.Server
	p      *auth.Principal
	broker broker.Broker
}

func (t *podTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set(mcpproxy.HeaderPodToken, t.pod.PodToken)
	r.Header.Set(mcpproxy.HeaderSubject, t.p.Subject)
	r.Header.Set(mcpproxy.HeaderServerType, t.srv.Name)
	r.Header.Del("Authorization")
	switch t.srv.Token.Mode {
	case config.TokenNone:
	case config.TokenStatic:
		v, err := t.srv.Token.StaticRef.Resolve()
		if err != nil {
			return nil, err
		}
		r.Header.Set(t.srv.Token.Header, t.srv.Token.Scheme+" "+v)
	default:
		tok, err := t.broker.TokenFor(r.Context(), t.p, t.srv, 60*time.Second)
		if err != nil {
			return nil, err
		}
		if tok != nil {
			r.Header.Set("Authorization", "Bearer "+tok.Value)
		}
	}
	return t.base.RoundTrip(r)
}

// upstream is one MCP client session from the router to a session pod.
type upstream struct {
	serverType string
	pod        *session.Pod
	cs         *mcp.ClientSession
}

// conns holds the upstream sessions of one gateway MCP session.
type conns struct {
	mu   sync.Mutex
	byST map[string]*upstream
}

func newConns() *conns { return &conns{byST: map[string]*upstream{}} }

func (c *conns) get(st string) *upstream {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.byST[st]
}

func (c *conns) put(u *upstream) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.byST[u.serverType] = u
}

func (c *conns) closeAll() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for k, u := range c.byST {
		_ = u.cs.Close()
		delete(c.byST, k)
	}
}

// connect opens an MCP client session to the pod.
func connect(ctx context.Context, p *auth.Principal, pod *session.Pod, srv *config.Server, br broker.Broker) (*upstream, error) {
	hc := &http.Client{Transport: &podTransport{base: http.DefaultTransport, pod: pod, srv: srv, p: p, broker: br}}
	client := mcp.NewClient(&mcp.Implementation{Name: "juggernaut-router", Version: "0.1"}, nil)
	cs, err := client.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: pod.Endpoint + "/mcp", HTTPClient: hc}, nil)
	if err != nil {
		return nil, fmt.Errorf("connect to %s: %w", pod.Name, err)
	}
	return &upstream{serverType: srv.Name, pod: pod, cs: cs}, nil
}
