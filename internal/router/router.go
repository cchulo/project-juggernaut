package router

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/cchulo/project-juggernaut/internal/config"
	"github.com/cchulo/project-juggernaut/internal/core"
	"github.com/cchulo/project-juggernaut/internal/core/contracts"
)

// CallHook receives every tool call for audit and metrics.
type CallHook func(ev CallEvent)

// CallEvent describes one routed tool call.
type CallEvent struct {
	Subject    string
	ServerType string
	PodName    string
	SessionID  string
	Tool       string
	Upstream   string
	Arguments  json.RawMessage
	Duration   time.Duration
	IsError    bool
	Err        error
	Lazy       bool
}

// Router serves the aggregated endpoint.
type Router struct {
	Store  *config.Store
	Policy contracts.AccessPolicy
	Broker contracts.TokenBroker
	Pods   contracts.SessionManager
	Table  contracts.RoutingTable
	Log    *slog.Logger
	OnCall CallHook

	cache *toolCache
	mu    sync.Mutex
	conns map[string]*conns // gateway session id → upstream sessions
}

// New builds a router.
func New(store *config.Store, policy contracts.AccessPolicy, br contracts.TokenBroker, pods contracts.SessionManager, table contracts.RoutingTable, log *slog.Logger) *Router {
	return &Router{Store: store, Policy: policy, Broker: br, Pods: pods, Table: table, Log: log,
		cache: newToolCache(10 * time.Minute), conns: map[string]*conns{}}
}

// Handler returns the Streamable HTTP handler for /mcp. It must sit behind the auth middleware.
func (rt *Router) Handler() http.Handler {
	return mcp.NewStreamableHTTPHandler(func(r *http.Request) *mcp.Server {
		return rt.serverFor(r)
	}, &mcp.StreamableHTTPOptions{
		Logger:                     rt.Log,
		DisableLocalhostProtection: true,
		MaxRequestBodyBytes:        rt.Store.Get().Config.Gateway.MaxBodyBytes,
		SessionTimeout:             rt.Store.Get().Config.Gateway.MaxSessionAge.Or(12 * time.Hour),
	})
}

// serverFor builds the per-session server. Tools are registered once the
// client has initialized, because lazy vs eager depends on clientInfo.name.
func (rt *Router) serverFor(r *http.Request) *mcp.Server {
	p := core.PrincipalFrom(r.Context())
	cfg := rt.Store.Get()
	var srv *mcp.Server
	srv = mcp.NewServer(&mcp.Implementation{Name: "juggernaut", Version: "0.1"}, &mcp.ServerOptions{
		Instructions: "Tools are namespaced <adapter>" + cfg.Config.Gateway.Tools.NamespaceSeparator + "<tool>. " +
			"If only search_tools/describe_tool/execute are listed, search first, then execute by full name.",
		Logger: rt.Log,
		InitializedHandler: func(ctx context.Context, req *mcp.InitializedRequest) {
			if p == nil {
				return
			}
			clientName := ""
			if ip := req.Session.InitializeParams(); ip != nil && ip.ClientInfo != nil {
				clientName = ip.ClientInfo.Name
			}
			grants := rt.Policy.Grants(p, clientName)
			c := newConns()
			rt.mu.Lock()
			rt.conns[req.Session.ID()] = c
			rt.mu.Unlock()
			go func() {
				_ = req.Session.Wait()
				rt.mu.Lock()
				delete(rt.conns, req.Session.ID())
				rt.mu.Unlock()
				c.closeAll()
			}()
			rt.addWhoami(srv, p, grants)
			if grants.LazyTools {
				rt.addMetaTools(srv, p, grants, c)
			} else {
				rt.addEagerTools(context.WithoutCancel(ctx), srv, p, grants, c)
			}
		},
	})
	return srv
}

// toolsFor lists the (visible, namespaced) tools of one server type, from cache when possible.
func (rt *Router) toolsFor(ctx context.Context, p *core.Principal, grants core.Grants, st *config.Server, c *conns) ([]*mcp.Tool, map[string]string, error) {
	l := rt.Store.Get()
	sep := l.Config.Gateway.Tools.NamespaceSeparator
	raw, ok := rt.cache.get(st.Name, l.Hash)
	if !ok {
		up, err := rt.upstreamFor(ctx, p, st, c)
		if err != nil {
			return nil, nil, err
		}
		res, err := up.cs.ListTools(ctx, &mcp.ListToolsParams{})
		if err != nil {
			return nil, nil, err
		}
		raw = res.Tools
		rt.cache.put(st.Name, l.Hash, raw)
	}
	var out []*mcp.Tool
	back := map[string]string{} // exposed name → upstream name
	for _, t := range raw {
		rule := rt.Policy.ToolRule(grants, st, t.Name)
		if !rule.Visible {
			continue
		}
		cp := *t
		cp.Name = st.Name + sep + rule.Name
		if cp.Description != "" {
			cp.Description = "[" + st.Name + "] " + cp.Description
		}
		out = append(out, &cp)
		back[cp.Name] = t.Name
	}
	return out, back, nil
}

// upstreamFor returns (creating if needed) the client session to the caller's pod for st.
func (rt *Router) upstreamFor(ctx context.Context, p *core.Principal, st *config.Server, c *conns) (*upstream, error) {
	if u := c.get(st.Name); u != nil {
		return u, nil
	}
	pod, srv, err := rt.Pods.EnsurePod(ctx, p, st.Name)
	if err != nil {
		return nil, err
	}
	u, err := connect(ctx, p, pod, srv, rt.Broker)
	if err != nil {
		return nil, err
	}
	c.put(u)
	return u, nil
}

func (rt *Router) addEagerTools(ctx context.Context, srv *mcp.Server, p *core.Principal, grants core.Grants, c *conns) {
	cfg := rt.Store.Get().Config
	for _, name := range grants.ServerTypes {
		st := cfg.Server(name)
		if st == nil {
			continue
		}
		tools, back, err := rt.toolsFor(ctx, p, grants, st, c)
		if err != nil {
			rt.Log.Warn("eager tool load failed", "serverType", name, "user", p.Username, "err", err)
			continue
		}
		for _, t := range tools {
			t := t
			upstreamName := back[t.Name]
			srv.AddTool(t, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				return rt.call(ctx, p, grants, st, c, t.Name, upstreamName, req.Params.Arguments, false, req.Session.ID())
			})
		}
	}
}

// call forwards a tool call to the pod and emits the audit event.
func (rt *Router) call(ctx context.Context, p *core.Principal, grants core.Grants, st *config.Server, c *conns, exposed, upstreamName string, args json.RawMessage, lazy bool, sessionID string) (*mcp.CallToolResult, error) {
	start := time.Now()
	up, err := rt.upstreamFor(ctx, p, st, c)
	var res *mcp.CallToolResult
	if err == nil {
		_, _ = rt.Table.InFlight(ctx, up.pod.Name, +1)
		_ = rt.Table.Touch(ctx, up.pod.Name, time.Now())
		res, err = up.cs.CallTool(ctx, &mcp.CallToolParams{Name: upstreamName, Arguments: args})
		_, _ = rt.Table.InFlight(ctx, up.pod.Name, -1)
	}
	if rt.OnCall != nil {
		ev := CallEvent{Subject: p.Subject, ServerType: st.Name, SessionID: sessionID, Tool: exposed, Upstream: upstreamName,
			Arguments: args, Duration: time.Since(start), Err: err, Lazy: lazy}
		if up != nil {
			ev.PodName = up.pod.Name
		}
		if res != nil {
			ev.IsError = res.IsError
		}
		rt.OnCall(ev)
	}
	_ = grants
	return res, err
}

// addWhoami exposes what the gateway made of the token, so an agent (and the
// person debugging it) can see subject, kind, groups, scopes and grants.
func (rt *Router) addWhoami(srv *mcp.Server, p *core.Principal, grants core.Grants) {
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "whoami",
		Description: "Who the gateway thinks you are: subject, kind, groups, token scopes, the adapters (server types) you may use, and whether tools are loaded lazily.",
	}, func(context.Context, *mcp.CallToolRequest, struct{}) (*mcp.CallToolResult, any, error) {
		view := map[string]any{
			"subject": p.Subject, "username": p.Username, "kind": p.Kind, "issuer": p.Issuer,
			"groups": p.Groups, "tokenScopes": p.Scopes,
			"adapters": grants.ServerTypes, "admin": grants.Admin, "podsPerUser": grants.PodsPerUser, "lazyTools": grants.LazyTools,
		}
		b, _ := json.MarshalIndent(view, "", "  ")
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(b)}}}, nil, nil
	})
}

// --- lazy meta-tools -------------------------------------------------------

type searchArgs struct {
	Query string `json:"query" jsonschema:"free-text query matched against tool names and descriptions"`
	Limit int    `json:"limit,omitempty" jsonschema:"maximum results (default 20)"`
}

type describeArgs struct {
	Name string `json:"name" jsonschema:"full namespaced tool name from search_tools"`
}

type executeArgs struct {
	Name      string          `json:"name" jsonschema:"full namespaced tool name"`
	Arguments json.RawMessage `json:"arguments,omitempty" jsonschema:"arguments object for the tool"`
}

func (rt *Router) addMetaTools(srv *mcp.Server, p *core.Principal, grants core.Grants, c *conns) {
	cfg := rt.Store.Get().Config
	sep := cfg.Gateway.Tools.NamespaceSeparator

	// allTools enumerates the caller's visible tools across granted types (spawning pods as needed).
	allTools := func(ctx context.Context) ([]*mcp.Tool, map[string]string, map[string]*config.Server) {
		var out []*mcp.Tool
		back := map[string]string{}
		owner := map[string]*config.Server{}
		for _, name := range grants.ServerTypes {
			st := cfg.Server(name)
			if st == nil {
				continue
			}
			tools, b, err := rt.toolsFor(ctx, p, grants, st, c)
			if err != nil {
				rt.Log.Warn("lazy tool enumeration failed", "serverType", name, "err", err)
				continue
			}
			out = append(out, tools...)
			for k, v := range b {
				back[k] = v
				owner[k] = st
			}
		}
		return out, back, owner
	}

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "search_tools",
		Description: "Search the tools available to you across all adapters. Returns namespaced names; call describe_tool for schemas and execute to run one.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in searchArgs) (*mcp.CallToolResult, any, error) {
		tools, _, _ := allTools(ctx)
		q := strings.ToLower(in.Query)
		limit := in.Limit
		if limit <= 0 {
			limit = 20
		}
		type hit struct {
			Name, Adapter, Description string
		}
		var hits []hit
		for _, t := range tools {
			if q == "" || strings.Contains(strings.ToLower(t.Name), q) || strings.Contains(strings.ToLower(t.Description), q) {
				adapter, _, _ := strings.Cut(t.Name, sep)
				hits = append(hits, hit{t.Name, adapter, t.Description})
			}
		}
		sort.Slice(hits, func(i, j int) bool { return hits[i].Name < hits[j].Name })
		if len(hits) > limit {
			hits = hits[:limit]
		}
		b, _ := json.MarshalIndent(hits, "", "  ")
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(b)}}}, nil, nil
	})

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "describe_tool",
		Description: "Return the full definition (description and input schema) of one tool by its namespaced name.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in describeArgs) (*mcp.CallToolResult, any, error) {
		tools, _, _ := allTools(ctx)
		for _, t := range tools {
			if t.Name == in.Name {
				b, _ := json.MarshalIndent(t, "", "  ")
				return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(b)}}}, nil, nil
			}
		}
		return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: "unknown tool " + in.Name}}}, nil, nil
	})

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "execute",
		Description: "Execute a tool by its namespaced name with a JSON arguments object.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, in executeArgs) (*mcp.CallToolResult, any, error) {
		_, back, owner := allTools(ctx)
		st, ok := owner[in.Name]
		if !ok {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("unknown or not permitted tool %q", in.Name)}}}, nil, nil
		}
		res, err := rt.call(ctx, p, grants, st, c, in.Name, back[in.Name], in.Arguments, true, req.Session.ID())
		return res, nil, err
	})
}
