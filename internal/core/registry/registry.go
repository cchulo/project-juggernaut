// Package registry maps the `type:` names in juggernaut.yaml to adapter
// constructors, one registry per contract kind.
//
// Go cannot import a package by a string at runtime, so instead of cerebro's
// "cerebro.adapters.<kind>.<type>:Adapter" lookup each adapter package
// registers itself in init() (the database/sql driver pattern) and
// internal/adapters/all blank-imports every in-tree adapter. An out-of-tree
// adapter is a Go package that calls Register from its own init and is
// imported by a custom main; no registry file is edited either way.
package registry

import (
	"fmt"
	"sort"
	"sync"

	"github.com/cchulo/project-juggernaut/internal/core"
	"github.com/cchulo/project-juggernaut/internal/core/contracts"
)

// Factory builds one adapter from its context (options are in ctx.Options).
type Factory[T any] func(ctx *core.Context) (T, error)

// Registry holds the factories of one kind.
type Registry[T any] struct {
	kind string
	mu   sync.RWMutex
	fac  map[string]Factory[T]
}

// New creates a registry for a kind.
func New[T any](kind string) *Registry[T] {
	return &Registry[T]{kind: kind, fac: map[string]Factory[T]{}}
}

// Register adds a type. Registering the same name twice is a programming error.
func (r *Registry[T]) Register(typ string, f Factory[T]) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, dup := r.fac[typ]; dup {
		panic(fmt.Sprintf("registry: %s adapter %q registered twice", r.kind, typ))
	}
	r.fac[typ] = f
}

// Build constructs the adapter named typ.
func (r *Registry[T]) Build(typ string, ctx *core.Context) (T, error) {
	r.mu.RLock()
	f, ok := r.fac[typ]
	r.mu.RUnlock()
	var zero T
	if !ok {
		return zero, &LookupError{Kind: r.kind, Type: typ, Known: r.Types()}
	}
	return f(ctx)
}

// Types lists the registered type names.
func (r *Registry[T]) Types() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, 0, len(r.fac))
	for k := range r.fac {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// LookupError reports an unknown adapter type.
type LookupError struct {
	Kind  string
	Type  string
	Known []string
}

func (e *LookupError) Error() string {
	return fmt.Sprintf("no %s adapter of type %q (known: %v)", e.Kind, e.Type, e.Known)
}

// One registry per contract kind.
var (
	Identity  = New[contracts.IdentityProvider]("identity")
	Policy    = New[contracts.AccessPolicy]("policy")
	Broker    = New[contracts.TokenBroker]("broker")
	Provision = New[contracts.Provisioner]("provision")
	Routing   = New[contracts.RoutingTable]("routing")
	Egress    = New[contracts.EgressEnforcer]("egress")
	Directory = New[contracts.Directory]("directory")
	Audit     = New[contracts.AuditSink]("audit")
)

// WithOptions returns a copy of ctx carrying the adapter's own options map.
func WithOptions(ctx *core.Context, opts map[string]any) *core.Context {
	cp := *ctx
	cp.Options = core.Options(opts)
	return &cp
}
