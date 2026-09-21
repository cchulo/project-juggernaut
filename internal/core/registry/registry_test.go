package registry

import (
	"errors"
	"testing"

	"github.com/cchulo/project-juggernaut/internal/core"
)

type thing interface{ Name() string }
type impl struct{ n string }

func (i impl) Name() string { return i.n }

func TestBuildAndLookup(t *testing.T) {
	r := New[thing]("thing")
	r.Register("a", func(ctx *core.Context) (thing, error) { return impl{ctx.Options.String("n", "a")}, nil })
	got, err := r.Build("a", WithOptions(&core.Context{}, map[string]any{"n": "x"}))
	if err != nil || got.Name() != "x" {
		t.Fatalf("build: %v %v", got, err)
	}
	_, err = r.Build("missing", &core.Context{})
	var le *LookupError
	if !errors.As(err, &le) || le.Kind != "thing" {
		t.Fatalf("expected LookupError, got %v", err)
	}
}

func TestDuplicatePanics(t *testing.T) {
	r := New[thing]("thing")
	f := func(*core.Context) (thing, error) { return impl{}, nil }
	r.Register("a", f)
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic on duplicate registration")
		}
	}()
	r.Register("a", f)
}
