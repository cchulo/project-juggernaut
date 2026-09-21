package redis

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	goredis "github.com/redis/go-redis/v9"

	"github.com/cchulo/project-juggernaut/internal/core"
	"github.com/cchulo/project-juggernaut/internal/core/contracts"
	"github.com/cchulo/project-juggernaut/internal/core/contracts/contracttest"
)

func newTable(t *testing.T, withKEK bool) (*Redis, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	c := goredis.NewClient(&goredis.Options{Addr: mr.Addr()})
	var sealer core.Sealer
	var mac []byte
	if withKEK {
		kek := []byte("0123456789abcdef0123456789abcdef")
		sealer, _ = core.NewAESGCM(kek)
		mac = core.DeriveMACKey(kek, "routing")
	}
	r := NewRedis(c, "jg:", time.Hour, sealer)
	r.macKey = mac
	return r, mr
}

func TestContract(t *testing.T) {
	r, _ := newTable(t, true)
	contracttest.RoutingTable(t, r)
}

func TestContractWithoutKEK(t *testing.T) {
	r, _ := newTable(t, false)
	contracttest.RoutingTable(t, r)
}

func TestPodTokenIsSealedAtRest(t *testing.T) {
	r, mr := newTable(t, true)
	key := core.PodKey{Subject: "alice", ServerType: "jira"}
	_ = r.PutPod(context.Background(), &contracts.Pod{Key: key, Name: key.Name(), Phase: contracts.PhaseReady, PodToken: "plain-pod-token"})
	raw, _ := mr.Get("jg:podtok:" + key.Name())
	if raw == "" || raw == "plain-pod-token" {
		t.Fatalf("pod token must be sealed in redis, got %q", raw)
	}
	p, err := r.GetPod(context.Background(), key)
	if err != nil || p.PodToken != "plain-pod-token" {
		t.Fatalf("unseal: %+v %v", p, err)
	}
}

func TestTamperedRecordsAreNotFound(t *testing.T) {
	r, mr := newTable(t, true)
	key := core.PodKey{Subject: "alice", ServerType: "jira"}
	_ = r.PutPod(context.Background(), &contracts.Pod{Key: key, Name: key.Name(), Phase: contracts.PhaseReady, Endpoint: "http://10.0.0.5:9000"})
	// Redirect alice's pod to another endpoint by editing the store directly.
	k := "jg:pod:jira:" + core.UserHash("alice")
	raw, _ := mr.Get(k)
	_ = mr.Set(k, replaceOnce(raw, "10.0.0.5", "10.0.0.6"))
	r.mem = NewMemory() // bypass the cache tier
	if _, err := r.GetPod(context.Background(), key); !errors.Is(err, contracts.ErrNotFound) {
		t.Fatalf("tampered pod record must read as not found, got %v", err)
	}
	s := &contracts.McpSession{ID: core.NewMcpSessionID(), Subject: "alice", PodName: key.Name(), CreatedAt: time.Now()}
	_ = r.PutSession(context.Background(), s)
	sraw, _ := mr.Get("jg:sess:" + s.ID)
	_ = mr.Set("jg:sess:"+s.ID, replaceOnce(sraw, key.Name(), "jira-deadbeef"))
	if _, err := r.GetSession(context.Background(), s.ID); !errors.Is(err, contracts.ErrNotFound) {
		t.Fatalf("tampered session record must read as not found, got %v", err)
	}
}

func replaceOnce(s, old, new string) string {
	for i := 0; i+len(old) <= len(s); i++ {
		if s[i:i+len(old)] == old {
			return s[:i] + new + s[i+len(old):]
		}
	}
	return s
}
