// Package redis is the durable routing table shared by every gateway replica.
//
// Options: key_prefix (default gateway.redis.keyPrefix), seal_pod_tokens
// (default true: pod tokens are sealed with the KEK from $JUGGERNAUT_KEK).
package redis

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/cchulo/project-juggernaut/internal/adapters/routing/memory"
	"github.com/cchulo/project-juggernaut/internal/core"
	"github.com/cchulo/project-juggernaut/internal/core/contracts"
	"github.com/cchulo/project-juggernaut/internal/core/registry"
)

// Type is the registry name.
const Type = "redis"

func init() { registry.Routing.Register(Type, New) }

type (
	PodKey     = core.PodKey
	Pod        = contracts.Pod
	McpSession = contracts.McpSession
	Phase      = contracts.Phase
	Cipher     = core.Sealer
	Memory     = memory.Memory
)

const (
	PhaseGone        = contracts.PhaseGone
	PhaseTerminating = contracts.PhaseTerminating
	PhaseReady       = contracts.PhaseReady
)

var (
	ErrNotFound = contracts.ErrNotFound
	UserHash    = core.UserHash
	NewMemory   = memory.NewMemory
)

// New connects to gateway.redis and seals pod tokens with the KEK when present.
func New(ctx *core.Context) (contracts.RoutingTable, error) {
	cfg := ctx.Cfg()
	rc := cfg.Gateway.Redis
	if rc == nil {
		return nil, fmt.Errorf("routing adapter redis requires gateway.redis")
	}
	pw, err := ctx.Secrets.Get(rc.PasswordRef)
	if err != nil {
		return nil, err
	}
	c := redis.NewClient(&redis.Options{Addr: rc.Address, Password: pw, DB: rc.DB})
	if err := c.Ping(context.Background()).Err(); err != nil {
		return nil, fmt.Errorf("redis %s: %w", rc.Address, err)
	}
	var sealer core.Sealer
	var macKey []byte
	if ctx.Options.Bool("seal_pod_tokens", true) {
		if kek, ok := ctx.Secrets.Env("JUGGERNAUT_KEK"); ok && kek != "" {
			key, err := base64.StdEncoding.DecodeString(kek)
			if err != nil || len(key) != 32 {
				return nil, fmt.Errorf("JUGGERNAUT_KEK must be base64 of 32 bytes")
			}
			if sealer, err = core.NewAESGCM(key); err != nil {
				return nil, err
			}
			macKey = core.DeriveMACKey(key, "routing")
		} else {
			ctx.Log.Warn("JUGGERNAUT_KEK not set: pod tokens are stored in Redis unencrypted")
		}
	}
	prefix := ctx.Options.String("key_prefix", rc.KeyPrefix)
	r := NewRedis(c, prefix, cfg.Gateway.MaxSessionAge.Or(12*time.Hour), sealer)
	r.macKey = macKey
	if macKey == nil {
		ctx.Log.Warn("routing records are not authenticated (no JUGGERNAUT_KEK)")
	}
	return r, nil
}

// Redis is the durable routing table shared by every gateway replica.
// Keys (docs/DESIGN.md §4):
//
//	<p>sess:<mcpSessionId>          JSON McpSession        TTL maxSessionAge
//	<p>pod:<serverType>:<userHash>  JSON Pod (no token)    no TTL
//	<p>podtok:<podName>             encrypted pod token    no TTL
//	<p>active:<podName>             unix seconds           no TTL
//	<p>inflight:<podName>           integer                TTL 1h, refreshed
//	<p>pods:by-user:<subject>       SET of pod keys
type Redis struct {
	c      *redis.Client
	prefix string
	maxAge time.Duration
	// Cipher protects pod tokens at rest; nil stores them as-is (dev only).
	Cipher Cipher
	// macKey authenticates routing records so a store compromise cannot point
	// a user at another pod. Derived from the KEK; nil disables (dev only).
	macKey []byte
	// mem fronts Redis as an LRU-ish cache for pods.
	mem *Memory
}

// NewRedis builds a Redis-backed table.
func NewRedis(c *redis.Client, prefix string, maxAge time.Duration, cipher Cipher) *Redis {
	return &Redis{c: c, prefix: prefix, maxAge: maxAge, Cipher: cipher, mem: NewMemory()}
}

func (r *Redis) k(parts ...string) string {
	out := r.prefix
	for i, p := range parts {
		if i > 0 {
			out += ":"
		}
		out += p
	}
	return out
}

type podRecord struct {
	Subject    string    `json:"subject"`
	ServerType string    `json:"serverType"`
	Name       string    `json:"name"`
	Endpoint   string    `json:"endpoint"`
	Phase      Phase     `json:"phase"`
	CreatedAt  time.Time `json:"createdAt"`
	ConfigHash string    `json:"configHash"`
	MAC        []byte    `json:"mac,omitempty"`
}

func (r *Redis) podMAC(rec *podRecord) []byte {
	if r.macKey == nil {
		return nil
	}
	return core.MAC(r.macKey, "pod", rec.Subject, rec.ServerType, rec.Name, rec.Endpoint, rec.ConfigHash)
}

type sessionRecord struct {
	McpSession
	MAC []byte `json:"mac,omitempty"`
}

func (r *Redis) sessionMAC(s *McpSession) []byte {
	if r.macKey == nil {
		return nil
	}
	return core.MAC(r.macKey, "sess", s.ID, s.Subject, s.ServerType, s.PodName, s.UpstreamSessionID)
}

func (r *Redis) GetPod(ctx context.Context, key PodKey) (*Pod, error) {
	if p, err := r.mem.GetPod(ctx, key); err == nil && p.Phase == PhaseReady {
		return p, nil
	}
	raw, err := r.c.Get(ctx, r.k("pod", key.ServerType, UserHash(key.Subject))).Result()
	if errors.Is(err, redis.Nil) {
		_ = r.mem.DeletePod(ctx, key)
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	var rec podRecord
	if err := json.Unmarshal([]byte(raw), &rec); err != nil {
		return nil, err
	}
	if !core.MACEqual(rec.MAC, r.podMAC(&rec)) {
		return nil, fmt.Errorf("%w: routing record for %s failed authentication", ErrNotFound, rec.Name)
	}
	p := &Pod{Key: key, Name: rec.Name, Endpoint: rec.Endpoint, Phase: rec.Phase, CreatedAt: rec.CreatedAt, ConfigHash: rec.ConfigHash}
	tok, err := r.c.Get(ctx, r.k("podtok", rec.Name)).Result()
	if err == nil {
		if r.Cipher != nil {
			tok, err = r.Cipher.Open(tok)
			if err != nil {
				return nil, fmt.Errorf("pod token: %w", err)
			}
		}
		p.PodToken = tok
	}
	_ = r.mem.PutPod(ctx, p)
	return p, nil
}

func (r *Redis) PutPod(ctx context.Context, p *Pod) error {
	rec := podRecord{Subject: p.Key.Subject, ServerType: p.Key.ServerType, Name: p.Name, Endpoint: p.Endpoint,
		Phase: p.Phase, CreatedAt: p.CreatedAt, ConfigHash: p.ConfigHash}
	rec.MAC = r.podMAC(&rec)
	b, _ := json.Marshal(rec)
	pipe := r.c.TxPipeline()
	pipe.Set(ctx, r.k("pod", p.Key.ServerType, UserHash(p.Key.Subject)), b, 0)
	pipe.SAdd(ctx, r.k("pods:by-user", p.Key.Subject), p.Key.ServerType)
	pipe.SAdd(ctx, r.k("pods:all"), p.Key.ServerType+"|"+p.Key.Subject)
	if p.PodToken != "" {
		tok := p.PodToken
		if r.Cipher != nil {
			var err error
			if tok, err = r.Cipher.Seal(tok); err != nil {
				return err
			}
		}
		pipe.Set(ctx, r.k("podtok", p.Name), tok, 0)
	}
	if _, err := pipe.Exec(ctx); err != nil {
		return err
	}
	return r.mem.PutPod(ctx, p)
}

func (r *Redis) DeletePod(ctx context.Context, key PodKey) error {
	name := key.Name()
	pipe := r.c.TxPipeline()
	pipe.Del(ctx, r.k("pod", key.ServerType, UserHash(key.Subject)), r.k("podtok", name), r.k("active", name), r.k("inflight", name))
	pipe.SRem(ctx, r.k("pods:by-user", key.Subject), key.ServerType)
	pipe.SRem(ctx, r.k("pods:all"), key.ServerType+"|"+key.Subject)
	_, err := pipe.Exec(ctx)
	_ = r.mem.DeletePod(ctx, key)
	return err
}

func (r *Redis) ListPods(ctx context.Context, subject string) ([]*Pod, error) {
	var keys []PodKey
	if subject != "" {
		types, err := r.c.SMembers(ctx, r.k("pods:by-user", subject)).Result()
		if err != nil {
			return nil, err
		}
		for _, t := range types {
			keys = append(keys, PodKey{Subject: subject, ServerType: t})
		}
	} else {
		all, err := r.c.SMembers(ctx, r.k("pods:all")).Result()
		if err != nil {
			return nil, err
		}
		for _, e := range all {
			for i := 0; i < len(e); i++ {
				if e[i] == '|' {
					keys = append(keys, PodKey{ServerType: e[:i], Subject: e[i+1:]})
					break
				}
			}
		}
	}
	out := make([]*Pod, 0, len(keys))
	for _, k := range keys {
		p, err := r.GetPod(ctx, k)
		if err == nil {
			out = append(out, p)
		}
	}
	return out, nil
}

func (r *Redis) CountPods(ctx context.Context, subject, serverType string) (int, int, int, error) {
	pods, err := r.ListPods(ctx, "")
	if err != nil {
		return 0, 0, 0, err
	}
	var perUser, perType int
	for _, p := range pods {
		if p.Phase == PhaseGone || p.Phase == PhaseTerminating {
			continue
		}
		if p.Key.Subject == subject {
			perUser++
		}
		if p.Key.ServerType == serverType {
			perType++
		}
	}
	return perUser, perType, len(pods), nil
}

func (r *Redis) GetSession(ctx context.Context, id string) (*McpSession, error) {
	raw, err := r.c.Get(ctx, r.k("sess", id)).Result()
	if errors.Is(err, redis.Nil) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	var rec sessionRecord
	if err := json.Unmarshal([]byte(raw), &rec); err != nil {
		return nil, err
	}
	if !core.MACEqual(rec.MAC, r.sessionMAC(&rec.McpSession)) {
		return nil, fmt.Errorf("%w: session record %s failed authentication", ErrNotFound, id)
	}
	return &rec.McpSession, nil
}

func (r *Redis) PutSession(ctx context.Context, s *McpSession) error {
	b, _ := json.Marshal(sessionRecord{McpSession: *s, MAC: r.sessionMAC(s)})
	pipe := r.c.TxPipeline()
	pipe.Set(ctx, r.k("sess", s.ID), b, r.maxAge)
	pipe.SAdd(ctx, r.k("sess:by-pod", s.PodName), s.ID)
	pipe.Expire(ctx, r.k("sess:by-pod", s.PodName), r.maxAge)
	_, err := pipe.Exec(ctx)
	return err
}

func (r *Redis) DeleteSession(ctx context.Context, id string) error {
	s, err := r.GetSession(ctx, id)
	if err != nil {
		return nil
	}
	pipe := r.c.TxPipeline()
	pipe.Del(ctx, r.k("sess", id))
	pipe.SRem(ctx, r.k("sess:by-pod", s.PodName), id)
	_, err = pipe.Exec(ctx)
	return err
}

func (r *Redis) DeleteSessionsForPod(ctx context.Context, podName string) error {
	ids, err := r.c.SMembers(ctx, r.k("sess:by-pod", podName)).Result()
	if err != nil {
		return err
	}
	keys := []string{r.k("sess:by-pod", podName)}
	for _, id := range ids {
		keys = append(keys, r.k("sess", id))
	}
	return r.c.Del(ctx, keys...).Err()
}

func (r *Redis) Touch(ctx context.Context, podName string, at time.Time) error {
	return r.c.Set(ctx, r.k("active", podName), at.Unix(), 0).Err()
}

func (r *Redis) LastActive(ctx context.Context, podName string) (time.Time, error) {
	v, err := r.c.Get(ctx, r.k("active", podName)).Result()
	if errors.Is(err, redis.Nil) {
		return time.Time{}, ErrNotFound
	}
	if err != nil {
		return time.Time{}, err
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return time.Time{}, err
	}
	return time.Unix(n, 0), nil
}

// InFlight adjusts the counter; the key expires after an hour so a crashed
// gateway replica cannot pin a pod forever (streams refresh it via Touch/InFlight(0)).
func (r *Redis) InFlight(ctx context.Context, podName string, delta int) (int, error) {
	key := r.k("inflight", podName)
	var n int64
	var err error
	if delta == 0 {
		v, gerr := r.c.Get(ctx, key).Result()
		if errors.Is(gerr, redis.Nil) {
			return 0, nil
		}
		if gerr != nil {
			return 0, gerr
		}
		n, _ = strconv.ParseInt(v, 10, 64)
	} else {
		n, err = r.c.IncrBy(ctx, key, int64(delta)).Result()
		if err != nil {
			return 0, err
		}
		if n < 0 {
			_ = r.c.Set(ctx, key, 0, time.Hour).Err()
			n = 0
		}
	}
	_ = r.c.Expire(ctx, key, time.Hour).Err()
	return int(n), nil
}

var _ contracts.RoutingTable = (*Redis)(nil)
