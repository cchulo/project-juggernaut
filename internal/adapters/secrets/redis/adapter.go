// Package redis is the shared UserSecretStore. It stores core.SealedEntry
// JSON, which is ciphertext under a key only the user holds; Redis, the
// operator and the gateway cannot open it.
//
//	<p>usersecret:<subject>:<adapter>   JSON SealedEntry
//	<p>usersecrets:<subject>            SET of adapters
package redis

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	goredis "github.com/redis/go-redis/v9"

	"github.com/cchulo/project-juggernaut/internal/core"
	"github.com/cchulo/project-juggernaut/internal/core/contracts"
	"github.com/cchulo/project-juggernaut/internal/core/registry"
)

// Type is the registry name.
const Type = "redis"

func init() { registry.Secrets.Register(Type, New) }

// Store is the Redis-backed store.
type Store struct {
	c      *goredis.Client
	prefix string
}

// New connects using gateway.redis.
func New(ctx *core.Context) (contracts.UserSecretStore, error) {
	rc := ctx.Cfg().Gateway.Redis
	if rc == nil {
		return nil, fmt.Errorf("secrets store redis requires gateway.redis")
	}
	pw, err := ctx.Secrets.Get(rc.PasswordRef)
	if err != nil {
		return nil, err
	}
	c := goredis.NewClient(&goredis.Options{Addr: rc.Address, Password: pw, DB: rc.DB})
	if err := c.Ping(context.Background()).Err(); err != nil {
		return nil, fmt.Errorf("redis %s: %w", rc.Address, err)
	}
	return &Store{c: c, prefix: ctx.Options.String("key_prefix", rc.KeyPrefix)}, nil
}

func (s *Store) key(subject, adapter string) string {
	return s.prefix + "usersecret:" + subject + ":" + adapter
}

func (s *Store) index(subject string) string { return s.prefix + "usersecrets:" + subject }

func (s *Store) Put(ctx context.Context, subject, adapter string, e *core.SealedEntry) error {
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	pipe := s.c.TxPipeline()
	pipe.Set(ctx, s.key(subject, adapter), b, 0)
	pipe.SAdd(ctx, s.index(subject), adapter)
	_, err = pipe.Exec(ctx)
	return err
}

func (s *Store) Get(ctx context.Context, subject, adapter string) (*core.SealedEntry, error) {
	raw, err := s.c.Get(ctx, s.key(subject, adapter)).Result()
	if errors.Is(err, goredis.Nil) {
		return nil, contracts.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	var e core.SealedEntry
	if err := json.Unmarshal([]byte(raw), &e); err != nil {
		return nil, err
	}
	return &e, nil
}

func (s *Store) List(ctx context.Context, subject string) ([]string, error) {
	return s.c.SMembers(ctx, s.index(subject)).Result()
}

func (s *Store) Delete(ctx context.Context, subject, adapter string) error {
	pipe := s.c.TxPipeline()
	pipe.Del(ctx, s.key(subject, adapter))
	pipe.SRem(ctx, s.index(subject), adapter)
	_, err := pipe.Exec(ctx)
	return err
}

func (s *Store) DeleteAll(ctx context.Context, subject string) error {
	adapters, err := s.List(ctx, subject)
	if err != nil {
		return err
	}
	keys := []string{s.index(subject)}
	for _, a := range adapters {
		keys = append(keys, s.key(subject, a))
	}
	return s.c.Del(ctx, keys...).Err()
}

var _ contracts.UserSecretStore = (*Store)(nil)
