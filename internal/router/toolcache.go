package router

import (
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// toolCache remembers the tool list of a server type for a config version so
// only the first user of a type pays the cold start to enumerate tools.
type toolCache struct {
	mu   sync.RWMutex
	ttl  time.Duration
	data map[string]cached // key: serverType|configHash
}

type cached struct {
	tools   []*mcp.Tool
	fetched time.Time
}

func newToolCache(ttl time.Duration) *toolCache {
	return &toolCache{ttl: ttl, data: map[string]cached{}}
}

func (c *toolCache) get(serverType, hash string) ([]*mcp.Tool, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	e, ok := c.data[serverType+"|"+hash]
	if !ok || time.Since(e.fetched) > c.ttl {
		return nil, false
	}
	return e.tools, true
}

func (c *toolCache) put(serverType, hash string, tools []*mcp.Tool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.data[serverType+"|"+hash] = cached{tools: tools, fetched: time.Now()}
}
