package runtime

import (
	"context"
	"fmt"
	"net/http"
	"time"
)

// WaitReady polls the wrapper's readiness endpoint until it answers 200 or the
// budget elapses. It is used by every backend after a spawn.
func WaitReady(ctx context.Context, readyURL string, budget time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	client := &http.Client{Timeout: 2 * time.Second}
	tick := time.NewTicker(500 * time.Millisecond)
	defer tick.Stop()
	for {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, readyURL, nil)
		resp, err := client.Do(req)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("pod not ready within %s: %w", budget, ctx.Err())
		case <-tick.C:
		}
	}
}
