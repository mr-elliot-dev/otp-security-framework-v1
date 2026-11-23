package ratelimit

import (
	"context"
	"sync"
	"time"

	"github.com/yourorg/otpsec/internal/httpclient"
)

// Probe sends sequential authorized requests and detects rate-limit headers/429s.
func Probe(ctx context.Context, c *httpclient.Client, url string, maxReq, rps int) map[string]any {
	if rps <= 0 {
		rps = 5
	}
	interval := time.Second / time.Duration(rps)
	var (
		mu        sync.Mutex
		codes     []int
		gotLimit  bool
		headerSet bool
		wg        sync.WaitGroup
	)
	sem := make(chan struct{}, 1)
	for i := 0; i < maxReq; i++ {
		select {
		case <-ctx.Done():
			break
		case sem <- struct{}{}:
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			resp, err := c.Do(ctx, "GET", url, nil)
			if err != nil {
				return
			}
			mu.Lock()
			codes = append(codes, resp.StatusCode)
			if resp.StatusCode == 429 {
				gotLimit = true
			}
			if resp.Headers.Get("Retry-After") != "" || resp.Headers.Get("X-RateLimit-Limit") != "" {
				headerSet = true
			}
			mu.Unlock()
		}()
		time.Sleep(interval)
	}
	wg.Wait()
	return map[string]any{
		"requests_sent":      len(codes),
		"rate_limit_hit":     gotLimit,
		"rate_limit_headers": headerSet,
		"observed_codes":     codes,
	}
}