// Package fetch implements guarded public-source HTTP access and metadata-only caching.
// Inputs: request contexts, per-host pacing intervals, and provider cooldown headers.
// Outputs: cancellable delays and normalized retry windows for the shared client.
package fetch

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type cooldown struct {
	until  time.Time
	status int
}

func waitContext(ctx context.Context, delay time.Duration) error {
	if delay <= 0 {
		return nil
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
func (c *Client) pace(ctx context.Context, host string) error {
	c.mu.Lock()
	if cd := c.cooldowns[host]; time.Now().Before(cd.until) {
		c.mu.Unlock()
		return &Error{Code: "quota_cooldown", Status: cd.status}
	}
	interval := c.interval
	if value, ok := c.rates[host]; ok {
		interval = value
	}
	next := c.last[host].Add(interval)
	if next.Before(time.Now()) {
		next = time.Now()
	}
	c.last[host] = next
	c.mu.Unlock()
	if e := waitContext(ctx, time.Until(next)); e != nil {
		return &Error{Code: "cancelled"}
	}
	return nil
}
func (c *Client) markCooldown(host string, status int, h http.Header) {
	now := time.Now()
	delay := time.Minute
	if value := strings.TrimSpace(h.Get("Retry-After")); value != "" {
		if seconds, e := strconv.ParseInt(value, 10, 64); e == nil {
			if seconds <= 0 {
				delay = 0
			} else if seconds < 60 {
				delay = time.Duration(seconds) * time.Second
			}
		} else if until, e := http.ParseTime(value); e == nil {
			delay = until.Sub(now)
		}
	} else if value := h.Get("X-RateLimit-Reset"); value != "" {
		if seconds, e := strconv.ParseInt(value, 10, 64); e == nil {
			delay = time.Unix(seconds, 0).Sub(now)
		}
	}
	if delay < 0 {
		delay = 0
	}
	if delay > time.Minute {
		delay = time.Minute
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cooldowns == nil {
		c.cooldowns = map[string]cooldown{}
	}
	c.cooldowns[host] = cooldown{until: now.Add(delay), status: status}
}
