// Package fetch confines all network requests to configured public source hosts.
// Inputs: HTTPS requests, exact host allowlists, DNS answers, robots policy, and response limits.
// Outputs: address-pinned, redirect-rejecting, size-bounded public source responses.
package fetch

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"github.com/temoto/robotstxt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"proxywatch/internal/config"
	"strings"
	"sync"
	"time"
)

const UserAgent = "ProxyWatch/0.1 (bounded public-source discovery; no destination crawling)"

type Response struct {
	Body            []byte
	Status          int
	Header          http.Header
	Cached          bool
	Key             string
	RetrievedAt     time.Time
	CacheState      string
	FromNetwork     bool
	NetworkRequests int
}
type Error struct {
	Code   string
	Status int
}

func (e *Error) Error() string { return fmt.Sprintf("%s (HTTP %d)", e.Code, e.Status) }

type Client struct {
	http       *http.Client
	allowed    map[string]bool
	maxBytes   int64
	interval   time.Duration
	mu         sync.Mutex
	last       map[string]time.Time
	robots     map[string]*robotstxt.RobotsData
	test       bool
	cache      Cache
	cacheTTL   time.Duration
	rates      map[string]time.Duration
	cooldowns  map[string]cooldown
	maxRetries int
	retryDelay time.Duration
}

func New(cfg config.Config) *Client {
	c := &Client{allowed: map[string]bool{}, maxBytes: cfg.MaxBytes, interval: time.Duration(cfg.IntervalMS) * time.Millisecond, last: map[string]time.Time{}, robots: map[string]*robotstxt.RobotsData{}, rates: map[string]time.Duration{}, cooldowns: map[string]cooldown{}, maxRetries: 2, retryDelay: 250 * time.Millisecond}
	for _, h := range cfg.AllowedHosts {
		c.allowed[strings.ToLower(h)] = true
	}
	for host, ms := range cfg.RatesMS {
		c.rates[strings.ToLower(host)] = time.Duration(ms) * time.Millisecond
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	// When connecting directly, pin each connection to a validated public IP.
	// A configured forward proxy remains a trusted egress boundary and resolves
	// its destination itself; the allowlist and preflight DNS check still apply.
	tr.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		h, p, e := net.SplitHostPort(address)
		if e != nil {
			return nil, &Error{Code: "invalid_address"}
		}
		proxy := false
		for _, scheme := range []string{"https", "http"} {
			u, _ := url.Parse(scheme + "://public.invalid")
			pu, _ := http.ProxyFromEnvironment(&http.Request{URL: u})
			if pu != nil && pu.Hostname() == h {
				proxy = true
			}
		}
		if proxy {
			return (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, network, address)
		}
		ips, e := PublicIPs(ctx, h)
		if e != nil {
			return nil, e
		}
		return (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, network, net.JoinHostPort(ips[0].String(), p))
	}
	c.http = &http.Client{Transport: tr, Timeout: time.Duration(cfg.TimeoutSeconds) * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return c
}

// NewForTest accepts an in-memory transport; never use it for live crawling.
func NewForTest(h *http.Client) *Client {
	safe := *h
	safe.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &Client{http: &safe, maxBytes: 2097152, last: map[string]time.Time{}, robots: map[string]*robotstxt.RobotsData{}, test: true, rates: map[string]time.Duration{}, cooldowns: map[string]cooldown{}, maxRetries: 2, retryDelay: time.Millisecond}
}
func PublicIP(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.IsValid() || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
		return false
	}
	for _, s := range []string{"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "2001:db8::/32", "2001::/23", "2002::/16", "64:ff9b::/96"} {
		if netip.MustParsePrefix(s).Contains(ip) {
			return false
		}
	}
	return true
}
func PublicIPs(ctx context.Context, host string) ([]netip.Addr, error) {
	if ip, e := netip.ParseAddr(host); e == nil {
		if PublicIP(ip) {
			return []netip.Addr{ip}, nil
		}
		return nil, &Error{Code: "unsafe_ip"}
	}
	ips, e := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if e != nil || len(ips) == 0 {
		return nil, &Error{Code: "dns_unavailable"}
	}
	for _, ip := range ips {
		if !PublicIP(ip) {
			return nil, &Error{Code: "unsafe_dns"}
		}
	}
	return ips, nil
}
func (c *Client) Validate(ctx context.Context, raw string) error {
	u, e := url.Parse(raw)
	if e != nil || u.Hostname() == "" || u.User != nil || u.Fragment != "" || (u.Scheme != "https" && u.Scheme != "http") {
		return &Error{Code: "unsafe_url"}
	}
	if u.Port() != "" && u.Port() != "443" && u.Port() != "80" {
		return &Error{Code: "unsafe_port"}
	}
	if !c.allowed[strings.ToLower(u.Hostname())] {
		return &Error{Code: "host_not_allowed"}
	}
	_, e = PublicIPs(ctx, u.Hostname())
	return e
}
func (c *Client) Get(ctx context.Context, raw string, headers map[string]string) (result Response, err error) {
	requests := 0
	defer func() { result.NetworkRequests = requests; result.FromNetwork = requests > 0 }()
	if !c.test {
		if e := c.Validate(ctx, raw); e != nil {
			return Response{}, e
		}
	}
	if ctx.Err() != nil {
		return Response{}, &Error{Code: "cancelled"}
	}
	u, e := url.Parse(raw)
	if e != nil {
		return Response{}, &Error{Code: "unsafe_url"}
	}
	c.mu.Lock()
	cache, ttl := c.cache, c.cacheTTL
	c.mu.Unlock()
	key := ""
	var entry CacheEntry
	hasEvidence := false
	if cache != nil && cacheable(u) {
		key = cacheKey(u, headers)
		if ns, ok := ctx.Value(cacheNamespaceKey{}).(string); ok && ns != "" {
			key = Hash([]byte(key + "\x00" + ns))
		}
		var found bool
		entry, found, e = cache.Lookup(key)
		if e != nil {
			return Response{}, &Error{Code: "cache_lookup_failed"}
		}
		if found {
			hasEvidence, e = cache.HasEvidence(key)
			if e != nil {
				return Response{}, &Error{Code: "cache_lookup_failed"}
			}
		}
		if hasEvidence && ttl > 0 && !entry.ValidatedAt.IsZero() && time.Since(entry.ValidatedAt) >= 0 && time.Since(entry.ValidatedAt) < ttl {
			return Response{Status: 304, Cached: true, Key: key, RetrievedAt: entry.ValidatedAt, CacheState: "ttl", FromNetwork: false}, nil
		}
	}
	for attempt := 0; attempt <= c.maxRetries; attempt++ {
		if attempt > 0 {
			if e = waitContext(ctx, c.retryDelay*time.Duration(1<<(attempt-1))); e != nil {
				return Response{}, &Error{Code: "cancelled"}
			}
		}
		if e = c.pace(ctx, strings.ToLower(u.Hostname())); e != nil {
			return Response{}, e
		}
		req, e := http.NewRequestWithContext(ctx, "GET", raw, nil)
		if e != nil {
			return Response{}, &Error{Code: "unsafe_url"}
		}
		req.Header.Set("User-Agent", UserAgent)
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		if hasEvidence {
			if entry.ETag != "" {
				req.Header.Set("If-None-Match", entry.ETag)
			}
			if entry.LastModified != "" {
				req.Header.Set("If-Modified-Since", entry.LastModified)
			}
		}
		requests++
		resp, e := c.http.Do(req)
		if e != nil {
			var timeout net.Error
			if ctx.Err() == nil && attempt < c.maxRetries && errors.As(e, &timeout) && timeout.Timeout() {
				continue
			}
			return Response{}, &Error{Code: "network_or_timeout"}
		}
		r := Response{Status: resp.StatusCode, Header: resp.Header.Clone(), Key: key, RetrievedAt: time.Now().UTC(), FromNetwork: true}
		if resp.StatusCode == http.StatusNotModified {
			resp.Body.Close()
			if key == "" || !hasEvidence {
				return r, &Error{Code: "cache_evidence_unavailable", Status: 304}
			}
			if value := resp.Header.Get("ETag"); value != "" {
				entry.ETag = value
			}
			if value := resp.Header.Get("Last-Modified"); value != "" {
				entry.LastModified = value
			}
			entry.ValidatedAt = r.RetrievedAt
			if e = cache.Put(key, entry); e != nil {
				return r, &Error{Code: "cache_store_failed"}
			}
			r.Cached = true
			r.CacheState = "not_modified"
			return r, nil
		}
		if resp.StatusCode >= 300 && resp.StatusCode < 400 {
			resp.Body.Close()
			return r, &Error{Code: "redirect_rejected", Status: resp.StatusCode}
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			resp.Body.Close()
			code := "http_error"
			if resp.StatusCode == 429 {
				code = "rate_limited"
				c.markCooldown(strings.ToLower(u.Hostname()), resp.StatusCode, r.Header)
			}
			if resp.StatusCode == 403 {
				code = "access_or_quota_restricted"
				c.markCooldown(strings.ToLower(u.Hostname()), resp.StatusCode, r.Header)
			}
			if resp.StatusCode >= 500 && resp.StatusCode <= 599 && attempt < c.maxRetries {
				continue
			}
			return r, &Error{Code: code, Status: resp.StatusCode}
		}
		r.Body, e = io.ReadAll(io.LimitReader(resp.Body, c.maxBytes+1))
		resp.Body.Close()
		if e != nil {
			return r, &Error{Code: "read_failed"}
		}
		if int64(len(r.Body)) > c.maxBytes {
			return Response{}, &Error{Code: "response_too_large"}
		}
		if key != "" {
			entry = CacheEntry{ETag: r.Header.Get("ETag"), LastModified: r.Header.Get("Last-Modified"), ValidatedAt: r.RetrievedAt}
			if e = cache.Put(key, entry); e != nil {
				return r, &Error{Code: "cache_store_failed"}
			}
		}
		return r, nil
	}
	return Response{}, &Error{Code: "network_or_timeout"}
}
func (c *Client) PublicPage(ctx context.Context, raw string) (result Response, err error) {
	robotRequests := 0
	defer func() { result.NetworkRequests += robotRequests; result.FromNetwork = result.NetworkRequests > 0 }()
	u, e := url.Parse(raw)
	if e != nil {
		return Response{}, &Error{Code: "unsafe_url"}
	}
	origin := u.Scheme + "://" + u.Host
	c.mu.Lock()
	robots, ok := c.robots[origin]
	c.mu.Unlock()
	if !ok {
		r, e := c.Get(ctx, origin+"/robots.txt", nil)
		robotRequests += r.NetworkRequests
		if e != nil && r.Status != 404 {
			return Response{}, &Error{Code: "robots_unavailable", Status: r.Status}
		}
		if r.Status == 404 {
			robots, _ = robotstxt.FromStatusAndBytes(404, nil)
		} else {
			robots, e = robotstxt.FromBytes(r.Body)
			if e != nil {
				return Response{}, &Error{Code: "robots_invalid"}
			}
		}
		c.mu.Lock()
		c.robots[origin] = robots
		c.mu.Unlock()
	}
	path := u.EscapedPath()
	if u.RawQuery != "" {
		path += "?" + u.RawQuery
	}
	group := robots.FindGroup("ProxyWatch")
	if group.CrawlDelay > time.Minute {
		return Response{}, &Error{Code: "robots_crawl_delay_exceeds_limit"}
	}
	if group.CrawlDelay > 0 {
		c.mu.Lock()
		current := c.interval
		if ms, ok := c.rates[strings.ToLower(u.Hostname())]; ok {
			current = ms
		}
		if group.CrawlDelay > current {
			c.rates[strings.ToLower(u.Hostname())] = group.CrawlDelay
		}
		c.mu.Unlock()
	}
	if !group.Test(path) {
		return Response{}, &Error{Code: "robots_denied"}
	}
	return c.Get(ctx, raw, nil)
}
func Hash(body []byte) string { return fmt.Sprintf("%x", sha256.Sum256(body)) }
