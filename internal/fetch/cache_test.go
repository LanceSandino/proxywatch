package fetch

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"proxywatch/internal/config"
)

type memoryCache struct {
	entries  map[string]CacheEntry
	evidence map[string]bool
	puts     int
	err      error
}

func newMemoryCache() *memoryCache {
	return &memoryCache{entries: map[string]CacheEntry{}, evidence: map[string]bool{}}
}
func (m *memoryCache) Lookup(key string) (CacheEntry, bool, error) {
	e, ok := m.entries[key]
	return e, ok, m.err
}
func (m *memoryCache) Put(key string, e CacheEntry) error {
	if m.err != nil {
		return m.err
	}
	m.entries[key] = e
	m.puts++
	return nil
}
func (m *memoryCache) HasEvidence(key string) (bool, error) { return m.evidence[key], m.err }

func TestMetadataCacheConditionalValidationAndTTL(t *testing.T) {
	cache := newMemoryCache()
	calls := 0
	c := NewForTest(&http.Client{Transport: transportFunc(func(req *http.Request) (*http.Response, error) {
		calls++
		if calls == 1 {
			if req.Header.Get("If-None-Match") != "" {
				t.Fatal("unexpected first conditional request")
			}
			r := response(200, "public proxy list")
			r.Header.Set("ETag", `"one"`)
			r.Header.Set("Last-Modified", "Mon, 12 Oct 2026 00:00:00 GMT")
			return r, nil
		}
		if req.Header.Get("If-None-Match") != `"one"` || req.Header.Get("If-Modified-Since") == "" {
			t.Fatalf("missing validators: %v", req.Header)
		}
		return response(304, ""), nil
	})})
	c.SetCache(cache, 0)
	first, e := c.Get(context.Background(), "https://source.invalid/list", nil)
	if e != nil || first.Status != 200 || first.Key == "" || !first.FromNetwork || first.Cached || first.RetrievedAt.IsZero() {
		t.Fatalf("first response: %+v, %v", first, e)
	}
	cache.evidence[first.Key] = true
	second, e := c.Get(context.Background(), "https://source.invalid/list", nil)
	if e != nil || second.Status != 304 || !second.Cached || second.CacheState != "not_modified" || !second.FromNetwork || len(second.Body) != 0 || second.Key != first.Key || second.RetrievedAt.Before(first.RetrievedAt) {
		t.Fatalf("conditional response: %+v, %v", second, e)
	}
	c.SetCache(cache, time.Hour)
	third, e := c.Get(context.Background(), "https://source.invalid/list", nil)
	if e != nil || third.Status != 304 || !third.Cached || third.CacheState != "ttl" || third.FromNetwork || third.RetrievedAt != second.RetrievedAt || calls != 2 {
		t.Fatalf("ttl response: %+v, %v; calls=%d", third, e, calls)
	}
	encoded, _ := json.Marshal(cache.entries)
	if strings.Contains(string(encoded), "public proxy list") {
		t.Fatal("response body persisted")
	}
	if cache.puts != 2 {
		t.Fatalf("validator updates: %d", cache.puts)
	}
}

func TestMetadataWithoutPersistedEvidenceCannotBeReused(t *testing.T) {
	cache := newMemoryCache()
	calls := 0
	c := NewForTest(&http.Client{Transport: transportFunc(func(req *http.Request) (*http.Response, error) {
		calls++
		if req.Header.Get("If-None-Match") != "" {
			t.Fatal("conditionally fetched document without durable evidence")
		}
		r := response(200, "fresh")
		r.Header.Set("ETag", `"same"`)
		return r, nil
	})})
	c.SetCache(cache, time.Hour)
	for i := 0; i < 2; i++ {
		r, e := c.Get(context.Background(), "https://source.invalid/list", nil)
		if e != nil || r.Cached || r.Status != 200 {
			t.Fatalf("metadata-only document reused: %+v, %v", r, e)
		}
	}
	if calls != 2 {
		t.Fatalf("metadata hid fetch: %d", calls)
	}
}

func TestUnsolicited304RequiresPersistedEvidence(t *testing.T) {
	cache := newMemoryCache()
	c := NewForTest(&http.Client{Transport: transportFunc(func(*http.Request) (*http.Response, error) { return response(304, ""), nil })})
	c.SetCache(cache, time.Hour)
	_, e := c.Get(context.Background(), "https://source.invalid/list", nil)
	assertCode(t, e, "cache_evidence_unavailable")
	if cache.puts != 0 {
		t.Fatal("invalid304 changed cache")
	}
}

func TestSearchAndRobotsResponsesNeverMetadataCached(t *testing.T) {
	for _, raw := range []string{"https://api.github.com/search/repositories?q=proxy", "https://www.googleapis.com/youtube/v3/search?q=proxy", "https://www.googleapis.com/youtube/v3/commentThreads?videoId=one", "https://www.googleapis.com/youtube/v3/comments?parentId=one", "https://public.api.bsky.app/xrpc/app.bsky.feed.searchPosts?q=proxy", "https://hn.algolia.com/api/v1/search?query=proxy", "https://scope.flarum.cloud/api/discussions?filter[q]=proxy", "https://source.invalid/robots.txt"} {
		t.Run(raw, func(t *testing.T) {
			cache := newMemoryCache()
			c := NewForTest(&http.Client{Transport: transportFunc(func(*http.Request) (*http.Response, error) {
				r := response(200, "search result")
				r.Header.Set("ETag", `"result"`)
				return r, nil
			})})
			c.SetCache(cache, time.Hour)
			r, e := c.Get(context.Background(), raw, nil)
			if e != nil || r.Key != "" || cache.puts != 0 {
				t.Fatalf("search/robots cached: %+v, %v, puts=%d", r, e, cache.puts)
			}
		})
	}
}

func TestFailedFetchCannotOverwriteGoodValidators(t *testing.T) {
	cache := newMemoryCache()
	calls := 0
	c := NewForTest(&http.Client{Transport: transportFunc(func(*http.Request) (*http.Response, error) {
		calls++
		if calls == 1 {
			r := response(200, "good")
			r.Header.Set("ETag", `"good"`)
			return r, nil
		}
		r := response(500, "failure")
		r.Header.Set("ETag", `"bad"`)
		return r, nil
	})})
	c.SetCache(cache, 0)
	first, e := c.Get(context.Background(), "https://source.invalid/list", nil)
	if e != nil {
		t.Fatal(e)
	}
	cache.evidence[first.Key] = true
	before := cache.entries[first.Key]
	_, e = c.Get(context.Background(), "https://source.invalid/list", nil)
	assertCode(t, e, "http_error")
	if cache.puts != 1 || cache.entries[first.Key] != before || calls != 4 {
		t.Fatalf("failure polluted cache or unbounded retries: %+v calls=%d puts=%d", cache.entries, calls, cache.puts)
	}
}

func TestCacheKeyKeepsSecretsOutAndSeparatesCredentialIdentity(t *testing.T) {
	raw := "https://source.invalid/api/doc?id=42&key=secret-value&sig=signed-secret"
	u, e := url.Parse(raw)
	if e != nil {
		t.Fatal(e)
	}
	key := cacheKey(u, map[string]string{"Authorization": "Bearer header-secret"})
	if len(key) != 64 || strings.Contains(key, "secret") || key != cacheKey(u, map[string]string{"authorization": "Bearer header-secret"}) {
		t.Fatalf("unsafe/unstable key: %s", key)
	}
	changed := *u
	q := changed.Query()
	q.Set("id", "43")
	changed.RawQuery = q.Encode()
	if key == cacheKey(&changed, map[string]string{"Authorization": "Bearer header-secret"}) {
		t.Fatal("source citation identities collided")
	}
	if key == cacheKey(u, map[string]string{"Authorization": "Bearer changed-secret"}) {
		t.Fatal("credential identities collided")
	}
	q = u.Query()
	q.Set("key", "changed-secret")
	u.RawQuery = q.Encode()
	if key == cacheKey(u, map[string]string{"Authorization": "Bearer header-secret"}) {
		t.Fatal("query credential identities collided")
	}
}

func TestCacheCannotBypassSSRFValidationOrCancellation(t *testing.T) {
	cache := newMemoryCache()
	c := New(config.Config{AllowedHosts: []string{"127.0.0.1"}, TimeoutSeconds: 1, MaxBytes: 1024})
	c.SetCache(cache, time.Hour)
	u, _ := url.Parse("http://127.0.0.1/list")
	key := cacheKey(u, nil)
	cache.entries[key] = CacheEntry{ValidatedAt: time.Now().UTC()}
	cache.evidence[key] = true
	_, e := c.Get(context.Background(), u.String(), nil)
	assertCode(t, e, "unsafe_ip")
	cache.err = errors.New("internal path containing secret")
	test := NewForTest(&http.Client{})
	test.SetCache(cache, time.Hour)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, e = test.Get(ctx, "https://source.invalid/list", nil)
	assertCode(t, e, "cancelled")
	_, e = test.Get(context.Background(), "https://source.invalid/list", nil)
	assertCode(t, e, "cache_lookup_failed")
	if strings.Contains(e.Error(), "secret") {
		t.Fatal("cache error exposed internal details")
	}
}

func TestRetryAndCooldownAreBounded(t *testing.T) {
	for _, status := range []int{403, 429} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			calls := 0
			c := NewForTest(&http.Client{Transport: transportFunc(func(*http.Request) (*http.Response, error) {
				calls++
				r := response(status, "")
				r.Header.Set("Retry-After", "100000")
				return r, nil
			})})
			_, e := c.Get(context.Background(), "https://source.invalid/one", nil)
			if e == nil {
				t.Fatal("quota response accepted")
			}
			_, e = c.Get(context.Background(), "https://source.invalid/two", nil)
			assertCode(t, e, "quota_cooldown")
			if calls != 1 {
				t.Fatalf("quota response retried: %d", calls)
			}
			delay := time.Until(c.cooldowns["source.invalid"].until)
			if delay <= 0 || delay > time.Minute {
				t.Fatalf("unbounded cooldown: %v", delay)
			}
		})
	}
	calls := 0
	c := NewForTest(&http.Client{Transport: transportFunc(func(*http.Request) (*http.Response, error) {
		calls++
		if calls < 3 {
			return response(503, ""), nil
		}
		return response(200, "recovered"), nil
	})})
	r, e := c.Get(context.Background(), "https://source.invalid/list", nil)
	if e != nil || r.Status != 200 || calls != 3 {
		t.Fatalf("bounded recovery failed: %+v, %v, calls=%d", r, e, calls)
	}
}

func TestCancellationDuringRetryAndPerHostIntervals(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	calls := 0
	c := NewForTest(&http.Client{Transport: transportFunc(func(*http.Request) (*http.Response, error) { calls++; cancel(); return response(503, ""), nil })})
	_, e := c.Get(ctx, "https://source.invalid/list", nil)
	assertCode(t, e, "cancelled")
	if calls != 1 {
		t.Fatal("retried after cancellation")
	}
	c = NewForTest(&http.Client{})
	c.interval = 0
	c.rates["source.invalid"] = time.Hour
	c.last["source.invalid"] = time.Now()
	ctx, cancel = context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	e = c.pace(ctx, "source.invalid")
	assertCode(t, e, "cancelled")
	if e = c.pace(context.Background(), "other.invalid"); e != nil {
		t.Fatalf("source-specific limit blocked unrelated source: %v", e)
	}
}

func TestOutboundCountsIncludeRetriesAndRobots(t *testing.T) {
	calls := 0
	c := NewForTest(&http.Client{Transport: transportFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.URL.Path == "/robots.txt" {
			if calls == 1 {
				return response(503, ""), nil
			}
			return response(200, "User-agent: *\nAllow: /\n"), nil
		}
		return response(200, "public list"), nil
	})})
	r, e := c.PublicPage(context.Background(), "https://source.invalid/list")
	if e != nil || r.NetworkRequests != 3 || !r.FromNetwork || calls != 3 {
		t.Fatalf("request accounting incorrect: %+v, %v, calls=%d", r, e, calls)
	}
	r, e = c.PublicPage(context.Background(), "https://source.invalid/list")
	if e != nil || r.NetworkRequests != 1 || calls != 4 {
		t.Fatalf("cached robots counted as request: %+v, %v, calls=%d", r, e, calls)
	}
}

func TestNonTimeoutTransportFailuresAreNotRetried(t *testing.T) {
	calls := 0
	c := NewForTest(&http.Client{Transport: transportFunc(func(*http.Request) (*http.Response, error) {
		calls++
		return nil, errors.New("invalid certificate: no transient timeout")
	})})
	r, e := c.Get(context.Background(), "https://source.invalid/list", nil)
	assertCode(t, e, "network_or_timeout")
	if calls != 1 || r.NetworkRequests != 1 {
		t.Fatalf("permanent transport error retried: calls=%d, response=%+v", calls, r)
	}
}

func TestRetryAfterDateAndRateLimitResetBoundCooldown(t *testing.T) {
	for _, h := range []http.Header{{"Retry-After": []string{time.Now().Add(30 * time.Second).UTC().Format(http.TimeFormat)}}, {"X-Ratelimit-Reset": []string{"1"}}, {"Retry-After": []string{"-1"}}} {
		c := NewForTest(&http.Client{})
		c.markCooldown("source.invalid", 429, h)
		delay := time.Until(c.cooldowns["source.invalid"].until)
		if delay > time.Minute || delay < -time.Second {
			t.Fatalf("invalid cooldown: %v", delay)
		}
	}
}

func TestAdapterNamespaceSeparatesSameURL(t *testing.T) {
	cache := &memoryCache{entries: map[string]CacheEntry{}, evidence: map[string]bool{}}
	client := NewForTest(&http.Client{Transport: transportFunc(func(req *http.Request) (*http.Response, error) {
		r := response(200, "body")
		r.Header.Set("ETag", `"one"`)
		return r, nil
	})})
	client.SetCache(cache, time.Hour)
	a, e := client.Get(WithNamespace(context.Background(), "publicpage"), "https://source.invalid/document", nil)
	if e != nil {
		t.Fatal(e)
	}
	cache.evidence[a.Key] = true
	b, e := client.Get(WithNamespace(context.Background(), "flarum"), "https://source.invalid/document", nil)
	if e != nil {
		t.Fatal(e)
	}
	if a.Key == b.Key || b.Cached {
		t.Fatal("different adapter reused foreign source provenance")
	}
}
