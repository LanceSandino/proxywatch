// Package fetch implements guarded public-source HTTP access and metadata-only caching.
// Inputs: allowlisted requests, cache validators, timing policy, and transport responses.
// Outputs: bounded responses with explicit network, cached, or revalidated provenance.
package fetch

import (
	"context"
	"net/url"
	"sort"
	"strings"
	"time"
)

// CacheEntry stores only HTTP validators and a validation time, never content.
type CacheEntry struct {
	ETag         string
	LastModified string
	ValidatedAt  time.Time
}

// HasEvidence reports whether the source document was successfully persisted.
// Metadata alone is insufficient to reuse an unavailable response body.
type Cache interface {
	Lookup(key string) (CacheEntry, bool, error)
	Put(key string, entry CacheEntry) error
	HasEvidence(key string) (bool, error)
}

func (c *Client) SetCache(cache Cache, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cache = cache
	if ttl < 0 {
		ttl = 0
	}
	c.cacheTTL = ttl
}

func cacheable(u *url.URL) bool {
	p := strings.ToLower(u.Path)
	if strings.HasSuffix(p, "/robots.txt") || strings.Contains(p, "/search") || strings.Contains(p, "searchposts") || strings.TrimSuffix(p, "/") == "/youtube/v3/commentthreads" || strings.TrimSuffix(p, "/") == "/youtube/v3/comments" || strings.EqualFold(u.Hostname(), "hn.algolia.com") || strings.TrimSuffix(p, "/") == "/api/discussions" {
		return false
	}
	return true
}

// The URL persisted by adapters is independently sanitized. Keys additionally
// isolate credential identities with one-way hashes, without retaining secrets.
func cacheKey(u *url.URL, headers map[string]string) string {
	safe := *u
	safe.User = nil
	safe.Fragment = ""
	safe.RawFragment = ""
	q := safe.Query()
	secret := []string{}
	for k, values := range q {
		low := strings.ToLower(k)
		if strings.Contains(low, "key") || strings.Contains(low, "token") || strings.Contains(low, "secret") || strings.Contains(low, "password") || strings.Contains(low, "credential") || strings.Contains(low, "session") || strings.Contains(low, "email") || strings.Contains(low, "username") || low == "sig" || low == "auth" {
			secret = append(secret, k+"="+strings.Join(values, "\x00"))
			q.Del(k)
		}
	}
	safe.Scheme = strings.ToLower(safe.Scheme)
	safe.Host = strings.ToLower(safe.Host)
	safe.RawQuery = q.Encode()
	identity := append([]string{}, secret...)
	for k, v := range headers {
		identity = append(identity, strings.ToLower(k)+"="+v)
	}
	sort.Strings(identity)
	return Hash([]byte(safe.String() + "\x00" + Hash([]byte(strings.Join(identity, "\x00")))))
}

type cacheNamespaceKey struct{}

// WithNamespace separates different adapter interpretations of one source URL.
func WithNamespace(ctx context.Context, namespace string) context.Context {
	return context.WithValue(ctx, cacheNamespaceKey{}, namespace)
}
