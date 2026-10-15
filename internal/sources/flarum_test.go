package sources

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"proxywatch/internal/fetch"
	"proxywatch/internal/model"
)

func TestFlarumIndependentFirstPostOnly(t *testing.T) {
	c := cfg()
	c.FlarumURL = "https://scope.proxywatch-test.net"
	c.AllowedHosts = []string{"scope.proxywatch-test.net"}
	c.FlarumQueries = []string{"StudyHub", "Interstellar"}
	var requests []string
	client := fetch.NewForTest(&http.Client{Transport: transport(func(r *http.Request) (*http.Response, error) {
		requests = append(requests, r.URL.Path)
		switch r.URL.Path {
		case "/robots.txt":
			return response(404, ""), nil
		case "/api/discussions":
			if r.URL.Query().Get("include") != "firstPost" || r.URL.Query().Get("filter[q]") != "StudyHub" {
				t.Fatal("unbounded query or author includes", r.URL.String())
			}
			return response(200, `{"data":[{"type":"discussions","id":"101","attributes":{"title":"StudyHub Proxy Links"},"relationships":{"firstPost":{"data":{"type":"posts","id":"202"}}}}],"included":[{"type":"users","attributes":{"username":"private-profile"}},{"type":"posts","id":"999","attributes":{"contentHtml":"https://never-read.proxywatch-test.net"}}]}`), nil
		case "/api/posts/202":
			if r.URL.Query().Get("include") != "discussion" {
				t.Fatal("profile include requested")
			}
			return response(200, `{"data":{"type":"posts","id":"202","attributes":{"contentHtml":"<p>StudyHub mirror https://alpha.proxywatch-test.net</p>","number":1},"relationships":{"discussion":{"data":{"type":"discussions","id":"101"}}}},"included":[{"type":"users","attributes":{"username":"private-profile"}}]}`), nil
		}
		t.Fatal("arbitrary post or path fetched", r.URL.String())
		return nil, nil
	})})
	result := Collect(context.Background(), c, client, []string{"flarum"})
	if len(result.Errors) > 0 || len(result.Documents) != 1 || len(requests) != 3 {
		t.Fatalf("result %+v requests %+v", result, requests)
	}
	d := result.Documents[0]
	if d.URL != "https://scope.proxywatch-test.net/d/101" || d.ExternalID != "202" || d.IndependenceKey != "flarum:scope.proxywatch-test.net" || strings.Contains(d.Text, "private-profile") || strings.Contains(d.Text, "never-read") {
		t.Fatalf("bad document %+v", d)
	}
}
func TestFlarumBoundsAndInvalidReferences(t *testing.T) {
	c := cfg()
	c.FlarumURL = "https://scope.proxywatch-test.net"
	c.AllowedHosts = []string{"scope.proxywatch-test.net"}
	c.FlarumQueries = []string{"StudyHub"}
	c.MaxResults = 1
	posts := 0
	client := fetch.NewForTest(&http.Client{Transport: transport(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/robots.txt" {
			return response(404, ""), nil
		}
		if r.URL.Path == "/api/discussions" {
			return response(200, `{"data":[{"type":"discussions","id":"101","relationships":{"firstPost":{"data":{"type":"posts","id":"../../private"}}}},{"type":"discussions","id":"102","relationships":{"firstPost":{"data":{"type":"posts","id":"203"}}}}]}`), nil
		}
		posts++
		return response(200, "{}"), nil
	})})
	result := Collect(context.Background(), c, client, []string{"flarum"})
	if posts != 0 || len(result.Documents) != 0 || len(result.Errors) != 1 || result.Errors[0].Code != "INVALID_RESPONSE" {
		t.Fatalf("unsafe/unbounded reference %+v posts %d", result, posts)
	}
}
func TestFlarumMalformedAndAccessRestricted(t *testing.T) {
	for _, status := range []int{200, 403} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			c := cfg()
			c.FlarumURL = "https://scope.proxywatch-test.net"
			c.AllowedHosts = []string{"scope.proxywatch-test.net"}
			c.FlarumQueries = []string{"StudyHub"}
			client := fetch.NewForTest(&http.Client{Transport: transport(func(r *http.Request) (*http.Response, error) {
				if r.URL.Path == "/robots.txt" {
					return response(404, ""), nil
				}
				return response(status, "malformed"), nil
			})})
			result := Collect(context.Background(), c, client, []string{"flarum"})
			if len(result.Documents) != 0 || len(result.Errors) != 1 {
				t.Fatalf("result %+v", result)
			}
			expected := "INVALID_RESPONSE"
			if status == 403 {
				expected = "ACCESS_OR_QUOTA_RESTRICTED"
			}
			if result.Errors[0].Code != expected {
				t.Fatalf("result %+v", result)
			}
		})
	}
}
func TestPublicFlarumJSShellUnavailable(t *testing.T) {
	c := cfg()
	c.Pages = []string{"https://scope.proxywatch-test.net/u/Profile"}
	client := fetch.NewForTest(&http.Client{Transport: transport(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/robots.txt" {
			return response(404, ""), nil
		}
		return response(200, `<script src="flarum.js"></script><div>Loading...</div><noscript>Please enable JavaScript in your browser</noscript><a href="https://freeflarum.com">hosting</a>`), nil
	})})
	result := Collect(context.Background(), c, client, []string{"publicpage"})
	if len(result.Documents) != 0 || len(result.Errors) != 1 || result.Errors[0].Code != "SOURCE_UNAVAILABLE_JS_REQUIRED" {
		t.Fatalf("JS-only shell reported successful %+v", result)
	}
}

type metadataCache struct {
	entry   fetch.CacheEntry
	present bool
}

func (m *metadataCache) Lookup(key string) (fetch.CacheEntry, bool, error) {
	return m.entry, m.present, nil
}
func (m *metadataCache) Put(key string, entry fetch.CacheEntry) error {
	m.entry = entry
	m.present = true
	return nil
}
func (m *metadataCache) HasEvidence(key string) (bool, error) { return m.present, nil }
func TestCachedDocumentMetadataReusedWithoutParsing(t *testing.T) {
	for _, ttl := range []time.Duration{time.Hour, 0} {
		name := "conditional304"
		if ttl > 0 {
			name = "ttl"
		}
		t.Run(name, func(t *testing.T) {
			c := cfg()
			c.GitHubRepos = []string{"school/list"}
			cache := &metadataCache{entry: fetch.CacheEntry{ETag: `"v1"`, ValidatedAt: time.Now().UTC()}, present: true}
			network := 0
			client := fetch.NewForTest(&http.Client{Transport: transport(func(r *http.Request) (*http.Response, error) {
				network++
				if r.Header.Get("If-None-Match") != `"v1"` {
					t.Fatal("missing validator")
				}
				return response(304, ""), nil
			})})
			client.SetCache(cache, ttl)
			result := Collect(context.Background(), c, client, []string{"github"})
			if len(result.Documents) != 0 || len(result.Errors) > 0 || len(result.Reused) != 1 || result.Reused[0].Key == "" || result.Reused[0].RetrievedAt.IsZero() {
				t.Fatalf("invalid reuse metadata %+v", result)
			}
			wantNetwork := 1
			wantState := "not_modified"
			if ttl > 0 {
				wantNetwork = 0
				wantState = "ttl"
			}
			if network != wantNetwork || result.NetworkRequests["github"] != wantNetwork || result.Reused[0].CacheState != wantState {
				t.Fatalf("invalid cache/network accounting %+v requests %d", result, network)
			}
		})
	}
}

func TestCachedReuseConsumesGlobalDocumentBudget(t *testing.T) {
	c := cfg()
	c.MaxDocs = 1
	c.GitHubRepos = []string{"school/first", "school/second"}
	cache := &metadataCache{entry: fetch.CacheEntry{ValidatedAt: time.Now().UTC()}, present: true}
	client := fetch.NewForTest(&http.Client{Transport: transport(func(r *http.Request) (*http.Response, error) {
		t.Fatal("TTL reuse made network request", r.URL.String())
		return nil, nil
	})})
	client.SetCache(cache, time.Hour)
	result := Collect(context.Background(), c, client, []string{"github", "fixtures", "flarum"})
	if len(result.Reused) != 1 || len(result.Documents) != 0 || result.SourceAttempts["github"] != 1 {
		t.Fatalf("cache reuse did not consume global slot %+v", result)
	}
	skipped := map[string]bool{}
	for _, e := range result.Errors {
		if e.Code == "SOURCE_NOT_ATTEMPTED_BUDGET" {
			skipped[e.Family] = true
		}
	}
	if !skipped["fixtures"] || !skipped["flarum"] {
		t.Fatalf("budget skips were not explicit %+v", result.Errors)
	}
}

func TestRepeatedCacheKeyDoesNotConsumeExtraSlot(t *testing.T) {
	cache := &metadataCache{entry: fetch.CacheEntry{ValidatedAt: time.Now().UTC()}, present: true}
	client := fetch.NewForTest(&http.Client{Transport: transport(func(r *http.Request) (*http.Response, error) {
		t.Fatal("TTL reuse made network request")
		return nil, nil
	})})
	client.SetCache(cache, time.Hour)
	c := &collector{ctx: context.Background(), cfg: cfg(), client: client, seen: map[string]bool{}, blocked: map[string]bool{}, result: model.Result{SourceAttempts: map[string]int{}, NetworkRequests: map[string]int{}}}
	c.cfg.MaxDocs = 2
	for i := 0; i < 2; i++ {
		c.get("github", "https://api.github.com/repos/school/first/readme", nil, false)
	}
	if len(c.result.Reused) != 1 || c.full() {
		t.Fatalf("repeated key inflated reuse budget %+v", c.result)
	}
	c.get("github", "https://api.github.com/repos/school/second/readme", nil, false)
	if len(c.result.Reused) != 2 || !c.full() {
		t.Fatalf("unique cached key failed to consume slot %+v", c.result)
	}
}
