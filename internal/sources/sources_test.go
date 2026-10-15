package sources

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"proxywatch/internal/config"
	"proxywatch/internal/fetch"
)

func TestMain(m *testing.M) { githubSearchInterval = time.Millisecond; os.Exit(m.Run()) }

type transport func(*http.Request) (*http.Response, error)

func (f transport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func response(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}
}
func cfg() config.Config {
	return config.Config{MaxDocs: 10, MaxQueries: 1, MaxResults: 2, MaxCommentPages: 1}
}
func TestFixturesOfflineAndBound(t *testing.T) {
	called := false
	client := fetch.NewForTest(&http.Client{Transport: transport(func(r *http.Request) (*http.Response, error) {
		called = true
		return nil, fmt.Errorf("unexpected network")
	})})
	c := cfg()
	c.MaxDocs = 2
	result := Collect(context.Background(), c, client, []string{"fixtures"})
	if called || len(result.Documents) != 2 || result.Attempts != 0 {
		t.Fatalf("offline fixtures: %+v", result)
	}
	for _, doc := range result.Documents {
		if !doc.Synthetic || !strings.Contains(doc.Text, "SYNTHETIC") {
			t.Fatal("unlabelled fixture")
		}
	}
}
func TestGitHubReadmeAndIssuesEvidence(t *testing.T) {
	c := cfg()
	c.Queries = []string{"school proxy"}
	c.GitHubRepos = []string{"school/list"}
	calls := map[string]int{}
	client := fetch.NewForTest(&http.Client{Transport: transport(func(r *http.Request) (*http.Response, error) {
		calls[r.URL.Path]++
		switch r.URL.Path {
		case "/repos/school/list/readme":
			return response(200, fmt.Sprintf(`{"content":%q,"encoding":"base64","html_url":"https://github.com/school/list/blob/main/README.md","sha":"abc123"}`, base64.StdEncoding.EncodeToString([]byte("Proxy links https://alpha.proxywatch-test.net")))), nil
		case "/search/repositories":
			return response(200, `{"items":[{"full_name":"school/list"}]}`), nil
		case "/search/issues":
			return response(200, `{"items":[{"id":17,"title":"Proxy mirror","body":"https://beta.proxywatch-test.net","html_url":"https://github.com/school/list/issues/1","repository_url":"https://api.github.com/repos/school/list"}]}`), nil
		}
		t.Fatalf("unexpected URL %s", r.URL)
		return nil, nil
	})})
	result := Collect(context.Background(), c, client, []string{"github"})
	if len(result.Errors) > 0 || len(result.Documents) != 2 || calls["/repos/school/list/readme"] != 1 {
		t.Fatalf("result %+v calls %+v", result, calls)
	}
	if !strings.Contains(result.Documents[0].ExternalID, "abc123") || result.Documents[0].URL != "https://github.com/school/list/blob/main/README.md" || result.Documents[1].IndependenceKey != "github:school/list" {
		t.Fatalf("missing provenance: %+v", result.Documents)
	}
}
func TestProviderFailuresAreIsolatedAndKeysRedacted(t *testing.T) {
	t.Setenv("YOUTUBE_API_KEY", "")
	t.Setenv("GITHUB_TOKEN", "")
	t.Setenv("SEARCH_API_KEY", "")
	c := cfg()
	c.Queries = []string{"school proxy"}
	client := fetch.NewForTest(&http.Client{Transport: transport(func(r *http.Request) (*http.Response, error) {
		if r.URL.Host == "api.github.com" {
			return response(429, `quota`), nil
		}
		if r.URL.Host != "api.bsky.app" {
			t.Fatalf("Bluesky must use the keyless AppView host, got %s", r.URL.Host)
		}
		return response(200, `{"posts":[{"uri":"at://did:plc:abc/app.bsky.feed.post/p1","record":{"text":"Proxy https://alpha.proxywatch-test.net"},"author":{"handle":"do-not-store"}}]}`), nil
	})})
	result := Collect(context.Background(), c, client, []string{"youtube", "github", "bluesky", "reddit"})
	if len(result.Documents) != 1 || result.Documents[0].Family != "bluesky" {
		t.Fatalf("source isolation %+v", result)
	}
	if strings.Contains(result.Documents[0].Text, "do-not-store") {
		t.Fatal("profile harvested")
	}
	var quota, missing bool
	for _, e := range result.Errors {
		quota = quota || strings.Contains(e.Code, "RATE")
		missing = missing || e.Code == "SKIPPED_MISSING_KEY"
	}
	if !quota || !missing {
		t.Fatalf("errors %+v", result.Errors)
	}
	t.Setenv("YOUTUBE_API_KEY", "secret-api-key")
	s := safeError(fmt.Errorf("GET https://www.googleapis.com/a?key=secret-api-key&part=snippet failed secret-api-key"))
	if strings.Contains(s, "secret-api-key") || strings.Contains(s, "key=") {
		t.Fatal("secret exposed:", s)
	}
}
func TestYouTubeDescriptionCommentsAndReplies(t *testing.T) {
	t.Setenv("YOUTUBE_API_KEY", "synthetic-secret")
	c := cfg()
	c.YouTubeIDs = []string{"abcdefghijk", "abcdefghijk"}
	c.YouTubeComments = true
	c.YouTubeReplies = true
	calls := map[string]int{}
	client := fetch.NewForTest(&http.Client{Transport: transport(func(r *http.Request) (*http.Response, error) {
		// The key travels only in a header, never in a URL that could be logged.
		if r.Header.Get("X-Goog-Api-Key") != "synthetic-secret" || r.URL.Query().Has("key") || strings.Contains(r.URL.String(), "synthetic-secret") {
			t.Fatal("API key missing from header or present in URL")
		}
		calls[r.URL.Path]++
		switch r.URL.Path {
		case "/youtube/v3/videos":
			return response(200, `{"items":[{"id":"abcdefghijk","snippet":{"title":"School proxies","description":"https://alpha.proxywatch-test.net","publishedAt":"2026-01-01T00:00:00Z"}}]}`), nil
		case "/youtube/v3/commentThreads":
			return response(200, `{"items":[{"snippet":{"topLevelComment":{"id":"c1","snippet":{"textDisplay":"Proxy https://beta.proxywatch-test.net","authorDisplayName":"private-author"}},"totalReplyCount":2},"replies":{"comments":[{"id":"r1","snippet":{"textDisplay":"https://gamma.proxywatch-test.net"}}]}}]}`), nil
		case "/youtube/v3/comments":
			return response(200, `{"items":[{"id":"r1","snippet":{"textDisplay":"https://gamma.proxywatch-test.net"}},{"id":"r2","snippet":{"textDisplay":"https://delta.proxywatch-test.net"}}]}`), nil
		}
		t.Fatalf("unexpected request %s", r.URL.Path)
		return nil, nil
	})})
	result := Collect(context.Background(), c, client, []string{"youtube"})
	if len(result.Documents) != 4 || len(result.Errors) > 0 || calls["/youtube/v3/videos"] != 1 {
		t.Fatalf("result %+v calls %+v", result, calls)
	}
	for _, doc := range result.Documents {
		if strings.Contains(doc.Text, "private-author") || strings.Contains(doc.URL, "synthetic-secret") || doc.IndependenceKey != "youtube:abcdefghijk" {
			t.Fatalf("bad evidence %+v", doc)
		}
	}
}
func TestForumFetchesActualItems(t *testing.T) {
	c := cfg()
	c.Queries = []string{"Rammerhead proxy"}
	client := fetch.NewForTest(&http.Client{Transport: transport(func(r *http.Request) (*http.Response, error) {
		if r.URL.Host == "hn.algolia.com" {
			return response(200, `{"hits":[{"objectID":"123"},{"objectID":"123"}]}`), nil
		}
		if r.URL.Path != "/v0/item/123.json" {
			t.Fatal(r.URL.String())
		}
		return response(200, `{"id":123,"text":"School proxy <a href=\"https://alpha.proxywatch-test.net\">mirror</a>","by":"do-not-store"}`), nil
	})})
	result := Collect(context.Background(), c, client, []string{"forum"})
	if len(result.Documents) != 1 || result.SourceAttempts["forum"] != 2 || result.Documents[0].URL != "https://news.ycombinator.com/item?id=123" || strings.Contains(result.Documents[0].Text, "do-not-store") {
		t.Fatalf("result %+v", result)
	}
}
func TestPublicPageHonorsRobots(t *testing.T) {
	c := cfg()
	c.Pages = []string{"https://forum.proxywatch-test.net/private", "https://forum.proxywatch-test.net/public"}
	calls := []string{}
	client := fetch.NewForTest(&http.Client{Transport: transport(func(r *http.Request) (*http.Response, error) {
		calls = append(calls, r.URL.Path)
		if r.URL.Path == "/robots.txt" {
			return response(200, "User-agent: *\nDisallow: /private\n"), nil
		}
		if r.URL.Path == "/private" {
			t.Fatal("robots denied path fetched")
		}
		return response(200, `<p>proxy https://alpha.proxywatch-test.net</p>`), nil
	})})
	result := Collect(context.Background(), c, client, []string{"publicpage"})
	if len(result.Documents) != 1 || len(result.Errors) != 1 || len(calls) != 2 {
		t.Fatalf("result %+v calls %+v", result, calls)
	}
}

func TestMalformedInputsAndJSON(t *testing.T) {
	t.Setenv("YOUTUBE_API_KEY", "test-key")
	c := cfg()
	c.GitHubRepos = []string{"../../private"}
	c.YouTubeIDs = []string{"invalid video!"}
	c.Queries = []string{"proxy"}
	client := fetch.NewForTest(&http.Client{Transport: transport(func(r *http.Request) (*http.Response, error) { return response(200, "{malformed"), nil })})
	result := Collect(context.Background(), c, client, []string{"github", "youtube", "bluesky", "forum", "unknown"})
	invalid, responseErrors := 0, 0
	for _, e := range result.Errors {
		if e.Code == "INVALID_INPUT" {
			invalid++
		}
		if e.Code == "INVALID_RESPONSE" {
			responseErrors++
		}
	}
	if invalid != 2 || responseErrors < 4 || len(result.Documents) != 0 {
		t.Fatalf("result %+v", result)
	}
}
func TestRateLimitStopsFamilyOnly(t *testing.T) {
	c := cfg()
	c.MaxQueries = 3
	c.Queries = []string{"proxy", "school", "mirrors"}
	calls := 0
	client := fetch.NewForTest(&http.Client{Transport: transport(func(r *http.Request) (*http.Response, error) { calls++; return response(429, "quota"), nil })})
	result := Collect(context.Background(), c, client, []string{"github", "bluesky"})
	if calls != 2 || len(result.Errors) != 2 {
		t.Fatalf("quota handling result %+v calls %d", result, calls)
	}
}
func TestSearchResultsAreNotEvidenceOrDestinations(t *testing.T) {
	t.Setenv("SEARCH_API_KEY", "test-key")
	c := cfg()
	c.SearchEndpoint = "https://api.search.brave.com/res/v1/web/search"
	c.Queries = []string{"school proxy"}
	c.AllowedHosts = []string{"approved.proxywatch-test.net"}
	var fetched []string
	client := fetch.NewForTest(&http.Client{Transport: transport(func(r *http.Request) (*http.Response, error) {
		fetched = append(fetched, r.URL.Host+r.URL.Path)
		switch r.URL.Path {
		case "/res/v1/web/search":
			return response(200, `{"web":{"results":[{"url":"https://untrusted.proxywatch-test.net/path","description":"https://snippet.proxywatch-test.net"},{"url":"https://approved.proxywatch-test.net/list","description":"https://snippet.proxywatch-test.net"}]}}`), nil
		case "/robots.txt":
			return response(404, ""), nil
		case "/list":
			return response(200, "Proxy mirror https://actual.proxywatch-test.net"), nil
		}
		t.Fatal("unexpected URL", r.URL.String())
		return nil, nil
	})})
	result := Collect(context.Background(), c, client, []string{"websearch"})
	if len(result.Documents) != 1 || strings.Contains(result.Documents[0].Text, "snippet") || strings.Contains(strings.Join(fetched, ","), "untrusted") {
		t.Fatalf("result %+v fetched %+v", result, fetched)
	}
}
func TestProviderResultCaps(t *testing.T) {
	c := cfg()
	c.Queries = []string{"proxy"}
	c.MaxResults = 1
	client := fetch.NewForTest(&http.Client{Transport: transport(func(r *http.Request) (*http.Response, error) {
		return response(200, `{"posts":[{"uri":"at://did:plc:abc/app.bsky.feed.post/1","record":{"text":"https://one.proxywatch-test.net"}},{"uri":"at://did:plc:abc/app.bsky.feed.post/2","record":{"text":"https://two.proxywatch-test.net"}}]}`), nil
	})})
	result := Collect(context.Background(), c, client, []string{"bluesky"})
	if len(result.Documents) != 1 {
		t.Fatalf("result cap ignored %+v", result)
	}
}

func TestGitHubTopicFilter(t *testing.T) {
	for _, text := range []string{"School proxy links https://one.proxywatch-test.net", "Interstellar\nA modern proxy for school browsing", "Ultraviolet highly sophisticated proxy", "unblocked games at https://one.proxywatch-test.net", "GoGuardian bypass links", "Proxy mirror https://one.proxywatch-test.net"} {
		if !topicalEvidence(text) {
			t.Fatal("relevant document rejected:", text)
		}
	}
	for _, text := range []string{"School website maintenance: update calendar, fix broken links, and configure the HTTP reverse proxy.", "Ultraviolet light science experiments at a school. " + strings.Repeat("Other educational material. ", 10) + "Configure the network reverse proxy.", "School links and student learning resources https://university.proxywatch-test.net"} {
		if topicalEvidence(text) {
			t.Fatal("irrelevant document admitted:", text)
		}
	}
}
func TestBudgetSkippedSourceIsExplicitAndAliasesDeduplicate(t *testing.T) {
	c := cfg()
	c.MaxDocs = 1
	client := fetch.NewForTest(&http.Client{Transport: transport(func(r *http.Request) (*http.Response, error) {
		t.Fatal("network after budget exhausted")
		return nil, nil
	})})
	result := Collect(context.Background(), c, client, []string{"fixtures", "forum", "hn", "bluesky", "seeds", "publicpage"})
	counts := map[string]int{}
	for _, e := range result.Errors {
		if e.Code == "SOURCE_NOT_ATTEMPTED_BUDGET" {
			counts[e.Family]++
		}
	}
	if counts["forum"] != 1 || counts["bluesky"] != 1 || counts["publicpage"] != 1 || result.Attempts != 0 {
		t.Fatalf("missing budget source outcomes %+v", result)
	}
}
func TestGitHubIrrelevantIssueExcluded(t *testing.T) {
	c := cfg()
	c.Queries = []string{"school proxy links"}
	client := fetch.NewForTest(&http.Client{Transport: transport(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/search/repositories" {
			return response(200, `{"items":[]}`), nil
		}
		return response(200, `{"items":[{"id":17,"title":"School website maintenance","body":"Update calendar links and configure the HTTP reverse proxy. https://university.proxywatch-test.net","html_url":"https://github.com/school/site/issues/1","repository_url":"https://api.github.com/repos/school/site"}]}`), nil
	})})
	result := Collect(context.Background(), c, client, []string{"github"})
	if len(result.Documents) != 0 || len(result.Errors) != 1 || result.Errors[0].Code != "SKIPPED_IRRELEVANT_CONTEXT" {
		t.Fatalf("irrelevant evidence cataloged %+v", result)
	}
}
