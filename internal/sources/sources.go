// Package sources retrieves only configured public source documents. Extracted
// destination URLs are data; no adapter follows links found in source content.
// Inputs: validated configuration, bounded queries, optional credentials, and guarded fetching.
// Outputs: source documents, structured skips/errors, cache reuse, and request statistics.
package sources

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"proxywatch/internal/config"
	"proxywatch/internal/fetch"
	"proxywatch/internal/model"
	"proxywatch/internal/secrets"
)

// Anonymous GitHub search is limited independently from its core API.
var githubSearchInterval = 6100 * time.Millisecond

type collector struct {
	ctx              context.Context
	cfg              config.Config
	client           *fetch.Client
	result           model.Result
	seen             map[string]bool
	blocked          map[string]bool
	lastGitHubSearch time.Time
}

// Collect isolates unavailable adapters and limits total accepted documents.
func Collect(ctx context.Context, cfg config.Config, client *fetch.Client, names []string) model.Result {
	c := &collector{ctx: ctx, cfg: cfg, client: client, seen: map[string]bool{}, blocked: map[string]bool{}, result: model.Result{SourceAttempts: map[string]int{}, NetworkRequests: map[string]int{}}}
	if cfg.MaxDocs < 1 {
		c.cfg.MaxDocs = 30
	}
	if cfg.MaxQueries < 1 {
		c.cfg.MaxQueries = 4
	}
	if cfg.MaxResults < 1 {
		c.cfg.MaxResults = 5
	}
	if cfg.MaxCommentPages < 1 {
		c.cfg.MaxCommentPages = 1
	}
	used := map[string]bool{}
	for _, name := range names {
		name = strings.TrimSpace(strings.ToLower(name))
		switch name {
		case "seeds":
			name = "publicpage"
		case "hn":
			name = "forum"
		case "web":
			name = "websearch"
		}
		if used[name] {
			continue
		}
		used[name] = true
		c.result.SourceAttempts[name] = 0
		callable := name == "github" || name == "publicpage" || name == "forum" || name == "bluesky" || name == "youtube" || name == "websearch" || name == "fixtures" || name == "flarum"
		if callable && c.full() {
			code, message := "SOURCE_NOT_ATTEMPTED_BUDGET", "Source was not attempted because the global document budget was exhausted; this is not a searched-source miss"
			if c.ctx.Err() != nil {
				code, message = "SOURCE_NOT_ATTEMPTED_CANCELLED", "Source was not attempted because discovery was cancelled"
			}
			c.fail(name, "adapter", code, message)
			if name == "youtube" && secrets.Get("YOUTUBE_API_KEY") == "" {
				c.youtube()
			}
			continue
		}
		switch name {
		case "github":
			c.github()
		case "publicpage", "seeds":
			c.publicpages()
		case "youtube":
			c.youtube()
		case "bluesky":
			c.bluesky()
		case "forum", "hn":
			c.forum()
		case "flarum":
			c.flarum()
		case "web", "websearch":
			c.websearch()
		case "fixtures":
			c.fixtures()
		case "reddit":
			c.fail("reddit", "official OAuth API", "SKIPPED_ACCESS_RESTRICTED", "No approved Reddit OAuth client configured; enable later with approved Data API access and retention policy")
		case "tiktok":
			c.fail("tiktok", "Research API", "DEFERRED_APPROVAL_REQUIRED", "General public discovery requires eligible approved Research API access; creator Display API is insufficient")
		case "instagram", "facebook", "x", "discord":
			c.fail(name, "official public API", "DEFERRED_APPROVAL_REQUIRED", "No authorized public discovery endpoint configured; enable only with approved official API access")
		default:
			c.fail(name, "adapter", "UNSUPPORTED_SOURCE", "Unknown source adapter")
		}
	}
	return c.result
}
func (c *collector) full() bool {
	return len(c.result.Documents)+len(c.result.Reused) >= c.cfg.MaxDocs || c.ctx.Err() != nil
}
func (c *collector) queries() []string {
	n := len(c.cfg.Queries)
	if n > c.cfg.MaxQueries {
		n = c.cfg.MaxQueries
	}
	return c.cfg.Queries[:n]
}
func (c *collector) fail(family, ref, code, message string) {
	c.result.Errors = append(c.result.Errors, model.SourceError{Family: family, Ref: ref, Code: code, Message: message})
}
func (c *collector) get(family, raw string, headers map[string]string, public bool) (fetch.Response, bool) {
	if c.blocked[family] {
		return fetch.Response{}, false
	}
	if family == "github" && strings.Contains(raw, "api.github.com/search/") {
		if delay := time.Until(c.lastGitHubSearch.Add(githubSearchInterval)); delay > 0 {
			timer := time.NewTimer(delay)
			select {
			case <-c.ctx.Done():
				timer.Stop()
				c.fail(family, safeURL(raw), "CANCELLED", "Discovery cancelled during GitHub search pacing")
				return fetch.Response{}, false
			case <-timer.C:
			}
		}
		c.lastGitHubSearch = time.Now()
	}
	c.result.Attempts++
	c.result.SourceAttempts[family]++
	var r fetch.Response
	var err error
	if public {
		r, err = c.client.PublicPage(fetch.WithNamespace(c.ctx, family), raw)
	} else {
		r, err = c.client.Get(fetch.WithNamespace(c.ctx, family), raw, headers)
	}
	ref := safeURL(raw)
	c.result.NetworkRequests[family] += r.NetworkRequests
	if err == nil && r.Status == 304 && r.Cached {
		key := "reuse|" + family + "|" + r.Key
		if !c.seen[key] {
			c.seen[key] = true
			c.result.Reused = append(c.result.Reused, model.Reuse{Family: family, Key: r.Key, RetrievedAt: r.RetrievedAt, CacheState: r.CacheState})
		}
		return r, false
	}
	if err != nil {
		code := "FETCH_FAILED"
		var fe *fetch.Error
		if errors.As(err, &fe) {
			code = strings.ToUpper(fe.Code)
			if fe.Status == 429 {
				c.blocked[family] = true
			}
		}
		c.fail(family, ref, code, safeError(err))
		return r, false
	}
	if r.Status < 200 || r.Status >= 300 {
		code := "HTTP_ERROR"
		if r.Status == 429 || r.Status == 403 {
			code = "RATE_OR_ACCESS_LIMIT"
		}
		c.fail(family, ref, code, fmt.Sprintf("Public source returned HTTP %d; respect provider access or quota restrictions", r.Status))
		return r, false
	}
	return r, true
}
func safeURL(raw string) string {
	u, e := url.Parse(raw)
	if e != nil {
		return "source"
	}
	u.User = nil
	q := u.Query()
	for k := range q {
		if strings.Contains(strings.ToLower(k), "key") || strings.Contains(strings.ToLower(k), "token") || strings.Contains(strings.ToLower(k), "secret") || strings.Contains(strings.ToLower(k), "password") || strings.Contains(strings.ToLower(k), "credential") || strings.Contains(strings.ToLower(k), "session") || strings.Contains(strings.ToLower(k), "email") || strings.Contains(strings.ToLower(k), "username") || strings.EqualFold(k, "sig") || strings.EqualFold(k, "auth") {
			q.Del(k)
		}
	}
	u.RawQuery = q.Encode()
	return u.String()
}

var errorURL = regexp.MustCompile(`https?://[^\s"<>]+`)

func safeError(err error) string {
	s := errorURL.ReplaceAllStringFunc(err.Error(), safeURL)
	for _, v := range secrets.Values() {
		s = strings.ReplaceAll(s, v, "[REDACTED]")
	}
	if len(s) > 300 {
		s = s[:300]
	}
	return s
}
func (c *collector) add(family, id, raw, query, text, field, independence string, r fetch.Response) {
	if c.full() || strings.TrimSpace(text) == "" {
		return
	}
	key := family + "|" + id
	if c.seen[key] {
		return
	}
	c.seen[key] = true
	h := sha256.Sum256([]byte(text))
	retrievedAt := r.RetrievedAt
	if retrievedAt.IsZero() {
		retrievedAt = time.Now().UTC()
	}
	c.result.Documents = append(c.result.Documents, model.Document{FetchKey: r.Key, Family: family, ExternalID: id, URL: safeURL(raw), Query: query, Text: text, Field: field, IndependenceKey: independence, RetrievedAt: retrievedAt, ContentHash: hex.EncodeToString(h[:]), Cached: r.Cached})
}
func (c *collector) decode(family, ref string, b []byte, v any) bool {
	if err := json.Unmarshal(b, v); err != nil {
		c.fail(family, ref, "INVALID_RESPONSE", "Public API returned malformed JSON")
		return false
	}
	return true
}

func (c *collector) publicpages() {
	for _, page := range c.cfg.Pages {
		if c.full() {
			return
		}
		r, ok := c.get("publicpage", page, nil, true)
		if ok {
			if scriptShell(string(r.Body)) {
				c.fail("publicpage", page, "SOURCE_UNAVAILABLE_JS_REQUIRED", "Source is a JavaScript-dependent profile/app shell without discussion evidence; use its permitted public API adapter")
				continue
			}
			c.add("publicpage", page, page, "", string(r.Body), "public page", page, r)
		}
	}
}

// Exact topic phrases keep broad provider searches from ingesting unrelated
// school website maintenance and generic reverse-proxy engineering issues.
var topicPhrase = regexp.MustCompile(`(?i)\b(unblockers?|unblocked[ -]+games?|school[ -]+prox(?:y|ies)|proxy[ -]+(?:links?|lists?|mirrors?|sites?)|chromebook[ -]+(?:bypass|prox(?:y|ies)))\b`)
var namedProxyContext = regexp.MustCompile(`(?is)\b(interstellar|ultraviolet|rammerhead|scramjet|study[ -]?hub|doge[ -]?unblocker)\b.{0,120}\b(prox(?:y|ies)|unblock(?:er|ed|ing)?|bypass)\b|\b(prox(?:y|ies)|unblock(?:er|ed|ing)?|bypass)\b.{0,120}\b(interstellar|ultraviolet|rammerhead|scramjet|study[ -]?hub|doge[ -]?unblocker)\b`)
var managedBypass = regexp.MustCompile(`(?i)\b(goguardian|chromebook)\b[^\n]{0,100}\b(prox(?:y|ies)|unblock(?:er|ed|ing)?|bypass)\b|\b(prox(?:y|ies)|unblock(?:er|ed|ing)?|bypass)\b[^\n]{0,100}\b(goguardian|chromebook)\b`)

func topicalEvidence(text string) bool {
	return topicPhrase.MatchString(text) || managedBypass.MatchString(text) || namedProxyContext.MatchString(text)
}

var repoPattern = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$`)

func (c *collector) github() {
	headers := map[string]string{"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
	if token := secrets.Get("GITHUB_TOKEN"); token != "" {
		headers["Authorization"] = "Bearer " + token
	}
	fetched := map[string]bool{}
	readme := func(repo, query string) {
		if c.full() || fetched[repo] {
			return
		}
		fetched[repo] = true
		if !repoPattern.MatchString(repo) {
			c.fail("github", "configured repository", "INVALID_INPUT", "Repository must be owner/name")
			return
		}
		endpoint := "https://api.github.com/repos/" + repo + "/readme"
		r, ok := c.get("github", endpoint, headers, false)
		if !ok {
			return
		}
		var doc struct {
			Content  string `json:"content"`
			Encoding string `json:"encoding"`
			HTMLURL  string `json:"html_url"`
			SHA      string `json:"sha"`
		}
		if !c.decode("github", endpoint, r.Body, &doc) {
			return
		}
		if doc.Encoding != "base64" {
			c.fail("github", endpoint, "UNSUPPORTED_ENCODING", "README is not base64 text")
			return
		}
		body, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(doc.Content, "\n", ""))
		if err != nil {
			c.fail("github", endpoint, "INVALID_RESPONSE", "README base64 is malformed")
			return
		}
		if doc.HTMLURL == "" {
			doc.HTMLURL = "https://github.com/" + repo + "/blob/HEAD/README.md"
		}
		if !topicalEvidence(string(body)) {
			c.fail("github", doc.HTMLURL, "SKIPPED_IRRELEVANT_CONTEXT", "README has no explicit school proxy, unblocker, unblocked games, or named proxy project context")
			return
		}
		c.add("github", repo+"/README@"+doc.SHA, doc.HTMLURL, query, string(body), "README", "github:"+repo, r)
	}
	for _, repo := range c.cfg.GitHubRepos {
		readme(repo, "")
	}
	for _, query := range c.queries() {
		if c.full() {
			return
		}
		c.result.Queries = append(c.result.Queries, "github: "+query)
		endpoint := "https://api.github.com/search/repositories?q=" + url.QueryEscape(query) + "&per_page=" + strconv.Itoa(c.cfg.MaxResults)
		r, ok := c.get("github", endpoint, headers, false)
		if ok {
			var data struct {
				Items []struct {
					FullName string `json:"full_name"`
				} `json:"items"`
			}
			if c.decode("github", endpoint, r.Body, &data) {
				for i, item := range data.Items {
					if i >= c.cfg.MaxResults {
						break
					}
					readme(item.FullName, query)
				}
			}
		}
		if c.full() {
			return
		}
		endpoint = "https://api.github.com/search/issues?q=" + url.QueryEscape(query+" is:issue") + "&per_page=" + strconv.Itoa(c.cfg.MaxResults)
		r, ok = c.get("github", endpoint, headers, false)
		if !ok {
			continue
		}
		var issues struct {
			Items []struct {
				ID            int64  `json:"id"`
				Title         string `json:"title"`
				Body          string `json:"body"`
				HTMLURL       string `json:"html_url"`
				RepositoryURL string `json:"repository_url"`
			} `json:"items"`
		}
		if c.decode("github", endpoint, r.Body, &issues) {
			for i, item := range issues.Items {
				if i >= c.cfg.MaxResults {
					break
				}
				if !topicalEvidence(item.Title + "\n" + item.Body) {
					c.fail("github", item.HTMLURL, "SKIPPED_IRRELEVANT_CONTEXT", "Issue has no explicit school proxy, unblocker, unblocked games, or named proxy project context")
					continue
				}
				c.add("github", fmt.Sprint(item.ID), item.HTMLURL, query, item.Title+"\n"+item.Body, "issue", strings.Replace(item.RepositoryURL, "https://api.github.com/repos/", "github:", 1), r)
			}
		}
	}
}
func (c *collector) bluesky() {
	for _, query := range c.queries() {
		if c.full() {
			return
		}
		c.result.Queries = append(c.result.Queries, "bluesky: "+query)
		endpoint := "https://api.bsky.app/xrpc/app.bsky.feed.searchPosts?q=" + url.QueryEscape(query) + "&limit=" + strconv.Itoa(c.cfg.MaxResults)
		r, ok := c.get("bluesky", endpoint, nil, false)
		if !ok {
			continue
		}
		var data struct {
			Posts []struct {
				URI    string `json:"uri"`
				Record struct {
					Text string `json:"text"`
				} `json:"record"`
			} `json:"posts"`
		}
		if !c.decode("bluesky", endpoint, r.Body, &data) {
			continue
		}
		for i, p := range data.Posts {
			if i >= c.cfg.MaxResults {
				break
			}
			if !strings.HasPrefix(p.URI, "at://") {
				continue
			}
			parts := strings.Split(strings.TrimPrefix(p.URI, "at://"), "/")
			if len(parts) != 3 || parts[0] == "" || parts[1] != "app.bsky.feed.post" || parts[2] == "" || strings.ContainsAny(parts[0]+parts[2], " ?#@") {
				continue
			}
			canonical := "https://bsky.app/profile/" + url.PathEscape(parts[0]) + "/post/" + url.PathEscape(parts[2])
			c.add("bluesky", p.URI, canonical, query, p.Record.Text, "post", "bluesky:"+p.URI, r)
		}
	}
}
func (c *collector) forum() {
	seen := map[string]bool{}
	for _, query := range c.queries() {
		if c.full() {
			return
		}
		c.result.Queries = append(c.result.Queries, "forum: "+query)
		endpoint := "https://hn.algolia.com/api/v1/search?query=" + url.QueryEscape(`"`+query+`"`) + "&tags=comment&advancedSyntax=true&typoTolerance=false&removeWordsIfNoResults=none&hitsPerPage=" + strconv.Itoa(c.cfg.MaxResults)
		r, ok := c.get("forum", endpoint, nil, false)
		if !ok {
			continue
		}
		var results struct {
			Hits []struct {
				ID string `json:"objectID"`
			} `json:"hits"`
		}
		if !c.decode("forum", endpoint, r.Body, &results) {
			continue
		}
		for i, hit := range results.Hits {
			if i >= c.cfg.MaxResults {
				break
			}
			if c.full() {
				return
			}
			if seen[hit.ID] {
				continue
			}
			seen[hit.ID] = true
			if _, err := strconv.ParseUint(hit.ID, 10, 64); err != nil {
				continue
			}
			source := "https://hacker-news.firebaseio.com/v0/item/" + hit.ID + ".json"
			r, ok := c.get("forum", source, nil, false)
			if !ok {
				continue
			}
			var item struct {
				ID      int64  `json:"id"`
				Text    string `json:"text"`
				Deleted bool   `json:"deleted"`
				Dead    bool   `json:"dead"`
			}
			if !c.decode("forum", source, r.Body, &item) {
				continue
			}
			if item.Deleted || item.Dead || item.ID == 0 {
				c.fail("forum", source, "SOURCE_UNAVAILABLE", "Public item is deleted, dead, or unavailable")
				continue
			}
			c.add("forum", hit.ID, "https://news.ycombinator.com/item?id="+hit.ID, query, item.Text, "public comment", "hn:forum", r)
		}
	}
}
func (c *collector) websearch() {
	if c.cfg.SearchEndpoint == "" {
		c.fail("websearch", "provider", "SKIPPED_NOT_CONFIGURED", "Configure an approved web search endpoint and SEARCH_API_KEY; HTML search-result scraping is not supported")
		return
	}
	key := secrets.Get("SEARCH_API_KEY")
	if key == "" {
		c.fail("websearch", "provider", "SKIPPED_MISSING_KEY", "SEARCH_API_KEY absent; configure a permitted Brave-compatible JSON API")
		return
	}
	endpoint, err := url.Parse(c.cfg.SearchEndpoint)
	if err != nil || endpoint.Scheme != "https" || endpoint.User != nil {
		c.fail("websearch", "provider", "INVALID_INPUT", "Search endpoint must be HTTPS without embedded credentials")
		return
	}
	for _, query := range c.queries() {
		if c.full() {
			return
		}
		u := *endpoint
		q := u.Query()
		q.Set("q", query)
		q.Set("count", strconv.Itoa(c.cfg.MaxResults))
		u.RawQuery = q.Encode()
		c.result.Queries = append(c.result.Queries, "websearch: "+query)
		r, ok := c.get("websearch", u.String(), map[string]string{"Accept": "application/json", "X-Subscription-Token": key}, false)
		if !ok {
			continue
		}
		var results struct {
			Web struct {
				Results []struct {
					URL         string `json:"url"`
					Description string `json:"description"`
				} `json:"results"`
			} `json:"web"`
		}
		if !c.decode("websearch", safeURL(u.String()), r.Body, &results) {
			continue
		}
		for i, hit := range results.Web.Results {
			if i >= c.cfg.MaxResults {
				break
			}
			if c.full() {
				return
			}
			if !c.approvedPage(hit.URL) {
				continue
			}
			page, ok := c.get("websearch", hit.URL, nil, true)
			if ok {
				c.add("websearch", hit.URL, hit.URL, query, string(page.Body), "approved public page", hit.URL, page)
			}
		}
	}
}
func (c *collector) approvedPage(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.User != nil {
		return false
	}
	for _, host := range c.cfg.AllowedHosts {
		if strings.EqualFold(host, u.Hostname()) {
			return true
		}
	}
	return false
}
