// Package sources provides bounded adapters for configured public discovery sources.
// Inputs: permitted Flarum discussion queries and independently fetched first posts.
// Outputs: sanitized discussion evidence without author or profile metadata.
package sources

import (
	"html"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

var numericID = regexp.MustCompile(`^[1-9][0-9]*$`)

type flarumResource struct {
	Type       string `json:"type"`
	ID         string `json:"id"`
	Attributes struct {
		Title       string `json:"title"`
		ContentHTML string `json:"contentHtml"`
		Number      int    `json:"number"`
		IsHidden    bool   `json:"isHidden"`
	} `json:"attributes"`
	Relationships struct {
		FirstPost struct {
			Data struct {
				Type string `json:"type"`
				ID   string `json:"id"`
			} `json:"data"`
		} `json:"firstPost"`
		Discussion struct {
			Data struct {
				Type string `json:"type"`
				ID   string `json:"id"`
			} `json:"data"`
		} `json:"discussion"`
	} `json:"relationships"`
}

// flarum searches only public first posts. Search matches in subsequent posts
// remain a documented coverage gap. Included users are never parsed or retained.
func (c *collector) flarum() {
	if c.cfg.FlarumURL == "" {
		c.fail("flarum", "forum origin", "SKIPPED_NOT_CONFIGURED", "Configure an approved public Flarum origin and flarum_queries")
		return
	}
	u, err := url.Parse(c.cfg.FlarumURL)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") || !c.approvedPage(c.cfg.FlarumURL) {
		c.fail("flarum", "forum origin", "INVALID_INPUT", "Flarum origin must be an allowlisted HTTPS source origin without credentials, query or path")
		return
	}
	origin := u.Scheme + "://" + u.Host
	queries := c.cfg.FlarumQueries
	if len(queries) == 0 {
		c.fail("flarum", origin, "SKIPPED_NOT_CONFIGURED", "Configure bounded public discussion search terms in flarum_queries")
		return
	}
	if len(queries) > c.cfg.MaxQueries {
		queries = queries[:c.cfg.MaxQueries]
	}
	fetched := map[string]bool{}
	for _, query := range queries {
		if c.full() {
			return
		}
		c.result.Queries = append(c.result.Queries, "flarum: "+query)
		endpoint := origin + "/api/discussions?" + url.Values{"filter[q]": {query}, "page[limit]": {strconv.Itoa(c.cfg.MaxResults)}, "include": {"firstPost"}}.Encode()
		r, ok := c.get("flarum", endpoint, nil, true)
		if !ok {
			continue
		}
		var list struct {
			Data []flarumResource `json:"data"`
		}
		if !c.decode("flarum", endpoint, r.Body, &list) {
			continue
		}
		for i, discussion := range list.Data {
			if i >= c.cfg.MaxResults || c.full() {
				break
			}
			postID := discussion.Relationships.FirstPost.Data.ID
			if discussion.Type != "discussions" || !numericID.MatchString(discussion.ID) || discussion.Relationships.FirstPost.Data.Type != "posts" || !numericID.MatchString(postID) {
				c.fail("flarum", endpoint, "INVALID_RESPONSE", "Discussion lacks a valid public numeric first-post reference")
				continue
			}
			if fetched[postID] {
				continue
			}
			fetched[postID] = true
			// Explicit discussion-only includes avoid unnecessary author/profile relationships; only
			// contentHtml and minimal IDs are accepted from the independent response.
			postURL := origin + "/api/posts/" + postID + "?include=discussion"
			postResponse, ok := c.get("flarum", postURL, nil, true)
			if !ok {
				continue
			}
			var post struct {
				Data flarumResource `json:"data"`
			}
			if !c.decode("flarum", postURL, postResponse.Body, &post) {
				continue
			}
			if post.Data.Type != "posts" || post.Data.ID != postID {
				c.fail("flarum", postURL, "INVALID_RESPONSE", "Post endpoint did not return its requested public first post")
				continue
			}
			if post.Data.Attributes.IsHidden || strings.TrimSpace(post.Data.Attributes.ContentHTML) == "" {
				c.fail("flarum", postURL, "SOURCE_UNAVAILABLE", "First post is hidden or has no public content")
				continue
			}
			if related := post.Data.Relationships.Discussion.Data.ID; related != "" && related != discussion.ID {
				c.fail("flarum", postURL, "INVALID_RESPONSE", "Post belongs to a different discussion")
				continue
			}
			text := "<h1>" + html.EscapeString(discussion.Attributes.Title) + "</h1>\n" + post.Data.Attributes.ContentHTML
			c.add("flarum", postID, origin+"/d/"+discussion.ID, query, text, "public first post", "flarum:"+u.Hostname(), postResponse)
		}
	}
}

func scriptShell(body string) bool {
	lower := strings.ToLower(body)
	// Flarum user-profile shells contain navigation, metadata and asset URLs but
	// no discussion body. These must not be counted as searched discussion docs.
	return strings.Contains(lower, "flarum") && strings.Contains(lower, "loading...") && (strings.Contains(lower, "enable javascript") || strings.Contains(lower, "javascript enabled")) && !strings.Contains(lower, "contenthtml") && !strings.Contains(lower, "post-body")
}
