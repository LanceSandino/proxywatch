// Package sources provides bounded adapters for configured public discovery sources.
// Inputs: YouTube Data API credentials, queries, video IDs, and public comments.
// Outputs: description and comment evidence with quota and availability failures isolated.
package sources

import (
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"proxywatch/internal/fetch"
	"proxywatch/internal/secrets"
)

var videoIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{11}$`)

func (c *collector) youtube() {
	key := secrets.Get("YOUTUBE_API_KEY")
	if key == "" {
		c.fail("youtube", "YouTube Data API v3", "SKIPPED_MISSING_KEY", "YOUTUBE_API_KEY absent; enable official Data API v3 and configure a permitted quota in Cloud Console")
		return
	}
	call := func(path string, q url.Values) (fetch.Response, bool) {
		// Header, not ?key=, so the credential never appears in a URL.
		return c.get("youtube", "https://www.googleapis.com/youtube/v3/"+path+"?"+q.Encode(), map[string]string{"X-Goog-Api-Key": key}, false)
	}
	ids := append([]string{}, c.cfg.YouTubeIDs...)
	seen := map[string]bool{}
	for _, query := range c.queries() {
		if c.full() {
			return
		}
		c.result.Queries = append(c.result.Queries, "youtube: "+query)
		r, ok := call("search", url.Values{"part": {"snippet"}, "type": {"video"}, "q": {query}, "maxResults": {strconv.Itoa(c.cfg.MaxResults)}})
		if !ok {
			continue
		}
		var data struct {
			Items []struct {
				ID struct {
					VideoID string `json:"videoId"`
				} `json:"id"`
			} `json:"items"`
		}
		if c.decode("youtube", "search.list", r.Body, &data) {
			for i, item := range data.Items {
				if i >= c.cfg.MaxResults {
					break
				}
				ids = append(ids, item.ID.VideoID)
			}
		}
	}
	for _, id := range ids {
		if c.full() {
			return
		}
		if seen[id] {
			continue
		}
		seen[id] = true
		if !videoIDPattern.MatchString(id) {
			c.fail("youtube", "configured video", "INVALID_INPUT", "Video ID must contain eleven URL-safe characters")
			continue
		}
		r, ok := call("videos", url.Values{"part": {"snippet"}, "id": {id}})
		if !ok {
			continue
		}
		var videos struct {
			Items []struct {
				ID      string `json:"id"`
				Snippet struct {
					Title       string `json:"title"`
					Description string `json:"description"`
					PublishedAt string `json:"publishedAt"`
				} `json:"snippet"`
			} `json:"items"`
		}
		if !c.decode("youtube", "videos.list", r.Body, &videos) {
			continue
		}
		if len(videos.Items) == 0 {
			c.fail("youtube", "https://www.youtube.com/watch?v="+id, "SOURCE_UNAVAILABLE", "Video is deleted, private, or unavailable through the official API")
			continue
		}
		for _, video := range videos.Items {
			c.add("youtube", video.ID, "https://www.youtube.com/watch?v="+video.ID, "", video.Snippet.Title+"\n"+video.Snippet.Description, "video description; published_at="+video.Snippet.PublishedAt, "youtube:"+video.ID, r)
		}
		if !c.cfg.YouTubeComments {
			continue
		}
		pageToken := ""
		for page := 0; page < c.cfg.MaxCommentPages && !c.full(); page++ {
			q := url.Values{"part": {"snippet,replies"}, "videoId": {id}, "textFormat": {"plainText"}, "maxResults": {strconv.Itoa(c.cfg.MaxResults)}}
			if pageToken != "" {
				q.Set("pageToken", pageToken)
			}
			r, ok := call("commentThreads", q)
			if !ok {
				break
			}
			var threads struct {
				NextPageToken string `json:"nextPageToken"`
				Items         []struct {
					Snippet struct {
						TopLevelComment comment `json:"topLevelComment"`
						TotalReplyCount int     `json:"totalReplyCount"`
					} `json:"snippet"`
					Replies struct {
						Comments []comment `json:"comments"`
					} `json:"replies"`
				} `json:"items"`
			}
			if !c.decode("youtube", "commentThreads.list", r.Body, &threads) {
				break
			}
			for i, thread := range threads.Items {
				if i >= c.cfg.MaxResults {
					break
				}
				c.youtubeComment(id, thread.Snippet.TopLevelComment, r)
				if c.full() {
					break
				}
				if c.cfg.YouTubeReplies {
					for i, reply := range thread.Replies.Comments {
						if i >= c.cfg.MaxResults {
							break
						}
						c.youtubeComment(id, reply, r)
					}
					if !c.full() && thread.Snippet.TotalReplyCount > len(thread.Replies.Comments) {
						replyResponse, ok := call("comments", url.Values{"part": {"snippet"}, "parentId": {thread.Snippet.TopLevelComment.ID}, "textFormat": {"plainText"}, "maxResults": {strconv.Itoa(c.cfg.MaxResults)}})
						if ok {
							var replies struct {
								Items []comment `json:"items"`
							}
							if c.decode("youtube", "comments.list", replyResponse.Body, &replies) {
								for i, reply := range replies.Items {
									if i >= c.cfg.MaxResults {
										break
									}
									c.youtubeComment(id, reply, replyResponse)
								}
							}
						}
					}
				}
			}
			if threads.NextPageToken == "" {
				break
			}
			pageToken = threads.NextPageToken
		}
	}
}

type comment struct {
	ID      string `json:"id"`
	Snippet struct {
		Text        string `json:"textDisplay"`
		PublishedAt string `json:"publishedAt"`
	} `json:"snippet"`
}

func (c *collector) youtubeComment(video string, item comment, r fetch.Response) {
	if strings.TrimSpace(item.ID) == "" {
		return
	}
	c.add("youtube", fmt.Sprintf("%s/comment/%s", video, item.ID), "https://www.youtube.com/watch?v="+video+"&lc="+url.QueryEscape(item.ID), "", item.Snippet.Text, "public comment; published_at="+item.Snippet.PublishedAt, "youtube:"+video, r)
}
