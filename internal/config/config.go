// Package config loads and validates bounded discovery settings.
// Inputs: YAML configuration and environment-selected paths.
// Outputs: normalized query sets, source allowlists, and operational limits.
package config

import (
	"fmt"
	"gopkg.in/yaml.v3"
	"io"
	"os"
	"regexp"
	"strings"
)

type Config struct {
	ExpandQueries   bool                `yaml:"expand_queries" json:"expand_queries"`
	FlarumURL       string              `yaml:"flarum_url" json:"flarum_url"`
	FlarumQueries   []string            `yaml:"flarum_queries" json:"flarum_queries"`
	QuerySets       map[string][]string `yaml:"query_sets" json:"query_sets"`
	RatesMS         map[string]int      `yaml:"rates_ms" json:"rates_ms"`
	Queries         []string            `yaml:"queries" json:"queries"`
	AllowedHosts    []string            `yaml:"allowed_hosts" json:"allowed_hosts"`
	Pages           []string            `yaml:"pages" json:"pages"`
	GitHubRepos     []string            `yaml:"github_repos" json:"github_repos"`
	YouTubeIDs      []string            `yaml:"youtube_ids" json:"youtube_ids"`
	MaxDocs         int                 `yaml:"max_docs" json:"max_docs"`
	MaxQueries      int                 `yaml:"max_queries" json:"max_queries"`
	MaxResults      int                 `yaml:"max_results" json:"max_results"`
	TimeoutSeconds  int                 `yaml:"timeout_seconds" json:"timeout_seconds"`
	MaxBytes        int64               `yaml:"max_bytes" json:"max_bytes"`
	IntervalMS      int                 `yaml:"interval_ms" json:"interval_ms"`
	YouTubeComments bool                `yaml:"youtube_comments" json:"youtube_comments"`
	YouTubeReplies  bool                `yaml:"youtube_replies" json:"youtube_replies"`
	MaxCommentPages int                 `yaml:"max_comment_pages" json:"max_comment_pages"`
	CacheHours      int                 `yaml:"cache_hours" json:"cache_hours"`
	StaleDays       int                 `yaml:"stale_days" json:"stale_days"`
	SearchEndpoint  string              `yaml:"search_endpoint" json:"search_endpoint"`
}

func Load(path string) (Config, error) {
	c := Config{MaxDocs: 30, MaxQueries: 4, MaxResults: 5, TimeoutSeconds: 20, MaxBytes: 2097152, IntervalMS: 1000, MaxCommentPages: 1, StaleDays: 30}
	b, e := os.ReadFile(path)
	if e != nil {
		return c, e
	}
	d := yaml.NewDecoder(strings.NewReader(string(b)))
	d.KnownFields(true)
	if e = d.Decode(&c); e != nil {
		return c, e
	}
	var extra any
	if e = d.Decode(&extra); e != io.EOF {
		return c, fmt.Errorf("configuration must be a single YAML document")
	}
	if c.MaxDocs < 1 || c.MaxDocs > 500 || c.MaxQueries < 1 || c.MaxQueries > 50 || c.MaxResults < 1 || c.MaxResults > 50 || c.TimeoutSeconds < 1 || c.TimeoutSeconds > 120 || c.MaxBytes < 1 || c.MaxBytes > 10485760 || c.IntervalMS < 0 || c.IntervalMS > 60000 || c.MaxCommentPages < 1 || c.MaxCommentPages > 5 || c.CacheHours < 0 || c.StaleDays < 1 {
		return c, fmt.Errorf("invalid bounded crawl settings")
	}
	for _, ms := range c.RatesMS {
		if ms < 0 || ms > 60000 {
			return c, fmt.Errorf("invalid host rate interval")
		}
	}
	for _, h := range c.AllowedHosts {
		if !regexp.MustCompile(`^[a-zA-Z0-9]+([.-][a-zA-Z0-9]+)*$`).MatchString(h) {
			return c, fmt.Errorf("allowlist requires exact hostnames")
		}
	}
	return c, nil
}
