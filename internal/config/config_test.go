package config

import (
	"os"
	"path/filepath"
	"testing"
)

func loadText(t *testing.T, text string) (Config, error) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.yaml")
	if e := os.WriteFile(p, []byte(text), 0600); e != nil {
		t.Fatal(e)
	}
	return Load(p)
}
func TestDefaultsAndStrictFields(t *testing.T) {
	c, e := loadText(t, "queries: [school proxy links]\nallowed_hosts: [api.github.com]\n")
	if e != nil {
		t.Fatal(e)
	}
	if c.MaxDocs != 30 || c.MaxBytes != 2097152 || c.MaxCommentPages != 1 || c.TimeoutSeconds != 20 || c.StaleDays != 30 {
		t.Fatalf("defaults changed: %+v", c)
	}
	if _, e = loadText(t, "typo_setting: true\n"); e == nil {
		t.Fatal("unknown field accepted")
	}
	if _, e = loadText(t, "max_docs: 20\nmax_docs: 40\n"); e == nil {
		t.Fatal("duplicate key accepted")
	}
}
func TestCrawlSettingsBounds(t *testing.T) {
	for _, text := range []string{"max_docs: 0", "max_docs: 501", "max_queries: 0", "max_queries: 51", "max_results: 0", "max_results: 51", "timeout_seconds: 0", "timeout_seconds: 121", "max_bytes: 0", "max_bytes: 10485761", "interval_ms: -1", "interval_ms: 60001", "max_comment_pages: 0", "max_comment_pages: 6", "cache_hours: -1", "stale_days: 0"} {
		t.Run(text, func(t *testing.T) {
			if _, e := loadText(t, text+"\n"); e == nil {
				t.Fatalf("unsafe setting accepted: %s", text)
			}
		})
	}
}
func TestAllowlistRequiresExactHostnames(t *testing.T) {
	for _, host := range []string{"''", "'https://example.com'", "'*.example.com'", "'example.com/path'", "'example.com:443'", "'example.com evil.com'", "\"example.com\\t\"", "\"example.com\\n\"", "'example.com?query'", "'example.com#fragment'", "'user@example.com'"} {
		t.Run(host, func(t *testing.T) {
			if _, e := loadText(t, "allowed_hosts: ["+host+"]\n"); e == nil {
				t.Fatalf("non-host allowlist value accepted: %s", host)
			}
		})
	}
}
func TestMultipleDocumentsRejected(t *testing.T) {
	if _, e := loadText(t, "max_docs: 10\n---\nmax_docs: 500\n"); e == nil {
		t.Fatal("silently ignored second configuration document")
	}
}
func TestUnreadableConfigAndMalformedYAML(t *testing.T) {
	if _, e := Load(filepath.Join(t.TempDir(), "absent")); e == nil {
		t.Fatal("missing config accepted")
	}
	if _, e := loadText(t, "queries: [unfinished\n"); e == nil {
		t.Fatal("malformed YAML accepted")
	}
}
