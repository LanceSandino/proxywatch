package blocklist

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"proxywatch/internal/model"
)

func cand(host, root, class string, signals ...string) model.Candidate {
	return model.Candidate{Host: host, Registrable: root, Classification: class, ReviewStatus: "unreviewed",
		Evidence: []model.Evidence{{SourceURL: "https://src.example.net/list", OriginalURL: "https://" + host + "/", Signals: signals, DiscoveredAt: "2026-10-13T00:00:00Z", LastSeen: "2026-10-13T00:00:00Z"}}}
}

func pathCand(host string, urls map[string][]string) model.Candidate {
	c := model.Candidate{Host: host, Registrable: host, Classification: "needs_review", ReviewStatus: "unreviewed"}
	for u, sig := range urls {
		c.Evidence = append(c.Evidence, model.Evidence{SourceURL: "https://src.example.net/" + u, OriginalURL: u, Signals: sig, DiscoveredAt: "2026-10-12T00:00:00Z", LastSeen: "2026-10-13T00:00:00Z"})
	}
	return c
}

func hosts(es []Entry) []string {
	out := []string{}
	for _, e := range es {
		out = append(out, e.Host)
	}
	return out
}

func TestBuildTiers(t *testing.T) {
	cs := []model.Candidate{
		cand("play.proxysite.org", "proxysite.org", "likely_proxy", "explicit_proxy_link_context_unverified"),
		cand("bad.reviewed.org", "reviewed.org", "confirmed_unsafe"),
		cand("maybe.links.org", "links.org", "needs_review"),
		cand("listed.compilation.org", "compilation.org", "needs_review", "listed_in_proxy_link_compilation"),
		cand("listed.only.org", "only.org", "discovered"),
		// Benign control: a university Jitsi service in a proxy-adjacent page.
		cand("jitsi.math.uzh.ch", "uzh.ch", "likely_proxy", "benign_or_multiuse_context_requires_review"),
		cand("good.reviewed.org", "reviewed.org", "confirmed_benign"),
		cand("mail.google.com", "google.com", "likely_proxy"),
		cand("myproxy.pages.dev", "myproxy.pages.dev", "likely_proxy"),
	}
	cs[1].ReviewStatus, cs[6].ReviewStatus = "reviewed", "reviewed"
	r := Build(cs, time.Date(2026, 10, 14, 0, 0, 0, 0, time.UTC))
	if got := strings.Join(hosts(r.Block), ","); got != "play.proxysite.org,bad.reviewed.org,listed.compilation.org,myproxy.pages.dev" {
		t.Fatalf("block tier %s", got)
	}
	if got := strings.Join(hosts(r.Review), ","); got != "maybe.links.org,jitsi.math.uzh.ch" {
		t.Fatalf("review tier %s", got)
	}
	if got := strings.Join(hosts(r.Watch), ","); got != "listed.only.org" {
		t.Fatalf("watch tier %s", got)
	}
	if got := strings.Join(hosts(r.Excluded), ","); got != "good.reviewed.org,mail.google.com" {
		t.Fatalf("excluded %s", got)
	}
	if !strings.Contains(r.Block[3].Reason, "tenant subdomain") {
		t.Fatalf("tenant reason missing %+v", r.Block[2])
	}
	if r.GeneratedAt != "2026-10-14T00:00:00Z" || r.Block[0].Sources[0] != "https://src.example.net/list" {
		t.Fatalf("metadata lost %+v", r)
	}
}

func TestSharedPlatformsBecomePathRulesNotDNS(t *testing.T) {
	strong := []string{"shared_platform_path_scope", "explicit_proxy_link_context_unverified"}
	weak := []string{"shared_platform_path_scope"}
	cs := []model.Candidate{
		pathCand("sites.google.com", map[string][]string{
			"https://sites.google.com/view/n0repted/home":  strong,
			"https://sites.google.com/view/n0repted/games": weak,
			"https://sites.google.com/view/otherkid":       weak,
		}),
		pathCand("storage.googleapis.com", map[string][]string{"https://storage.googleapis.com/dogeub/index.html": strong}),
		pathCand("s3.us-east-1.amazonaws.com", map[string][]string{"https://s3.us-east-1.amazonaws.com/bucket/a/index.html": weak}),
	}
	r := Build(cs, time.Now())
	if len(r.Block)+len(r.Review)+len(r.Watch)+len(r.Excluded) != 0 {
		t.Fatalf("shared host leaked into DNS tiers %+v", r)
	}
	want := map[string]string{
		"sites.google.com/view/n0repted":    Block,
		"sites.google.com/view/otherkid":    Review,
		"storage.googleapis.com/dogeub":     Block,
		"s3.us-east-1.amazonaws.com/bucket": Review,
	}
	if len(r.Paths) != len(want) {
		t.Fatalf("paths %+v", r.Paths)
	}
	for _, p := range r.Paths {
		if want[p.Host+p.Prefix] != p.Tier {
			t.Errorf("%s%s tier %s", p.Host, p.Prefix, p.Tier)
		}
		if p.Enforcement == "" || len(p.Sources) == 0 {
			t.Errorf("rule lacks provenance %+v", p)
		}
	}
	for _, p := range r.Paths {
		if p.Prefix == "/view/n0repted" && (len(p.Examples) != 2 || p.FirstSeen != "2026-10-12T00:00:00Z") {
			t.Fatalf("tenant rule did not merge pages %+v", p)
		}
	}
}

func TestTenantPrefix(t *testing.T) {
	cases := [][3]string{
		{"sites.google.com", "/view/a/b/c", "/view/a"},
		{"docs.google.com", "/document/d/ID/edit", "/document/d/ID"},
		{"cdn.jsdelivr.net", "/gh/owner/repo@main/index.html", "/gh/owner/repo@main"},
		{"s3.amazonaws.com", "/bucket/x.html", "/bucket"},
		{"web.archive.org", "/web/2024/https://x", "/web/2024/https:/x"},
		{"sites.google.com", "/view", "/view"},
	}
	for _, c := range cases {
		if got := TenantPrefix(c[0], c[1]); got != c[2] {
			t.Errorf("TenantPrefix(%s,%s)=%s want %s", c[0], c[1], got, c[2])
		}
	}
}

func TestParentHints(t *testing.T) {
	cs := []model.Candidate{}
	for _, h := range []string{"a", "b", "c"} {
		cs = append(cs, cand(h+".freedns-zone.org", "freedns-zone.org", "likely_proxy"))
		cs = append(cs, cand(h+".onrender.com", h+".onrender.com", "likely_proxy"))
	}
	cs = append(cs, cand("x.small.org", "small.org", "likely_proxy"), cand("y.small.org", "small.org", "needs_review"))
	r := Build(cs, time.Now())
	if len(r.Parents) != 1 || r.Parents[0].Registrable != "freedns-zone.org" || r.Parents[0].FlaggedHosts != 3 || r.Parents[0].Regex != `(\.|^)freedns-zone\.org$` {
		t.Fatalf("parents %+v", r.Parents)
	}
}

func TestWriteFiles(t *testing.T) {
	dir := t.TempDir()
	cs := []model.Candidate{
		cand("play.proxysite.org", "proxysite.org", "likely_proxy"),
		cand("maybe.links.org", "links.org", "needs_review"),
		cand("listed.compilation.org", "compilation.org", "needs_review", "listed_in_proxy_link_compilation"),
		pathCand("sites.google.com", map[string][]string{"https://sites.google.com/view/kid": {"shared_platform_path_scope"}}),
	}
	files, err := Write(dir, Build(cs, time.Now()))
	if err != nil || len(files) != 7 {
		t.Fatalf("write %v %v", files, err)
	}
	read := func(n string) string {
		b, err := os.ReadFile(filepath.Join(dir, n))
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	block := read("pihole-block.txt")
	if !strings.Contains(block, "\nplay.proxysite.org\n") || strings.Contains(block, "maybe.links.org") || strings.Contains(block, "sites.google.com") {
		t.Fatalf("block file %q", block)
	}
	for _, line := range strings.Split(block, "\n") {
		if line != "" && !strings.HasPrefix(line, "#") && strings.ContainsAny(line, "/ ") {
			t.Fatalf("invalid adlist line %q", line)
		}
	}
	if !strings.Contains(read("path-rules.txt"), "# review: sites.google.com/view/kid") {
		t.Fatal("review path rule not commented")
	}
	if !strings.Contains(read("path-rules.csv"), "sites.google.com,/view/kid,review") {
		t.Fatal("path csv missing rule")
	}
	var back Result
	if err := json.Unmarshal([]byte(read("blocklist.json")), &back); err != nil || len(back.Paths) != 1 {
		t.Fatalf("json %v %+v", err, back)
	}
	if _, err := Write(filepath.Join(read("pihole-block.txt"), "x"), Result{}); err == nil {
		t.Fatal("invalid directory accepted")
	}
}

func TestSyntheticEvidenceNeverBlocks(t *testing.T) {
	c := cand("stdyhb.fixture-test.net", "fixture-test.net", "likely_proxy")
	c.Evidence[0].Synthetic = true
	r := Build([]model.Candidate{c}, time.Now())
	if len(r.Block) != 0 || len(r.Excluded) != 1 || !strings.Contains(r.Excluded[0].Reason, "synthetic") {
		t.Fatalf("synthetic candidate tiered %+v", r)
	}
}
