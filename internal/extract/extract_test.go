package extract

import (
	"strings"
	"testing"
	"unicode/utf8"

	"proxywatch/internal/model"
)

func TestNormalize(t *testing.T) {
	tests := []struct{ raw, host, root string }{
		{"HTTPS://Play.SchoolLinks.org.:443/path?q=secret#fragment", "play.schoollinks.org", "schoollinks.org"},
		{"(https://Play.SchoolLinks.org/path).", "play.schoollinks.org", "schoollinks.org"},
		{"BÜCHER.de", "xn--bcher-kva.de", "xn--bcher-kva.de"},
		{"https://one.schoollinks.co.uk:8443/", "one.schoollinks.co.uk", "schoollinks.co.uk"},
		{"https://project.github.io/", "project.github.io", "project.github.io"},
		{"//play.schoollinks.org/path", "play.schoollinks.org", "schoollinks.org"},
		{"https://person:password@play.schoollinks.org/", "play.schoollinks.org", "schoollinks.org"},
	}
	for _, tt := range tests {
		t.Run(tt.raw, func(t *testing.T) {
			h, r, err := Normalize(tt.raw)
			if err != nil || h != tt.host || r != tt.root {
				t.Fatalf("Normalize = %q %q %v", h, r, err)
			}
		})
	}
	for _, raw := range []string{"", "URL...", "localhost", "printer.local", "proxy.internal", "foo.invalid", "fake.unknownsuffix", "example.com", "sub.example.org", "https://127.0.0.1", "http://[::1]", "http://169.254.169.254", "https://192.168.1.1", "http://10.0.0.1", "ftp://valid.org", "javascript:alert(1)", "mailto:person@valid.org", "user@valid.org", "bad_label.valid.org", "-bad.valid.org", "valid.org:65536", "https://valid.org:port", "https://valid.org\\@169.254.169.254", "https://com", "https://foo..org"} {
		t.Run(raw, func(t *testing.T) {
			if _, _, err := Normalize(raw); err == nil {
				t.Fatalf("accepted invalid input %q", raw)
			}
		})
	}
}

func TestSanitizeAndRedact(t *testing.T) {
	got := SanitizeURL("https://alice:password@UPPER.schoollinks.org:443/list?api_key=secret#private")
	if got != "https://upper.schoollinks.org/list" {
		t.Fatal(got)
	}
	got = Redact("See https://alice:password@upper.schoollinks.org/list?api_key=secret#private person@valid.org @student token=SECRET username=alice")
	for _, secret := range []string{"alice", "password", "secret", "private", "person@", "student", "SECRET"} {
		if strings.Contains(got, secret) {
			t.Fatalf("redaction leaked %q in %q", secret, got)
		}
	}
	if !strings.Contains(got, "https://upper.schoollinks.org/list") {
		t.Fatalf("lost citation %q", got)
	}
	got = Redact("bare.schoollinks.org/path?private=SECRETVALUE#fragment Authorization: Bearer CREDENTIALVALUE")
	if strings.Contains(got, "SECRETVALUE") || strings.Contains(got, "CREDENTIALVALUE") || strings.Contains(got, "fragment") {
		t.Fatalf("leaked bare link or authorization: %q", got)
	}
}

func TestDocumentMarkdownAndDedup(t *testing.T) {
	doc := model.Document{Field: "readme", Text: "# Interstellar proxy links\n[One](https://Play.SchoolLinks.org:443/path?token=secret)\nhttps://play.schoollinks.org/path#fragment\nNew mirror: second.schoollinks.org\nURL...\nhttps://example.com\n"}
	hits, discarded := Document(doc)
	if len(hits) != 2 || discarded != 1 {
		t.Fatalf("got %d hits, %d discarded: %+v", len(hits), discarded, hits)
	}
	for _, hit := range hits {
		if hit.Classification != "likely_proxy" || hit.Excerpt == "" || hit.Field != "readme" || hit.Registrable != "schoollinks.org" {
			t.Fatalf("bad hit %+v", hit)
		}
		if strings.Contains(hit.URL, "token") || strings.Contains(hit.Excerpt, "secret") {
			t.Fatalf("leaked token %+v", hit)
		}
	}
}

func TestHTMLOnlyPublicBodyLinks(t *testing.T) {
	doc := model.Document{Field: "html", Text: `<!doctype html><html><head><script>https://hidden.schoollinks.org</script></head><body><nav><a href="https://nav.schoollinks.org">Navigation</a></nav><ul><li>Interstellar proxy links: <a href="https://play.schoollinks.org?secret=x&amp;token=y">Play</a></li><li><a href="https://other.schoollinks.org">Unrelated</a></li></ul><script>https://script.schoollinks.org</script><p>person@private.org ftp://blocked.schoollinks.org https://example.net</p><a href="javascript:alert(1)">Run</a></body></html>`}
	hits, _ := Document(doc)
	if len(hits) != 2 {
		t.Fatalf("got %+v", hits)
	}
	if hits[0].Host != "play.schoollinks.org" || hits[0].Classification != "likely_proxy" || strings.Contains(hits[0].URL, "?") {
		t.Fatalf("bad evidence %+v", hits[0])
	}
	if hits[1].Host != "other.schoollinks.org" || hits[1].Classification != "discovered" {
		t.Fatalf("overclassified %+v", hits[1])
	}
}

func TestNegativeUniversityAndSEOControls(t *testing.T) {
	// Synthetic held-out examples are tests only, never live inputs or query seeds.
	doc := model.Document{Synthetic: true, Field: "description", Text: "GoGuardian proxy links: https://stdyhb.jurematoz.com\nUniversity of Zurich legitimate Jitsi meeting service: https://jitsi.math.uzh.ch\n"}
	hits, _ := Document(doc)
	if len(hits) != 2 || hits[0].Host != "stdyhb.jurematoz.com" || hits[1].Host != "jitsi.math.uzh.ch" {
		t.Fatalf("got %+v", hits)
	}
	if hits[1].Classification != "needs_review" || hits[1].Score != 0 {
		t.Fatalf("benign control failed %+v", hits[1])
	}
	seo := model.Document{Text: "proxy unblocked goguardian interstellar rammerhead scramjet " + strings.Repeat("SEO keywords ", 40) + "Our unrelated contact is https://contact.schoollinks.org"}
	result, _ := Document(seo)
	if len(result) != 1 || result[0].Classification != "discovered" {
		t.Fatalf("SEO stuffing inflated confidence %+v", result)
	}
	for _, hit := range append(hits, result...) {
		if hit.Classification == "confirmed_unsafe" || hit.Classification == "confirmed_proxy" {
			t.Fatal("automatic verification")
		}
	}
}

func TestSocialNavigationAndUnsupportedSchemes(t *testing.T) {
	doc := model.Document{Text: "# School proxy links\nFollow https://youtube.com/channel/a and https://github.com/org/repo\nContact user@valid.org\nftp://files.valid.org\nCDN dependency: https://cdn.jsdelivr.net/file.js\ninvalid_label.good.org\nhttp://127.0.0.1\n"}
	hits, _ := Document(doc)
	if len(hits) != 0 {
		t.Fatalf("irrelevant or invalid hosts extracted %+v", hits)
	}
}

func TestExactIdentityAndExcerptBounds(t *testing.T) {
	doc := model.Document{Text: strings.Repeat("😀 public ", 30) + "https://a.schoollinks.org/?token=secret\nhttps://b.schoollinks.org/\nhttps://schoollinks.org/"}
	hits, _ := Document(doc)
	if len(hits) != 3 {
		t.Fatalf("collapsed exact hosts %+v", hits)
	}
	for _, hit := range hits {
		if utf8.RuneCountInString(hit.Excerpt) > 160 || !utf8.ValidString(hit.Excerpt) || strings.Contains(hit.Excerpt, "secret") {
			t.Fatalf("invalid excerpt %+v", hit)
		}
	}
}

func TestHTMLHeadingAndProtocolRelative(t *testing.T) {
	hits, _ := Document(model.Document{Text: `<h2>Interstellar proxy links</h2><ul><li><a href="//play.schoollinks.org/path">Play</a></li></ul>`})
	if len(hits) != 1 || hits[0].Classification != "likely_proxy" || hits[0].URL != "https://play.schoollinks.org/path" {
		t.Fatalf("lost heading/link evidence %+v", hits)
	}
}

func TestKeywordListDoesNotVerifyProxy(t *testing.T) {
	hits, _ := Document(model.Document{Text: "tags: school proxy links goguardian https://contact.schoollinks.org\n"})
	if len(hits) != 1 || hits[0].Classification == "likely_proxy" {
		t.Fatalf("keyword tags inflated confidence %+v", hits)
	}
}

func TestRelativeMarkdownFilesAreNotDomains(t *testing.T) {
	hits, _ := Document(model.Document{Text: "# Proxy links\nAGENTS.md mirrors.md privacy.md 2026-new-plan.md\n[Policy](docs/privacy.md) /local/mirrors.md ../guides/plan.md\n[Host](https://real.md/path)\n[Mirror](https://play.schoollinks.org)"})
	if len(hits) != 2 || hits[0].Host != "real.md" || hits[1].Host != "play.schoollinks.org" {
		t.Fatalf("bare local files became domains: %+v", hits)
	}
}

func TestMarkdownAdjacentLinksAndEncodedPaths(t *testing.T) {
	hits, _ := Document(model.Document{Text: "# Proxy links\n[Mirror](https://play.schoollinks.org/path)[Another](https://other.schoollinks.org/next)\n[Encoded](https://encoded.schoollinks.org/a%28b%29)\n[Deploy](https://railway.app/new/template)\n[Badge](https://binbashbanana.github.io/deploy-buttons/railway.svg)"})
	if len(hits) != 3 {
		t.Fatalf("bad markdown extraction: %+v", hits)
	}
	for _, hit := range hits {
		if strings.Contains(hit.URL, "][") || strings.Contains(hit.URL, "Another") || strings.Contains(hit.URL, "https:") && strings.Count(hit.URL, "https:") != 1 {
			t.Fatalf("merged adjacent links: %+v", hit)
		}
	}
	if hits[2].Host != "encoded.schoollinks.org" || hits[2].URL != "https://encoded.schoollinks.org/a%28b%29" {
		t.Fatalf("lost encoded legitimate path: %+v", hits[2])
	}
}

func TestCDNPrivateSuffixAndRepositoryReferences(t *testing.T) {
	hits, _ := Document(model.Document{Text: "# School proxy links\nMake your own proxy link: https://github.com/org/tutorial\nhttps://avatars.githubusercontent.com/u/123\nhttps://camo.githubusercontent.com/abcdef\nhttps://user-images.githubusercontent.com/picture.png\nhttps://img.shields.io/badge/alive-green\nhttps://actual-mirror.github.io/"})
	if len(hits) != 1 || hits[0].Host != "actual-mirror.github.io" {
		t.Fatalf("CDN/tutorial links became candidates: %+v", hits)
	}
}

func TestInlineHTMLRetainsSiblingContext(t *testing.T) {
	doc := model.Document{Text: `I’m working on Neon Arcade (<a href="https://neonarc.app/">https://neonarc.app/</a>) — a browser-based arcade platform with a curated collection of free unblocked games and remastered classics. ` + strings.Repeat("More irrelevant description. ", 20)}
	hits, _ := Document(doc)
	if len(hits) != 1 || hits[0].Host != "neonarc.app" || hits[0].Classification != "needs_review" || !strings.Contains(hits[0].Excerpt, "unblocked games") || !strings.Contains(hits[0].Excerpt, "https://neonarc.app/") {
		t.Fatalf("lost public sibling evidence: %+v", hits)
	}
}

func TestDeploymentDonationForumChromeAndSelfLinks(t *testing.T) {
	doc := model.Document{URL: "https://scope.flarum.cloud/d/123", Text: "# Interstellar proxy links\nDeploy to https://glitch.com or https://replit.com or https://app.koyeb.com or https://app.cyclic.sh\nContributors: https://contrib.rocks\nDonate https://www.patreon.com/myproject\nHosting by https://freeflarum.com\nSelf thread: https://scope.flarum.cloud/d/456\nMirror https://working.repl.co\nMirror https://working.koyeb.app\nMirror https://working.glitch.me\nDeploy instructions: https://deployment.schoollinks.org\n"}
	hits, _ := Document(doc)
	if len(hits) != 4 {
		t.Fatalf("support/deployment chrome became candidates %+v", hits)
	}
	for _, hit := range hits {
		if hit.Host == "deployment.schoollinks.org" && hit.Classification == "likely_proxy" {
			t.Fatalf("deployment instructions imply proxy verification %+v", hit)
		}
	}
	for i, host := range []string{"working.repl.co", "working.koyeb.app", "working.glitch.me"} {
		if hits[i].Host != host {
			t.Fatalf("discarded actual hosted mirrors %+v", hits)
		}
	}
}

func TestWildcardICANNTLDNormalization(t *testing.T) {
	for _, raw := range []string{"school.reference.com.np", "school.reference.org.np", "portal.reference.net.np", "school.reference.co.ck"} {
		host, root, e := Normalize(raw)
		if e != nil || host != raw || root == "" {
			t.Fatalf("valid wildcard-TLD hostname rejected: %s %s %v", raw, host, e)
		}
	}
	for _, raw := range []string{"com.np", "co.ck", "fake.unknownsuffix", "learnmore.neeb.wt", "main.svg"} {
		if _, _, e := Normalize(raw); e == nil {
			t.Fatalf("reserved/public suffix or unknown TLD accepted: %s", raw)
		}
	}
}

func TestSharedPlatformPathsAreKeptAsPathScope(t *testing.T) {
	// Shared hosts cannot be DNS-blocked, but their proxy paths must be kept
	// so a later path-level control has evidence to act on.
	doc := model.Document{Text: "# Working proxy links\n" +
		"https://sites.google.com/view/n0repted/home\n" +
		"https://storage.googleapis.com/dogeub/index.html\n" +
		"https://s3.us-east-1.amazonaws.com/somebucket/index.html\n" +
		"https://sites.google.com/\n" +
		"https://github.com/titaniumnetwork-dev/Ultraviolet\n" +
		"https://storage.googleapis.com/dogeub/app.js\n"}
	hits, _ := Document(doc)
	got := map[string]model.Hit{}
	for _, h := range hits {
		got[h.URL] = h
	}
	for _, url := range []string{"https://sites.google.com/view/n0repted/home", "https://storage.googleapis.com/dogeub/index.html", "https://s3.us-east-1.amazonaws.com/somebucket/index.html"} {
		h, ok := got[url]
		if !ok {
			t.Fatalf("shared-platform proxy path %s dropped; got %+v", url, hits)
		}
		// The shared host itself must never look like a likely proxy.
		if h.Classification != "needs_review" || !hasSignal(h, "shared_platform_path_scope") || !hasSignal(h, "explicit_proxy_link_context_unverified") {
			t.Fatalf("path hit not scoped %+v", h)
		}
	}
	if len(hits) != 3 {
		t.Fatalf("bare shared host, repository citation or asset kept: %+v", hits)
	}
	benign := model.Document{Text: "Proxy project documentation hosted at https://sites.google.com/view/docs-site\n"}
	if hits, _ := Document(benign); len(hits) != 0 {
		t.Fatalf("benign shared path kept %+v", hits)
	}
}

func hasSignal(h model.Hit, s string) bool {
	for _, v := range h.Signals {
		if v == s {
			return true
		}
	}
	return false
}

func TestProxyLinkCompilationSignal(t *testing.T) {
	// Long curated lists lose heading context after a few lines; the document
	// itself being a proxy-link compilation is the signal for every entry.
	var b strings.Builder
	b.WriteString("# Unblocked proxy links\n")
	for i := 0; i < 14; i++ {
		b.WriteString("- https://site" + string(rune('a'+i)) + ".listhost.org\n")
	}
	b.WriteString("- https://jitsi.listhost.org\n")
	hits, _ := Document(model.Document{Text: b.String()})
	if len(hits) != 15 {
		t.Fatalf("got %d hits", len(hits))
	}
	last := hits[13] // beyond the heading window
	if last.Classification != "needs_review" || !hasSignal(last, "listed_in_proxy_link_compilation") {
		t.Fatalf("compilation entry not marked %+v", last)
	}
	if j := hits[14]; hasSignal(j, "listed_in_proxy_link_compilation") || !hasSignal(j, "benign_or_multiuse_context_requires_review") {
		t.Fatalf("benign control upgraded %+v", j)
	}
	// A short page, or a long page without proxy vocabulary, is not a compilation.
	var plain strings.Builder
	plain.WriteString("# Bakery partners\n")
	for i := 0; i < 14; i++ {
		plain.WriteString("- https://shop" + string(rune('a'+i)) + ".bakery.org\n")
	}
	for _, h := range func() []model.Hit { h, _ := Document(model.Document{Text: plain.String()}); return h }() {
		if hasSignal(h, "listed_in_proxy_link_compilation") || h.Classification != "discovered" {
			t.Fatalf("non-proxy list upgraded %+v", h)
		}
	}
	short, _ := Document(model.Document{Text: "# Proxy links\n" + strings.Repeat("filler line\n", 20) + "https://lone.listhost.org\n"})
	if len(short) != 1 || hasSignal(short[0], "listed_in_proxy_link_compilation") {
		t.Fatalf("short page upgraded %+v", short)
	}
}
