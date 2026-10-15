// Package extract treats source content as untrusted data. It never fetches links.
// Inputs: bounded text, Markdown, HTML, and URL-like source values.
// Outputs: normalized exact hostnames and sanitized local evidence excerpts.
package extract

import (
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"golang.org/x/net/html"
	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
	"proxywatch/internal/model"
	"proxywatch/internal/platform"
)

var (
	urlPattern        = regexp.MustCompile(`(?i)(?:[a-z][a-z0-9+.-]*://|//)[^\s<>"'\[\]()` + "`" + `]+`)
	barePattern       = regexp.MustCompile(`(?:[\p{L}\p{N}](?:[\p{L}\p{N}_-]*[\p{L}\p{N}])?\.)+[\p{L}][\p{L}\p{N}-]{1,62}(?::[0-9]+)?(?:[/?#][^\s<>"'\[\]()` + "`" + `]*)?`)
	emailPattern      = regexp.MustCompile(`[\p{L}\p{N}_.+%-]+@[\p{L}\p{N}.-]+\.[\p{L}]{2,}`)
	usernamePattern   = regexp.MustCompile(`(^|[\s/(])@[\p{L}\p{N}_.-]+`)
	secretPattern     = regexp.MustCompile(`(?i)\b(?:api[_-]?key|access[_-]?token|token|password|secret|authorization|username|user)\s*[:=]\s*[^\s,;]+`)
	bearerPattern     = regexp.MustCompile(`(?i)\b(?:bearer|basic)\s+[a-z0-9._~+/=-]+`)
	strongPattern     = regexp.MustCompile(`(?i)\b(?:proxy|unblocker)\s+(?:links?|mirrors?|sites?|websites?|list)\b|\b(?:interstellar|ultraviolet|rammerhead|scramjet|study\s?hub|doge\s+unblocker)\s+(?:proxy|links?)\b|\b(?:working|new|school)\s+proxy\b`)
	proxyPattern      = regexp.MustCompile(`(?i)\b(?:proxy|unblocker|interstellar|ultraviolet|rammerhead|scramjet|study\s?hub|goguardian|unblocked)\b`)
	benignPattern     = regexp.MustCompile(`(?i)\b(?:university|universit[aä]t|jitsi|video conferencing|meeting service|legitimate|documentation|dependency|license|cdn|tracking|analytics)\b`)
	seoPattern        = regexp.MustCompile(`(?i)\b(?:tags|keywords|seo)\s*[:=]`)
	navigationPattern = regexp.MustCompile(`(?i)\b(?:subscribe|follow|social|channel|donate|donation|repository|source code|documentation|community|join|install|dependency|badge)\b`)
	supportPattern    = regexp.MustCompile(`(?i)\b(?:deploy|deployment|donate|donation|support us|sponsor|contributors?|patreon)\b`)
)

// Normalize validates and returns the exact DNS hostname and its PSL registrable
// domain. A registrable domain is metadata, never the candidate identity.
func Normalize(raw string) (string, string, error) {
	raw = clean(raw)
	if raw == "" || strings.ContainsAny(raw, "\\ \t\r\n") {
		return "", "", fmt.Errorf("invalid URL or hostname")
	}
	if strings.HasPrefix(raw, "//") {
		raw = "https:" + raw
	} else if !strings.Contains(raw, "://") {
		if strings.Contains(raw, "@") || strings.HasPrefix(strings.ToLower(raw), "mailto:") {
			return "", "", fmt.Errorf("email is not a candidate")
		}
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Opaque != "" || u.Host == "" {
		return "", "", fmt.Errorf("invalid or unsupported URL")
	}
	if p := u.Port(); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			return "", "", fmt.Errorf("invalid port")
		}
	}
	host, err := idna.Lookup.ToASCII(strings.TrimSuffix(strings.ToLower(u.Hostname()), "."))
	if err != nil || len(host) > 253 || net.ParseIP(host) != nil {
		return "", "", fmt.Errorf("invalid DNS hostname")
	}
	labels := strings.Split(host, ".")
	if len(labels) < 2 {
		return "", "", fmt.Errorf("hostname must be public FQDN")
	}
	for _, label := range labels {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", "", fmt.Errorf("invalid DNS label")
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return "", "", fmt.Errorf("invalid DNS label")
			}
		}
	}
	// Unknown and special-use TLDs must not turn internal hostnames into candidates.
	// Probe a child label: wildcard-only ICANN rules such as *.np and
	// *.ck do not mark the bare TLD itself as ICANN in x/net/publicsuffix.
	if _, icann := publicsuffix.PublicSuffix("psl-validation." + labels[len(labels)-1]); !icann {
		return "", "", fmt.Errorf("unknown or reserved suffix")
	}
	root, err := publicsuffix.EffectiveTLDPlusOne(host)
	if err != nil && platform.Classify(host) == platform.SharedPath {
		// Path-style storage endpoints are PSL suffixes themselves; keep them so
		// their tenant paths can be recorded, never as registrable domains.
		root, err = host, nil
	}
	if err != nil || root == "example.com" || root == "example.org" || root == "example.net" {
		return "", "", fmt.Errorf("reserved or nonregistrable hostname")
	}
	return host, root, nil
}

func clean(s string) string {
	return strings.Trim(strings.TrimSpace(html.UnescapeString(s)), "<>\"'`[](){}.,;!?")
}

// SanitizeURL removes credentials, query strings, fragments and explicit identity
// path segments. Paths remain useful for attributing citations.
func SanitizeURL(raw string) string {
	raw = clean(raw)
	if strings.HasPrefix(raw, "//") {
		raw = "https:" + raw
	} else if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return "[invalid URL]"
	}
	u.User, u.RawQuery, u.Fragment, u.RawFragment, u.ForceQuery = nil, "", "", "", false
	u.Scheme = strings.ToLower(u.Scheme)
	host, err := idna.Lookup.ToASCII(strings.TrimSuffix(strings.ToLower(u.Hostname()), "."))
	if err != nil {
		return "[invalid URL]"
	}
	port := u.Port()
	if port != "" && !(port == "80" && u.Scheme == "http" || port == "443" && u.Scheme == "https") {
		u.Host = net.JoinHostPort(host, port)
	} else {
		u.Host = host
		if strings.Contains(host, ":") {
			u.Host = "[" + host + "]"
		}
	}
	u.Path = emailPattern.ReplaceAllString(u.Path, "[redacted]")
	u.Path = usernamePattern.ReplaceAllString(u.Path, "${1}[redacted]")
	u.RawPath = ""
	return u.String()
}

// Redact applies bounded evidence privacy rules without retaining full documents.
func Redact(s string) string {
	s = urlPattern.ReplaceAllStringFunc(s, SanitizeURL)
	s = emailPattern.ReplaceAllString(s, "[redacted email]")
	// Bare links also carry private query strings. Work backwards to retain the
	// original match offsets and avoid reprocessing already sanitized URLs.
	urls := urlPattern.FindAllStringIndex(s, -1)
	bare := barePattern.FindAllStringIndex(s, -1)
	for i := len(bare) - 1; i >= 0; i-- {
		ix := bare[i]
		overlaps := false
		for _, u := range urls {
			if ix[0] < u[1] && ix[1] > u[0] {
				overlaps = true
				break
			}
		}
		if !overlaps && strings.ContainsAny(s[ix[0]:ix[1]], "?#") {
			s = s[:ix[0]] + SanitizeURL(s[ix[0]:ix[1]]) + s[ix[1]:]
		}
	}
	s = usernamePattern.ReplaceAllString(s, "${1}[redacted user]")
	s = bearerPattern.ReplaceAllString(s, "[redacted authorization]")
	s = secretPattern.ReplaceAllString(s, "[redacted credential]")
	return strings.Join(strings.Fields(s), " ")
}

type occurrence struct{ raw, context, field string }

// Document extracts candidates and counts invalid/irrelevant occurrences. It
// deliberately has no network access and does not resolve URL shorteners.
func Document(doc model.Document) ([]model.Hit, int) {
	var items []occurrence
	if looksHTML(doc.Text) {
		items = htmlOccurrences(doc.Text, doc.Field)
	} else {
		items = textOccurrences(doc.Text, doc.Field)
	}
	var hits []model.Hit
	discarded := 0
	seen := map[string]int{}
	sourceHost, _, _ := Normalize(doc.URL)
	for _, item := range items {
		host, root, err := Normalize(item.raw)
		if err != nil {
			discarded++
			continue
		}
		strong := strongPattern.MatchString(item.context) && !seoPattern.MatchString(item.context)
		benign := benignPattern.MatchString(item.context) || strings.HasPrefix(host, "jitsi.")
		if platform.Classify(host) == platform.SharedPath {
			if hit, ok := sharedPathHit(doc, item, host, root, strong, benign); ok {
				hits, seen = appendHit(hits, seen, hit)
				continue
			}
			discarded++
			continue
		}
		if host == sourceHost || alwaysInfrastructure(host, item.raw) || infrastructure(host, root) && (!strong || benign || navigationPattern.MatchString(item.context)) {
			discarded++
			continue
		}
		classification, score := "discovered", 0
		signals := []string{"hostname_in_public_source", "destination_not_visited"}
		if proxyPattern.MatchString(item.context) {
			classification, score = "needs_review", 15
			signals = append(signals, "proxy_related_context_is_not_verification")
		}
		if strong && !benign && !supportPattern.MatchString(item.context) {
			classification, score = "likely_proxy", 30
			signals = append(signals, "explicit_proxy_link_context_unverified")
		}
		if benign {
			classification, score = "needs_review", 0
			signals = append(signals, "benign_or_multiuse_context_requires_review")
		}
		sanitized := SanitizeURL(item.raw)
		excerpt := bounded(Redact(item.context), 160)
		hit := model.Hit{Host: host, Registrable: root, URL: sanitized, Excerpt: excerpt, Field: item.field, Signals: signals, Classification: classification, Score: score}
		hits, seen = appendHit(hits, seen, hit)
	}
	markCompilation(doc, hits)
	return hits, discarded
}

// MinCompilationHosts is the distinct-host count at which a proxy-themed
// document is treated as a curated link list rather than a passing mention.
const MinCompilationHosts = 10

// markCompilation upgrades context-free entries of a proxy-link compilation to
// needs_review. Being listed is evidence for review, never verification.
func markCompilation(doc model.Document, hits []model.Hit) {
	opening := doc.Text
	if len(opening) > 600 {
		opening = opening[:600]
	}
	if !proxyPattern.MatchString(doc.Query) && !proxyPattern.MatchString(opening) {
		return
	}
	hosts := map[string]bool{}
	for _, h := range hits {
		hosts[h.Host] = true
	}
	if len(hosts) < MinCompilationHosts {
		return
	}
	for i := range hits {
		if hits[i].Classification == "discovered" {
			hits[i].Classification, hits[i].Score = "needs_review", 15
			hits[i].Signals = append(hits[i].Signals, "listed_in_proxy_link_compilation")
		}
	}
}

// appendHit keeps one sighting per exact host and sanitized URL.
func appendHit(hits []model.Hit, seen map[string]int, hit model.Hit) ([]model.Hit, map[string]int) {
	key := hit.Host + "\x00" + hit.URL
	if old, ok := seen[key]; ok {
		// Repeated navigation/body links do not create redundant sightings.
		if hits[old].Score < hit.Score {
			hits[old] = hit
		}
		return hits, seen
	}
	seen[key] = len(hits)
	return append(hits, hit), seen
}

// sharedPathHit keeps a proxy-context link on a shared host (Google Sites,
// path-style object storage, code playgrounds). DNS cannot block such a host
// without collateral damage, so the hit is capped at needs_review and tagged
// for path-level enforcement; the host itself is never a likely proxy.
func sharedPathHit(doc model.Document, item occurrence, host, root string, strong, benign bool) (model.Hit, bool) {
	sanitized := SanitizeURL(item.raw)
	u, err := url.Parse(sanitized)
	if err != nil || u.Path == "" || u.Path == "/" || assetPath(u.Path) || sanitized == SanitizeURL(doc.URL) {
		return model.Hit{}, false
	}
	if benign || !proxyPattern.MatchString(item.context) || navigationPattern.MatchString(item.context) {
		return model.Hit{}, false
	}
	signals := []string{"hostname_in_public_source", "destination_not_visited", "proxy_related_context_is_not_verification", "shared_platform_path_scope"}
	if strong && !supportPattern.MatchString(item.context) {
		signals = append(signals, "explicit_proxy_link_context_unverified")
	}
	excerpt := bounded(Redact(item.context), 160)
	return model.Hit{Host: host, Registrable: root, URL: sanitized, Excerpt: excerpt, Field: item.field, Signals: signals, Classification: "needs_review", Score: 15}, true
}

func assetPath(path string) bool {
	path = strings.ToLower(path)
	for _, ext := range []string{".svg", ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".css", ".js"} {
		if strings.HasSuffix(path, ext) {
			return true
		}
	}
	return false
}

func bounded(s string, max int) string {
	if utf8.RuneCountInString(s) <= max {
		return s
	}
	r := []rune(s)
	return string(r[:max-1]) + "…"
}

// PSL private entries can make the registrable domain an individual CDN host.
// Match actual hostname boundaries as well as registrable metadata.
func suffix(host, parent string) bool {
	return host == parent || strings.HasSuffix(host, "."+parent)
}

func infrastructure(host, root string) bool {
	for _, domain := range []string{"google.com", "googleapis.com", "gstatic.com", "youtube.com", "youtu.be", "ytimg.com", "reddit.com", "redd.it", "bsky.app", "bsky.social", "facebook.com", "instagram.com", "tiktok.com", "twitter.com", "x.com", "discord.com", "discord.gg", "cloudflare.com", "jsdelivr.net", "unpkg.com", "cdnjs.com", "npmjs.com", "wikipedia.org", "bit.ly", "tinyurl.com"} {
		if root == domain || suffix(host, domain) {
			return true
		}
	}
	return false
}

func alwaysInfrastructure(host, raw string) bool {
	for _, domain := range []string{"github.com", "githubusercontent.com", "githubassets.com", "shields.io", "glitch.com", "replit.com", "koyeb.com", "cyclic.sh", "contrib.rocks", "patreon.com", "freeflarum.com"} {
		if suffix(host, domain) {
			return true
		}
	}
	u, err := url.Parse(SanitizeURL(raw))
	if err != nil {
		return false
	}
	path := strings.ToLower(u.Path)
	if assetPath(path) {
		return true
	}
	// Hosting management/deployment URLs are citations, not hosted mirrors.
	for _, domain := range []string{"railway.app", "render.com", "heroku.com", "vercel.com", "netlify.com"} {
		if host == domain || host == "www."+domain {
			if path == "" || path == "/" || strings.HasPrefix(path, "/new") || strings.HasPrefix(path, "/deploy") || strings.HasPrefix(path, "/template") || strings.HasPrefix(path, "/docs") {
				return true
			}
		}
	}
	return false
}

func textOccurrences(text, field string) []occurrence {
	var out []occurrence
	heading := ""
	age := 0
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") {
			heading, age = strings.TrimLeft(line, "# "), 0
		}
		context := line
		if heading != "" && age < 12 && len(heading) < 160 && !strings.HasPrefix(line, "#") {
			context = heading + ": " + line
		}
		out = append(out, scan(line, context, field)...)
		age++
	}
	return out
}

func scan(text, context, field string) []occurrence {
	var out []occurrence
	occupied := urlPattern.FindAllStringIndex(text, -1)
	for _, ix := range occupied {
		out = append(out, occurrence{text[ix[0]:ix[1]], nearby(context, text[ix[0]:ix[1]]), field})
	}
	emails := emailPattern.FindAllStringIndex(text, -1)
	for _, ix := range barePattern.FindAllStringIndex(text, -1) {
		overlap := false
		for _, range_ := range append(occupied, emails...) {
			if ix[0] < range_[1] && ix[1] > range_[0] {
				overlap = true
				break
			}
		}
		// Avoid matching substrings of malformed labels or unsupported schemes.
		if ix[0] > 0 && strings.ContainsRune("@_:.-/\\", rune(text[ix[0]-1])) {
			overlap = true
		}
		bareHost := strings.SplitN(strings.SplitN(strings.SplitN(clean(text[ix[0]:ix[1]]), "/", 2)[0], "?", 2)[0], "#", 2)[0]
		if strings.HasSuffix(strings.ToLower(bareHost), ".md") {
			overlap = true
		}
		if !overlap {
			out = append(out, occurrence{text[ix[0]:ix[1]], nearby(context, text[ix[0]:ix[1]]), field})
		}
	}
	return out
}

func nearby(context, raw string) string {
	// Limit proximity: SEO text far away on a long line is not per-link evidence.
	i := strings.Index(context, raw)
	if i < 0 || len(context) < 240 {
		return context
	}
	start, end := i-60, i+len(raw)+140
	if start < 0 {
		start = 0
	}
	if end > len(context) {
		end = len(context)
	}
	return strings.ToValidUTF8(context[start:end], "")
}

func looksHTML(s string) bool {
	lower := strings.ToLower(s)
	return strings.Contains(lower, "<html") || strings.Contains(lower, "<body") || strings.Contains(lower, "<a ") || strings.Contains(lower, "<li>") || strings.Contains(lower, "<p>")
}

func htmlOccurrences(source, field string) []occurrence {
	root, err := html.Parse(strings.NewReader(source))
	if err != nil {
		return nil
	}
	var out []occurrence
	heading := ""
	age := 0
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode {
			switch n.Data {
			case "head", "script", "style", "nav", "footer":
				return
			}
			if n.Data == "h1" || n.Data == "h2" || n.Data == "h3" || n.Data == "h4" {
				heading, age = nodeText(n), 0
			}
			if n.Data == "p" || n.Data == "li" {
				age++
			}
			if n.Data == "a" {
				for _, a := range n.Attr {
					if a.Key == "href" && (!strings.HasPrefix(a.Val, "/") || strings.HasPrefix(a.Val, "//")) && !strings.HasPrefix(a.Val, "#") {
						context := nodeText(n)
						for p := n.Parent; p != nil; p = p.Parent {
							if p.Type == html.ElementNode && (p.Data == "li" || p.Data == "p" || p.Data == "td") {
								context = nodeText(p)
								break
							}
							if p.Type == html.ElementNode && (p.Data == "body" || p.Data == "div") {
								context = nearby(nodeText(p), nodeText(n))
								break
							}
						}
						if heading != "" && age < 12 && len(heading) < 160 {
							context = heading + ": " + context
						}
						// Include the raw link so the excerpt is independently attributable.
						out = append(out, occurrence{a.Val, nearby(context+" "+a.Val, a.Val), field + ":href"})
					}
				}
			}
		}
		if n.Type == html.TextNode && strings.TrimSpace(n.Data) != "" {
			context := n.Data
			if n.Parent != nil && (n.Parent.Data == "p" || n.Parent.Data == "li") {
				context = nodeText(n.Parent)
			}
			out = append(out, scan(n.Data, context, field+":text")...)
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(root)
	return out
}

func nodeText(n *html.Node) string {
	var b strings.Builder
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.TextNode {
			b.WriteString(n.Data)
			b.WriteByte(' ')
		}
		if n.Type == html.ElementNode && (n.Data == "script" || n.Data == "style") {
			return
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(n)
	return strings.Join(strings.Fields(b.String()), " ")
}
