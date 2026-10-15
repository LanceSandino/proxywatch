// Package blocklist turns catalog candidates into tiered, reviewable block lists.
// Inputs: catalog candidates with evidence; it never resolves or visits hosts.
// Outputs: exact-host DNS tiers, path-level rules for shared platforms, and
// parent-domain hints; files are written for later Pi-hole or browser policy use.
package blocklist

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"proxywatch/internal/model"
	"proxywatch/internal/platform"
)

// Tiers, strictest first. Only Block is intended for default Pi-hole use.
const (
	Block  = "block"  // likely_proxy or confirmed_unsafe
	Review = "review" // proxy context or benign signal; a parent decides
	Watch  = "watch"  // seen in proxy-related sources without proxy context
)

type Entry struct {
	Host               string   `json:"hostname"`
	Registrable        string   `json:"registrable_domain"`
	Scope              string   `json:"scope"`
	Tier               string   `json:"tier,omitempty"`
	Classification     string   `json:"classification"`
	ReviewStatus       string   `json:"review_status"`
	Score              int      `json:"score"`
	IndependentSources int      `json:"independent_sources"`
	FirstSeen          string   `json:"first_seen"`
	LastSeen           string   `json:"last_seen"`
	Reason             string   `json:"reason"`
	Sources            []string `json:"source_urls"`
}

type PathRule struct {
	Host        string   `json:"hostname"`
	Prefix      string   `json:"path_prefix"`
	Tier        string   `json:"tier"`
	Examples    []string `json:"example_urls"`
	Sources     []string `json:"source_urls"`
	Excerpt     string   `json:"evidence_excerpt"`
	FirstSeen   string   `json:"first_seen"`
	LastSeen    string   `json:"last_seen"`
	Enforcement string   `json:"enforcement"`
}

type ParentHint struct {
	Registrable  string   `json:"registrable_domain"`
	FlaggedHosts int      `json:"flagged_hosts"`
	BlockHosts   int      `json:"block_tier_hosts"`
	Regex        string   `json:"suggested_pihole_regex"`
	Hosts        []string `json:"hosts"`
}

type Result struct {
	GeneratedAt string       `json:"generated_at"`
	Block       []Entry      `json:"block"`
	Review      []Entry      `json:"review"`
	Watch       []Entry      `json:"watch"`
	Excluded    []Entry      `json:"excluded"`
	Paths       []PathRule   `json:"path_rules"`
	Parents     []ParentHint `json:"parent_hints"`
}

const pathEnforcement = "DNS cannot block a URL path. Enforce with a managed-browser URLBlocklist policy, a browser filter extension, or a TLS-inspecting proxy."

// MinParentHosts is the flagged-subdomain count that triggers a parent hint.
const MinParentHosts = 3

// Build assigns every candidate to exactly one tier, exclusion, or path rule set.
func Build(cs []model.Candidate, now time.Time) Result {
	r := Result{GeneratedAt: now.UTC().Format(time.RFC3339)}
	paths := map[string]*PathRule{}
	for _, c := range cs {
		scope := platform.Classify(c.Host)
		e := Entry{Host: c.Host, Registrable: c.Registrable, Scope: string(scope), Classification: c.Classification, ReviewStatus: c.ReviewStatus, Score: c.Score, IndependentSources: c.IndependentSources, FirstSeen: c.FirstSeen, LastSeen: c.LastSeen, Sources: sources(c.Evidence, 5)}
		switch {
		case syntheticOnly(c):
			e.Reason = "synthetic fixture evidence only; never a block input"
			r.Excluded = append(r.Excluded, e)
			continue
		case scope == platform.SharedPath:
			addPaths(paths, c)
			continue
		case c.Classification == "confirmed_benign":
			e.Reason = "reviewed as benign"
			r.Excluded = append(r.Excluded, e)
			continue
		case scope == platform.Protected:
			e.Reason = "protected platform; never auto-blocked"
			r.Excluded = append(r.Excluded, e)
			continue
		}
		switch {
		case c.Classification == "confirmed_unsafe":
			e.Tier, e.Reason = Block, "reviewed as unsafe"
		case benignSignal(c) && c.ReviewStatus == "unreviewed":
			e.Tier, e.Reason = Review, "benign or multi-use context; needs a human decision"
		case c.Classification == "likely_proxy":
			e.Tier, e.Reason = Block, "explicit proxy-link context (destination not visited)"
		case c.Classification == "needs_review" && hasSignal(c, "listed_in_proxy_link_compilation"):
			e.Tier, e.Reason = Block, "listed in a proxy-link compilation (destination not visited)"
		case c.Classification == "needs_review":
			e.Tier, e.Reason = Review, "proxy-related context only"
		default:
			e.Tier, e.Reason = Watch, "listed in a proxy-related source without proxy context"
		}
		if scope == platform.Tenant {
			e.Reason += "; tenant subdomain, block exact host only"
		}
		switch e.Tier {
		case Block:
			r.Block = append(r.Block, e)
		case Review:
			r.Review = append(r.Review, e)
		default:
			r.Watch = append(r.Watch, e)
		}
	}
	for _, p := range paths {
		r.Paths = append(r.Paths, *p)
	}
	sort.Slice(r.Paths, func(i, j int) bool {
		return r.Paths[i].Host+r.Paths[i].Prefix < r.Paths[j].Host+r.Paths[j].Prefix
	})
	r.Parents = parents(append(append([]Entry{}, r.Block...), r.Review...))
	return r
}

func syntheticOnly(c model.Candidate) bool {
	for _, v := range c.Evidence {
		if !v.Synthetic {
			return false
		}
	}
	return true
}

func benignSignal(c model.Candidate) bool {
	return hasSignal(c, "benign_or_multiuse_context_requires_review")
}

func hasSignal(c model.Candidate, signal string) bool {
	for _, v := range c.Evidence {
		if v.Synthetic {
			continue
		}
		for _, s := range v.Signals {
			if s == signal {
				return true
			}
		}
	}
	return false
}

func sources(ev []model.Evidence, max int) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, v := range ev {
		if v.Synthetic || seen[v.SourceURL] {
			continue
		}
		seen[v.SourceURL] = true
		out = append(out, v.SourceURL)
		if len(out) == max {
			break
		}
	}
	return out
}

// tenantSegments is how many leading path segments identify one tenant.
var tenantSegments = map[string]int{
	"sites.google.com": 2, "docs.google.com": 3, "drive.google.com": 3,
	"script.google.com": 3, "storage.googleapis.com": 1,
	"firebasestorage.googleapis.com": 3, "cdn.jsdelivr.net": 3, "codepen.io": 1,
	"replit.com": 2, "glitch.com": 2, "jsfiddle.net": 1, "stackblitz.com": 2,
	"codesandbox.io": 2, "scratch.mit.edu": 2,
}

// TenantPrefix reduces a URL path to the tenant it belongs to, so one rule
// covers a whole proxy site rather than a single page.
func TenantPrefix(host, path string) string {
	n, ok := tenantSegments[host]
	if !ok && platform.Classify(host) == platform.SharedPath && strings.Contains(host, "amazonaws.com") {
		n, ok = 1, true // path-style S3: /<bucket>
	}
	segs := []string{}
	for _, s := range strings.Split(path, "/") {
		if s != "" {
			segs = append(segs, s)
		}
	}
	if !ok || len(segs) <= n {
		return "/" + strings.Join(segs, "/")
	}
	return "/" + strings.Join(segs[:n], "/")
}

func addPaths(paths map[string]*PathRule, c model.Candidate) {
	for _, v := range c.Evidence {
		if v.Synthetic {
			continue
		}
		u, err := url.Parse(v.OriginalURL)
		if err != nil || u.Path == "" || u.Path == "/" {
			continue
		}
		prefix := TenantPrefix(c.Host, u.Path)
		tier := Review
		for _, s := range v.Signals {
			if s == "explicit_proxy_link_context_unverified" {
				tier = Block
			}
		}
		key := c.Host + prefix
		p, ok := paths[key]
		if !ok {
			p = &PathRule{Host: c.Host, Prefix: prefix, Tier: tier, Excerpt: v.Excerpt, FirstSeen: v.DiscoveredAt, LastSeen: v.LastSeen, Enforcement: pathEnforcement}
			paths[key] = p
		}
		if tier == Block {
			p.Tier = Block
		}
		p.Examples = addUnique(p.Examples, v.OriginalURL, 5)
		p.Sources = addUnique(p.Sources, v.SourceURL, 5)
		if v.DiscoveredAt < p.FirstSeen {
			p.FirstSeen = v.DiscoveredAt
		}
		if v.LastSeen > p.LastSeen {
			p.LastSeen = v.LastSeen
		}
	}
}

func addUnique(list []string, v string, max int) []string {
	for _, x := range list {
		if x == v {
			return list
		}
	}
	if len(list) >= max {
		return list
	}
	return append(list, v)
}

// parents suggests, but never applies, wildcard blocks for registrable domains
// that host many flagged subdomains (often free dynamic-DNS or hijacked zones).
func parents(es []Entry) []ParentHint {
	groups := map[string]*ParentHint{}
	for _, e := range es {
		if platform.Classify(e.Registrable) != platform.Dedicated {
			continue // never suggest blocking a hosting platform or protected service
		}
		g, ok := groups[e.Registrable]
		if !ok {
			g = &ParentHint{Registrable: e.Registrable, Regex: "(\\.|^)" + strings.ReplaceAll(e.Registrable, ".", "\\.") + "$"}
			groups[e.Registrable] = g
		}
		g.FlaggedHosts++
		if e.Tier == Block {
			g.BlockHosts++
		}
		g.Hosts = append(g.Hosts, e.Host)
	}
	out := []ParentHint{}
	for _, g := range groups {
		if g.FlaggedHosts >= MinParentHosts {
			sort.Strings(g.Hosts)
			out = append(out, *g)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].FlaggedHosts != out[j].FlaggedHosts {
			return out[i].FlaggedHosts > out[j].FlaggedHosts
		}
		return out[i].Registrable < out[j].Registrable
	})
	return out
}

// Write emits the result as Pi-hole adlists, path rules, hints and full JSON.
func Write(dir string, r Result) ([]string, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	var written []string
	write := func(name string, fn func(*os.File) error) error {
		p := filepath.Join(dir, name)
		f, err := os.OpenFile(p, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
		if err != nil {
			return err
		}
		if err = fn(f); err != nil {
			f.Close()
			return err
		}
		written = append(written, p)
		return f.Close()
	}
	tiers := []struct {
		name, desc string
		es         []Entry
	}{
		{"pihole-block.txt", "Default tier: explicit proxy-link context or reviewed unsafe.", r.Block},
		{"pihole-review.txt", "Optional tier: proxy-related or multi-use context; review before enabling.", r.Review},
		{"pihole-watch.txt", "Informational tier: listed in proxy sources without proxy context. Not recommended for blocking.", r.Watch},
	}
	for _, t := range tiers {
		t := t
		err := write(t.name, func(f *os.File) error {
			fmt.Fprintf(f, "# ProxyWatch %s\n# %s\n# Generated %s; %d exact hostnames. Destinations were never visited.\n# Exact-host entries only: shared platforms and their parent domains are excluded.\n", t.name, t.desc, r.GeneratedAt, len(t.es))
			for _, e := range t.es {
				fmt.Fprintln(f, e.Host)
			}
			return nil
		})
		if err != nil {
			return written, err
		}
	}
	err := write("path-rules.txt", func(f *os.File) error {
		fmt.Fprintf(f, "# ProxyWatch path rules for shared platforms (%d). DNS cannot enforce these.\n# Format: host/path-prefix, usable as Chrome URLBlocklist entries or, prefixed with ||, as uBlock filters.\n# Tier is in path-rules.csv; review-tier rules are commented out here.\n", len(r.Paths))
		for _, p := range r.Paths {
			prefix := ""
			if p.Tier != Block {
				prefix = "# review: "
			}
			fmt.Fprintf(f, "%s%s%s\n", prefix, p.Host, p.Prefix)
		}
		return nil
	})
	if err != nil {
		return written, err
	}
	err = write("path-rules.csv", func(f *os.File) error {
		w := csv.NewWriter(f)
		w.Write([]string{"hostname", "path_prefix", "tier", "example_urls", "source_urls", "evidence_excerpt", "first_seen", "last_seen", "enforcement"})
		for _, p := range r.Paths {
			w.Write([]string{p.Host, p.Prefix, p.Tier, strings.Join(p.Examples, " | "), strings.Join(p.Sources, " | "), p.Excerpt, p.FirstSeen, p.LastSeen, p.Enforcement})
		}
		w.Flush()
		return w.Error()
	})
	if err != nil {
		return written, err
	}
	err = write("parent-hints.csv", func(f *os.File) error {
		w := csv.NewWriter(f)
		w.Write([]string{"registrable_domain", "flagged_hosts", "block_tier_hosts", "suggested_pihole_regex", "hosts"})
		for _, p := range r.Parents {
			w.Write([]string{p.Registrable, strconv.Itoa(p.FlaggedHosts), strconv.Itoa(p.BlockHosts), p.Regex, strings.Join(p.Hosts, " ")})
		}
		w.Flush()
		return w.Error()
	})
	if err != nil {
		return written, err
	}
	err = write("blocklist.json", func(f *os.File) error {
		enc := json.NewEncoder(f)
		enc.SetIndent("", "  ")
		return enc.Encode(r)
	})
	return written, err
}
