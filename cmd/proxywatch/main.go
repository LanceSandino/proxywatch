// Command proxywatch exposes the discovery-only catalog CLI.
// Inputs: command-line flags, configuration, optional provider credentials, and public source responses.
// Outputs: SQLite state, evidence reports, exports, and operator-facing diagnostics.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"proxywatch/internal/blocklist"
	"proxywatch/internal/config"
	"proxywatch/internal/engine"
	"proxywatch/internal/export"
	"proxywatch/internal/extract"
	"proxywatch/internal/model"
	"proxywatch/internal/secrets"
	"proxywatch/internal/store"
	"sort"
	"strings"
	"syscall"
	"time"
)

func main() {
	if e := run(os.Args[1:]); e != nil {
		fmt.Fprintln(os.Stderr, "proxywatch:", e)
		os.Exit(1)
	}
}
func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
func printJSON(v any) error {
	e := json.NewEncoder(os.Stdout)
	e.SetIndent("", "  ")
	return e.Encode(v)
}
func run(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: proxywatch doctor|discover|candidates|explain|export|blocklist|runs|sources|history|compare|review|vocabulary|backup [flags]")
	}
	f := flag.NewFlagSet(args[0], flag.ContinueOnError)
	cfgPath := f.String("config", env("PROXYWATCH_CONFIG", "config.example.yaml"), "YAML config")
	dbPath := f.String("db", env("PROXYWATCH_DB", "data/proxywatch.db"), "SQLite path; keep fixture and live DBs separate")
	source := f.String("source", "publicpage,youtube,bluesky,websearch,forum,flarum,github", "comma-separated adapters")
	offline := f.Bool("offline", false, "fixtures only; never contacts external services")
	maxDocs := f.Int("max-docs", 0, "override max fetched candidate documents")
	format := f.String("format", "json", "csv/json/txt")
	output := f.String("output", "", "export output file (default stdout)")
	runID := f.String("run", "", "filter catalog to run ID")
	query := f.String("search", "", "hostname substring")
	sortBy := f.String("sort", "hostname", "hostname or last-seen")
	dry := f.Bool("dry-run", false, "print bounded configuration without requests")
	refresh := f.Bool("refresh", false, "revalidate source documents now instead of TTL reuse")
	querySet := f.String("query-set", "", "select a named YAML query set")
	from := f.String("from", "", "comparison baseline run")
	to := f.String("to", "", "comparison current run")
	status := f.String("status", "", "human review classification")
	rationale := f.String("rationale", "", "human review rationale")
	staleOnly := f.Bool("stale", false, "show only stale source observations (not reachability)")
	outDir := f.String("out-dir", "output/blocklist", "blocklist output directory")
	if e := f.Parse(args[1:]); e != nil {
		return e
	}
	cfg, e := config.Load(*cfgPath)
	if e != nil {
		return e
	}
	if *maxDocs != 0 {
		if *maxDocs < 1 || *maxDocs > 500 {
			return fmt.Errorf("max-docs must be 1..500")
		}
		cfg.MaxDocs = *maxDocs
	}
	if *refresh {
		cfg.CacheHours = 0
	}
	if *querySet != "" {
		qs, ok := cfg.QuerySets[*querySet]
		if !ok || len(qs) == 0 {
			return fmt.Errorf("unknown or empty query set")
		}
		cfg.Queries = qs
	}
	if args[0] == "doctor" {
		return printJSON(map[string]any{"version": "1.0", "scope": "discovery only", "config_valid": true, "database": *dbPath, "youtube_key_present": secrets.Get("YOUTUBE_API_KEY") != "", "github_token_present": secrets.Get("GITHUB_TOKEN") != "", "search_key_present": secrets.Get("SEARCH_API_KEY") != "", "queries": len(cfg.Queries), "allowed_source_hosts": cfg.AllowedHosts, "scheduled_discovery": false})
	}
	if args[0] == "discover" && *dry {
		return printJSON(cfg)
	}
	st, e := store.Open(*dbPath)
	if e != nil {
		return e
	}
	defer st.Close()
	switch args[0] {
	case "discover":
		names := strings.Split(*source, ",")
		for i := range names {
			names[i] = strings.TrimSpace(names[i])
		}
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer cancel()
		r, e := engine.Discover(ctx, cfg, st, names, *offline)
		if e != nil {
			return e
		}
		if e = printJSON(r); e != nil {
			return e
		}
		if r.UniqueHosts == 0 {
			return fmt.Errorf("no candidates collected; inspect source errors")
		}
		return nil
	case "candidates", "explain", "export":
		if args[0] == "explain" {
			if f.NArg() != 1 {
				return fmt.Errorf("explain requires an exact hostname after flags")
			}
			*query = f.Arg(0)
		}
		cs, e := st.Candidates(*runID, *query, cfg.StaleDays)
		if e != nil {
			return e
		}
		if *runID != "" {
			if e = st.RequireRun(*runID); e != nil {
				return e
			}
		}
		if *staleOnly {
			filtered := []model.Candidate{}
			for _, c := range cs {
				if c.Stale {
					filtered = append(filtered, c)
				}
			}
			cs = filtered
		}
		if args[0] == "explain" {
			exact := []model.Candidate{}
			for _, c := range cs {
				if c.Host == strings.ToLower(*query) {
					exact = append(exact, c)
				}
			}
			if len(exact) == 0 {
				return printJSON(map[string]string{"hostname": *query, "outcome": "not_found_in_inspected_sources", "note": "absence does not establish safety; check run source errors"})
			}
			cs = exact
		}
		if *sortBy == "last-seen" {
			sort.SliceStable(cs, func(i, j int) bool { return cs[i].LastSeen > cs[j].LastSeen })
		} else if *sortBy != "hostname" {
			return fmt.Errorf("sort must be hostname or last-seen")
		}
		if args[0] != "export" {
			return printJSON(cs)
		}
		if *output == "" {
			return export.Write(os.Stdout, *format, cs)
		}
		if e = os.MkdirAll(filepath.Dir(*output), 0700); e != nil {
			return e
		}
		out, e := os.OpenFile(*output, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
		if e != nil {
			return e
		}
		defer out.Close()
		return export.Write(out, *format, cs)
	case "blocklist":
		cs, e := st.Candidates("", "", cfg.StaleDays)
		if e != nil {
			return e
		}
		r := blocklist.Build(cs, time.Now())
		files, e := blocklist.Write(*outDir, r)
		if e != nil {
			return e
		}
		return printJSON(map[string]any{"block": len(r.Block), "review": len(r.Review), "watch": len(r.Watch), "excluded": len(r.Excluded), "path_rules": len(r.Paths), "parent_hints": len(r.Parents), "files": files, "note": "exact-host lists for Pi-hole; path rules need browser policy or a filtering proxy"})
	case "sources":
		v, e := st.Checkpoints()
		if e != nil {
			return e
		}
		return printJSON(v)
	case "vocabulary":
		v, e := st.Vocabulary()
		if e != nil {
			return e
		}
		return printJSON(v)
	case "history":
		if f.NArg() != 1 {
			return fmt.Errorf("history requires exact hostname after flags")
		}
		host, _, e := extract.Normalize(f.Arg(0))
		if e != nil {
			return e
		}
		observations, e := st.History(host)
		if e != nil {
			return e
		}
		reviews, e := st.Reviews(host)
		if e != nil {
			return e
		}
		return printJSON(map[string]any{"hostname": host, "observations": observations, "reviews": reviews})
	case "review":
		if f.NArg() != 1 {
			return fmt.Errorf("review requires exact hostname after flags")
		}
		host, _, e := extract.Normalize(f.Arg(0))
		if e != nil {
			return e
		}
		if e = st.Review(host, *status, *rationale); e != nil {
			return e
		}
		return printJSON(map[string]string{"hostname": host, "classification": *status, "result": "review recorded; discovery catalog only"})
	case "backup":
		if *output == "" {
			return fmt.Errorf("backup requires --output")
		}
		if e = st.Backup(*output); e != nil {
			return e
		}
		return printJSON(map[string]string{"backup": *output, "result": "snapshot created"})
	case "compare":
		if *from == "" || *to == "" {
			return fmt.Errorf("compare requires --from and --to run IDs")
		}
		if e = st.RequireRun(*from); e != nil {
			return e
		}
		if e = st.RequireRun(*to); e != nil {
			return e
		}
		a, e := st.RunHosts(*from)
		if e != nil {
			return e
		}
		b, e := st.RunHosts(*to)
		if e != nil {
			return e
		}
		before, after := map[string]bool{}, map[string]bool{}
		for _, h := range a {
			before[h] = true
		}
		for _, h := range b {
			after[h] = true
		}
		added, continued, missing := []string{}, []string{}, []string{}
		for _, h := range b {
			if before[h] {
				continued = append(continued, h)
			} else {
				added = append(added, h)
			}
		}
		for _, h := range a {
			if !after[h] {
				missing = append(missing, h)
			}
		}
		return printJSON(map[string]any{"from": *from, "to": *to, "new_in_comparison": added, "observed_in_both": continued, "not_observed_in_current": missing, "note": "unobserved does not mean removed, unreachable, safe, or unsafe; compare source coverage"})
	case "runs":
		r, e := st.Runs()
		if e != nil {
			return e
		}
		return printJSON(r)
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}
