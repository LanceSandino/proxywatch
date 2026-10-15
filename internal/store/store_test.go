package store

import (
	"database/sql"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"proxywatch/internal/model"
)

func openStore(t *testing.T) *Store {
	t.Helper()
	s, e := Open(filepath.Join(t.TempDir(), "nested", "catalog.db"))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.Close() })
	return s
}
func startRun(t *testing.T, s *Store, id string) {
	t.Helper()
	if e := s.Start(model.Run{ID: id, StartedAt: time.Now().UTC().Format(time.RFC3339Nano), ConfigHash: "test-config"}); e != nil {
		t.Fatal(e)
	}
}
func document(url, key string, when time.Time) model.Document {
	return model.Document{Family: "github", URL: url, ExternalID: url, Text: "proxy list: https://candidate.example/a", Field: "readme", IndependenceKey: key, RetrievedAt: when}
}
func hit(host string) model.Hit {
	return model.Hit{Host: host, Registrable: "example", URL: "https://" + host + "/a?x=1", Excerpt: "proxy list link", Field: "readme", Signals: []string{"proxy_context"}, Classification: "needs_review", Score: 20}
}
func count(t *testing.T, s *Store, table string) int {
	t.Helper()
	var n int
	if e := s.DB.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&n); e != nil {
		t.Fatal(e)
	}
	return n
}

func TestMigrationPersistenceAndFutureSchemaRejection(t *testing.T) {
	path := filepath.Join(t.TempDir(), "catalog.db")
	s, e := Open(path)
	if e != nil {
		t.Fatal(e)
	}
	var v int
	if e = s.DB.QueryRow("PRAGMA user_version").Scan(&v); e != nil || v != 3 {
		t.Fatalf("migration version %d: %v", v, e)
	}
	for _, table := range []string{"runs", "source_docs", "run_docs", "candidates", "sightings", "run_sightings", "source_errors", "reviews"} {
		if count(t, s, table) != 0 {
			t.Fatalf("new table %s not empty", table)
		}
	}
	startRun(t, s, "first")
	if e = s.Close(); e != nil {
		t.Fatal(e)
	}
	s, e = Open(path)
	if e != nil {
		t.Fatal(e)
	}
	if count(t, s, "runs") != 1 {
		t.Fatal("reopening lost runs")
	}
	if _, e = s.DB.Exec("PRAGMA user_version=4"); e != nil {
		t.Fatal(e)
	}
	s.Close()
	if x, e := Open(path); e == nil {
		x.Close()
		t.Fatal("accepted schema from a newer executable")
	}
}

func TestExactIdentityIdempotencyAndEvidencePersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "catalog.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	startRun(t, s, "r1")
	startRun(t, s, "r2")
	first := time.Now().UTC().Add(-48 * time.Hour).Truncate(time.Second)
	last := first.Add(24 * time.Hour)
	d := document("https://github.com/owner/repo/blob/main/README.md", "github:owner/repo", first)
	h := hit("candidate.example")
	n, e := s.Ingest("r1", d, []model.Hit{h, h, hit("sub.candidate.example")})
	if e != nil || n != 2 {
		t.Fatalf("first ingest new=%d: %v", n, e)
	}
	n, e = s.Ingest("r1", d, []model.Hit{h, h})
	if e != nil || n != 0 {
		t.Fatalf("repeat ingest new=%d: %v", n, e)
	}
	d.RetrievedAt = last
	n, e = s.Ingest("r2", d, []model.Hit{h, h})
	if e != nil || n != 0 {
		t.Fatalf("new-run ingest new=%d: %v", n, e)
	}
	if count(t, s, "candidates") != 2 || count(t, s, "source_docs") != 1 || count(t, s, "sightings") != 2 || count(t, s, "run_docs") != 2 || count(t, s, "run_sightings") != 3 {
		t.Fatal("duplicate candidate/document/sighting identities")
	}
	if e = s.Close(); e != nil {
		t.Fatal(e)
	}
	s, e = Open(path)
	if e != nil {
		t.Fatal(e)
	}
	cs, e := s.Candidates("r2", "candidate", 30)
	if e != nil {
		t.Fatal(e)
	}
	if len(cs) != 1 || cs[0].Host != "candidate.example" {
		t.Fatalf("run filter wrong: %+v", cs)
	}
	c := cs[0]
	if !sameTimestamp(c.FirstSeen, first) || !sameTimestamp(c.LastSeen, last) || c.IndependentSources != 1 {
		t.Fatalf("history/counts lost: %+v", c)
	}
	if len(c.Evidence) != 1 {
		t.Fatalf("sightings duplicated: %+v", c.Evidence)
	}
	ev := c.Evidence[0]
	if ev.SourceURL != d.URL || ev.SourceType != d.Family || ev.ExternalID != d.ExternalID || ev.OriginalURL != h.URL || ev.Excerpt != h.Excerpt || ev.Field != h.Field || ev.RunID != "r1" || ev.ContentHash == "" || ev.IndependenceKey != d.IndependenceKey || !sameTimestamp(ev.DiscoveredAt, first) || !sameTimestamp(ev.LastSeen, last) || !reflect.DeepEqual(ev.Signals, h.Signals) {
		t.Fatalf("provenance mismatch: %+v", ev)
	}
	stats := s.DB.Stats()
	if stats.MaxOpenConnections != 1 {
		t.Fatal("SQLite concurrency setting changed")
	}
}

func TestIndependenceCountsGroupMirrorsAndExcludeSynthetic(t *testing.T) {
	s := openStore(t)
	startRun(t, s, "r1")
	when := time.Now().UTC()
	h := hit("candidate.example")
	docs := []model.Document{document("https://github.com/owner/repo/README.md", "github:owner/repo", when), document("https://raw.githubusercontent.com/owner/repo/main/README.md", "github:owner/repo", when), document("https://github.com/different/project/README.md", "github:different/project", when), document("https://www.youtube.com/watch?v=one", "youtube:one", when)}
	docs[2].Text += " independent second repository"
	docs[3].Text += " independent video description"
	docs[3].Family = "youtube"
	for _, d := range docs {
		if _, e := s.Ingest("r1", d, []model.Hit{h}); e != nil {
			t.Fatal(e)
		}
	}
	cs, e := s.Candidates("r1", "", 30)
	if e != nil {
		t.Fatal(e)
	}
	if len(cs) != 1 || cs[0].IndependentSources != 3 || len(cs[0].Evidence) != 4 {
		t.Fatalf("independent provenance counts wrong: %+v", cs)
	}
	var fresh int
	if e = s.DB.QueryRow("SELECT SUM(fresh) FROM run_docs").Scan(&fresh); e != nil || fresh != 4 {
		t.Fatalf("live document freshness wrong: %d, %v", fresh, e)
	}
	fixtureStore := openStore(t)
	if e = fixtureStore.Start(model.Run{ID: "fixture", StartedAt: when.Format(time.RFC3339Nano), ConfigHash: "fixture", Synthetic: true}); e != nil {
		t.Fatal(e)
	}
	fixture := document("fixture://video-two", "fixture:two", when)
	fixture.Synthetic = true
	if _, e = fixtureStore.Ingest("fixture", fixture, []model.Hit{h}); e != nil {
		t.Fatal(e)
	}
	cs, e = fixtureStore.Candidates("fixture", "", 30)
	if e != nil || len(cs) != 1 || cs[0].IndependentSources != 0 || len(cs[0].Evidence) != 1 || !cs[0].Evidence[0].Synthetic {
		t.Fatalf("synthetic provenance/count wrong: %+v, %v", cs, e)
	}
	if e = fixtureStore.DB.QueryRow("SELECT SUM(fresh) FROM run_docs").Scan(&fresh); e != nil || fresh != 0 {
		t.Fatalf("synthetic document counted as fresh: %d, %v", fresh, e)
	}
}

func TestSourceFailureRetainsPriorHistory(t *testing.T) {
	s := openStore(t)
	startRun(t, s, "ok")
	if _, e := s.Ingest("ok", document("https://github.com/one/list", "github:one", time.Now().UTC()), []model.Hit{hit("candidate.example")}); e != nil {
		t.Fatal(e)
	}
	startRun(t, s, "failed")
	sourceErr := model.SourceError{Family: "youtube", Ref: "video:private", Code: "access_or_quota_restricted", Message: "credential unavailable"}
	if e := s.Error("failed", sourceErr); e != nil {
		t.Fatal(e)
	}
	r := model.Run{ID: "failed", FinishedAt: time.Now().UTC().Format(time.RFC3339Nano), Status: "partial", Sources: map[string]*model.SourceStats{"youtube": {Errors: []model.SourceError{sourceErr}}}}
	if e := s.Finish(r); e != nil {
		t.Fatal(e)
	}
	cs, e := s.Candidates("", "", 30)
	if e != nil || len(cs) != 1 {
		t.Fatalf("source failure deleted candidate: %+v, %v", cs, e)
	}
	failed, e := s.RunHosts("failed")
	if e != nil || len(failed) != 0 {
		t.Fatalf("failed run borrowed prior candidates: %+v, %v", failed, e)
	}
	runs, e := s.Runs()
	if e != nil || len(runs) != 1 || runs[0].Status != "partial" || len(runs[0].Sources["youtube"].Errors) != 1 {
		t.Fatalf("source error metrics lost: %+v, %v", runs, e)
	}
	if count(t, s, "source_errors") != 1 {
		t.Fatal("source error missing")
	}
}

func TestForeignKeysAndIngestAtomicity(t *testing.T) {
	s := openStore(t)
	if _, e := s.Ingest("nonexistent-run", document("https://github.com/one/list", "github:one", time.Now().UTC()), []model.Hit{hit("candidate.example")}); e == nil {
		t.Fatal("accepted evidence without a run")
	}
	for _, table := range []string{"source_docs", "candidates", "sightings", "run_docs"} {
		if count(t, s, table) != 0 {
			t.Fatalf("failed ingest left partial %s", table)
		}
	}
}

func TestAutomatedIngestCannotConfirmHumanClassifications(t *testing.T) {
	for _, classification := range []string{"confirmed_unsafe", "confirmed_benign"} {
		t.Run(classification, func(t *testing.T) {
			s := openStore(t)
			startRun(t, s, "r1")
			h := hit("candidate.example")
			h.Classification = classification
			_, e := s.Ingest("r1", document("https://github.com/one/list", "github:one", time.Now().UTC()), []model.Hit{h})
			if e != nil {
				return
			}
			cs, e := s.Candidates("", "", 0)
			if e != nil {
				t.Fatal(e)
			}
			for _, c := range cs {
				if c.Classification == classification && c.ReviewStatus == "unreviewed" {
					t.Fatalf("source claim automatically assigned human-only classification: %+v", c)
				}
			}
		})
	}
}

func TestHumanReviewSurvivesNewProxyClaims(t *testing.T) {
	s := openStore(t)
	startRun(t, s, "r1")
	h := hit("candidate.example")
	if _, e := s.Ingest("r1", document("https://github.com/one/list", "github:one", time.Now().UTC()), []model.Hit{h}); e != nil {
		t.Fatal(e)
	}
	if _, e := s.DB.Exec("UPDATE candidates SET classification='confirmed_benign',review_status='reviewed',score=0"); e != nil {
		t.Fatal(e)
	}
	startRun(t, s, "r2")
	h.Classification = "likely_proxy"
	h.Score = 99
	if _, e := s.Ingest("r2", document("https://github.com/two/list", "github:two", time.Now().UTC()), []model.Hit{h}); e != nil {
		t.Fatal(e)
	}
	cs, e := s.Candidates("", "", 0)
	if e != nil {
		t.Fatal(e)
	}
	if len(cs) != 1 || cs[0].Classification != "confirmed_benign" || cs[0].ReviewStatus != "reviewed" || cs[0].Score != 0 {
		t.Fatalf("automatic evidence overwrote human review: %+v", cs)
	}
}

func TestSortedSearchStalenessAndRunDifferenceInputs(t *testing.T) {
	s := openStore(t)
	startRun(t, s, "old")
	d := document("https://github.com/one/list", "github:one", time.Now().UTC().Add(-60*24*time.Hour))
	if _, e := s.Ingest("old", d, []model.Hit{hit("z.example"), hit("a.example")}); e != nil {
		t.Fatal(e)
	}
	startRun(t, s, "new")
	d.RetrievedAt = time.Now().UTC()
	if _, e := s.Ingest("new", d, []model.Hit{hit("z.example"), hit("b.example")}); e != nil {
		t.Fatal(e)
	}
	old, e := s.RunHosts("old")
	if e != nil {
		t.Fatal(e)
	}
	newHosts, e := s.RunHosts("new")
	if e != nil {
		t.Fatal(e)
	}
	if !reflect.DeepEqual(old, []string{"a.example", "z.example"}) || !reflect.DeepEqual(newHosts, []string{"b.example", "z.example"}) {
		t.Fatalf("run identities/order wrong: %v -> %v", old, newHosts)
	}
	cs, e := s.Candidates("", "a.example", 30)
	if e != nil || len(cs) != 1 || !cs[0].Stale {
		t.Fatalf("stale/search result wrong: %+v, %v", cs, e)
	}
	if _, e = s.Candidates("", "' OR 1=1 --", 30); e != nil {
		t.Fatalf("search query not parameterized: %v", e)
	}
}

func TestVersionOneUpgradePreservesDataAndEnforcesProvenance(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old.db")
	db, e := sql.Open("sqlite3", path)
	if e != nil {
		t.Fatal(e)
	}
	b, e := migrations.ReadFile("migrations/001_initial.sql")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = db.Exec(string(b)); e != nil {
		t.Fatal(e)
	}
	if _, e = db.Exec("INSERT INTO runs(id,started_at,status,config_hash,synthetic) VALUES('old','2026-10-12T00:00:00Z','complete','hash',0)"); e != nil {
		t.Fatal(e)
	}
	db.Close()
	s, e := Open(path)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	var version int
	if e = s.DB.QueryRow("PRAGMA user_version").Scan(&version); e != nil || version != 3 {
		t.Fatalf("upgrade version %d: %v", version, e)
	}
	if count(t, s, "runs") != 1 {
		t.Fatal("migration deleted existing run")
	}
	if _, e = s.DB.Exec("INSERT INTO runs(id,started_at,status,config_hash,synthetic) VALUES('fixture','2026-10-12T00:00:00Z','running','hash',1)"); e == nil {
		t.Fatal("upgraded DB allows SQL to bypass mode guard")
	}
}

func TestMixedRunAndDocumentModesRejectedAtomically(t *testing.T) {
	for _, synthetic := range []bool{false, true} {
		t.Run(map[bool]string{false: "live", true: "fixture"}[synthetic], func(t *testing.T) {
			s := openStore(t)
			when := time.Now().UTC()
			if e := s.Start(model.Run{ID: "first", StartedAt: when.Format(time.RFC3339Nano), ConfigHash: "hash", Synthetic: synthetic}); e != nil {
				t.Fatal(e)
			}
			if e := s.Start(model.Run{ID: "other", StartedAt: when.Format(time.RFC3339Nano), ConfigHash: "hash", Synthetic: !synthetic}); e == nil {
				t.Fatal("Start accepted mixed modes")
			}
			if _, e := s.DB.Exec("INSERT INTO runs(id,started_at,status,config_hash,synthetic) VALUES(?,?,?,?,?)", "bypass", when.Format(time.RFC3339Nano), "running", "hash", !synthetic); e == nil {
				t.Fatal("SQL bypassed atomic mode guard")
			}
			d := document("https://github.com/one/list", "github:one", when)
			d.Synthetic = !synthetic
			if _, e := s.Ingest("first", d, []model.Hit{hit("candidate.example")}); e == nil {
				t.Fatal("document/run provenance mismatch accepted")
			}
			for _, table := range []string{"source_docs", "run_docs", "candidates", "sightings", "run_sightings"} {
				if count(t, s, table) != 0 {
					t.Fatalf("mismatch left partial table %s", table)
				}
			}
		})
	}
}

func TestRunScopedEvidenceExcludesOtherRuns(t *testing.T) {
	s := openStore(t)
	startRun(t, s, "first")
	startRun(t, s, "second")
	when := time.Now().UTC()
	for i, id := range []string{"first", "second"} {
		d := document("https://github.com/"+id+"/list", "github:"+id, when.Add(time.Duration(i)*time.Second))
		d.Text += " " + id
		if _, e := s.Ingest(id, d, []model.Hit{hit("candidate.example")}); e != nil {
			t.Fatal(e)
		}
	}
	for _, id := range []string{"first", "second"} {
		cs, e := s.Candidates(id, "", 0)
		if e != nil || len(cs) != 1 || len(cs[0].Evidence) != 1 || cs[0].IndependentSources != 1 || cs[0].Evidence[0].RunID != id {
			t.Fatalf("%s borrowed evidence: %+v, %v", id, cs, e)
		}
	}
	all, e := s.Candidates("", "", 0)
	if e != nil || len(all) != 1 || len(all[0].Evidence) != 2 || all[0].IndependentSources != 2 {
		t.Fatalf("catalog history not preserved: %+v, %v", all, e)
	}
}

func TestConcurrentWritersCannotMixModes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "catalog.db")
	a, e := Open(path)
	if e != nil {
		t.Fatal(e)
	}
	defer a.Close()
	b, e := Open(path)
	if e != nil {
		t.Fatal(e)
	}
	defer b.Close()
	start := make(chan struct{})
	results := make(chan error, 2)
	for i, s := range []*Store{a, b} {
		go func(i int, s *Store) {
			<-start
			results <- s.Start(model.Run{ID: []string{"live", "fixture"}[i], StartedAt: time.Now().UTC().Format(time.RFC3339Nano), ConfigHash: "hash", Synthetic: i == 1})
		}(i, s)
	}
	close(start)
	success := 0
	for i := 0; i < 2; i++ {
		if e := <-results; e == nil {
			success++
		}
	}
	if success != 1 || count(t, a, "runs") != 1 {
		t.Fatalf("concurrent opposite modes accepted: successes=%d", success)
	}
}
