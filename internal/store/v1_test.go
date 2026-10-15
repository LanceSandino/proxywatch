package store

import (
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"proxywatch/internal/fetch"
	"proxywatch/internal/model"
)

func cachedDocument(url, key, body string, stamp time.Time) model.Document {
	d := document(url, "github:"+url, stamp)
	d.FetchKey = key
	d.Text = body
	return d
}
func TestCacheEvidenceMustMatchSuccessfulProcessing(t *testing.T) {
	s := openStore(t)
	startRun(t, s, "first")
	key := fetch.Hash([]byte("source"))
	stamp := time.Date(2026, 10, 12, 1, 0, 0, 0, time.UTC)
	entry := fetch.CacheEntry{ETag: `"v1"`, LastModified: "Mon, 12 Oct 2026 01:00:00 GMT", ValidatedAt: stamp}
	if e := s.Put(key, entry); e != nil {
		t.Fatal(e)
	}
	saved, ok, e := s.Lookup(key)
	if e != nil || !ok || saved != entry {
		t.Fatalf("validator persistence: %+v %v %v", saved, ok, e)
	}
	if evidence, e := s.HasEvidence(key); e != nil || evidence {
		t.Fatalf("metadata treated as evidence: %v %v", evidence, e)
	}
	d := cachedDocument("https://github.com/one/list", key, "version one", stamp)
	if _, e = s.Ingest("first", d, []model.Hit{hit("candidate.example")}); e != nil {
		t.Fatal(e)
	}
	if evidence, e := s.HasEvidence(key); e != nil || !evidence {
		t.Fatalf("processed evidence absent: %v %v", evidence, e)
	}
	entry.ValidatedAt = stamp.Add(time.Hour)
	entry.ETag = `"v2"`
	if e = s.Put(key, entry); e != nil {
		t.Fatal(e)
	}
	if evidence, e := s.HasEvidence(key); e != nil || evidence {
		t.Fatalf("unprocessed new response reused stale evidence: %v %v", evidence, e)
	}
	startRun(t, s, "second")
	d.RetrievedAt = entry.ValidatedAt
	d.Text = "version two"
	if _, e = s.Ingest("second", d, []model.Hit{hit("new.example")}); e != nil {
		t.Fatal(e)
	}
	if evidence, e := s.HasEvidence(key); e != nil || !evidence {
		t.Fatalf("processed new version absent: %v %v", evidence, e)
	}
	absent, ok, e := s.Lookup("missing-key")
	if e != nil || ok || absent.ETag != "" {
		t.Fatalf("missing cache semantics: %+v %v %v", absent, ok, e)
	}
}

func TestReuseLatestBodyTTLAndRemoteValidation(t *testing.T) {
	s := openStore(t)
	key := fetch.Hash([]byte("source"))
	first := time.Date(2026, 10, 12, 0, 0, 0, 0, time.UTC)
	latest := first.Add(time.Hour)
	for i, stamp := range []time.Time{first, latest} {
		id := []string{"old", "current"}[i]
		startRun(t, s, id)
		d := cachedDocument("https://github.com/one/list", key, id, stamp)
		h := hit([]string{"old.example", "current.example"}[i])
		if _, e := s.Ingest(id, d, []model.Hit{h}); e != nil {
			t.Fatal(e)
		}
	}
	startRun(t, s, "ttl")
	docs, hosts, sightings, e := s.Reuse("ttl", model.Reuse{Family: "github", Key: key, RetrievedAt: latest, CacheState: "ttl"})
	if e != nil || docs != 1 || hosts != 1 || sightings != 1 {
		t.Fatalf("TTL reuse metrics: %d %d %d %v", docs, hosts, sightings, e)
	}
	cs, e := s.Candidates("ttl", "", 0)
	if e != nil || len(cs) != 1 || cs[0].Host != "current.example" || !sameTimestamp(cs[0].LastSeen, latest) || len(cs[0].Evidence) != 1 {
		t.Fatalf("TTL resurrected old version or advanced freshness: %+v %v", cs, e)
	}
	validated := latest.Add(time.Hour)
	startRun(t, s, "validated")
	docs, hosts, sightings, e = s.Reuse("validated", model.Reuse{Family: "github", Key: key, RetrievedAt: validated, CacheState: "not_modified"})
	if e != nil || docs != 1 || hosts != 1 || sightings != 1 {
		t.Fatalf("304 reuse metrics: %d %d %d %v", docs, hosts, sightings, e)
	}
	cs, e = s.Candidates("validated", "", 0)
	if e != nil || len(cs) != 1 || cs[0].Host != "current.example" || !sameTimestamp(cs[0].LastSeen, validated) || !sameTimestamp(cs[0].FirstSeen, latest) {
		t.Fatalf("remote validation did not refresh latest identity: %+v %v", cs, e)
	}
	old, e := s.Candidates("", "old.example", 0)
	if e != nil || len(old) != 1 || !sameTimestamp(old[0].LastSeen, first) {
		t.Fatalf("removed old domain refreshed: %+v %v", old, e)
	}
	var fresh int
	if e = s.DB.QueryRow("SELECT SUM(fresh) FROM run_docs WHERE run_id IN('ttl','validated')").Scan(&fresh); e != nil || fresh != 0 {
		t.Fatalf("cached evidence counted live gate freshness: %d %v", fresh, e)
	}
	for _, runID := range []string{"ttl", "validated"} {
		stats, err := s.RunDocumentStats(runID)
		if err != nil || stats["github"].Documents != 1 || stats["github"].CandidateDocuments != 1 || stats["github"].FreshDocuments != 0 {
			t.Fatalf("cached document statistics count fresh or omit candidate evidence: %+v %v", stats, err)
		}
	}
	if count(t, s, "source_docs") != 2 || count(t, s, "sightings") != 2 {
		t.Fatal("reuse duplicated documents or sightings")
	}
}

func TestReuseRejectsAbsentEvidenceAndSyntheticDocuments(t *testing.T) {
	s := openStore(t)
	startRun(t, s, "empty")
	if _, _, _, e := s.Reuse("empty", model.Reuse{Family: "github", Key: "absent", RetrievedAt: time.Now().UTC(), CacheState: "ttl"}); e == nil {
		t.Fatal("missing cache evidence accepted")
	}
	if count(t, s, "run_docs") != 0 || count(t, s, "run_sightings") != 0 {
		t.Fatal("failed reuse mutated associations")
	}
	fixtures := openStore(t)
	stamp := time.Now().UTC()
	if e := fixtures.Start(model.Run{ID: "fixture", StartedAt: stamp.Format(time.RFC3339Nano), ConfigHash: "fixture", Synthetic: true}); e != nil {
		t.Fatal(e)
	}
	d := cachedDocument("fixture://test", "key", "synthetic", stamp)
	d.Synthetic = true
	if _, e := fixtures.Ingest("fixture", d, []model.Hit{hit("candidate.example")}); e != nil {
		t.Fatal(e)
	}
	if e := fixtures.Put("key", fetch.CacheEntry{ValidatedAt: stamp}); e != nil {
		t.Fatal(e)
	}
	if has, e := fixtures.HasEvidence("key"); e != nil || has {
		t.Fatalf("synthetic evidence enabled live reuse: %v %v", has, e)
	}
	if _, _, _, e := fixtures.Reuse("fixture", model.Reuse{Family: "github", Key: "key", RetrievedAt: stamp, CacheState: "ttl"}); e == nil {
		t.Fatal("fixture document reused as live evidence")
	}
}

func TestMigrationTwoToThreePreservesEvidence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "v2.db")
	db, e := sql.Open("sqlite3", path)
	if e != nil {
		t.Fatal(e)
	}
	for _, name := range []string{"migrations/001_initial.sql", "migrations/002_provenance_guards.sql"} {
		b, e := migrations.ReadFile(name)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = db.Exec(string(b)); e != nil {
			t.Fatal(e)
		}
	}
	old := &Store{DB: db}
	startRun(t, old, "old")
	stamp := "2026-10-12T00:00:00Z"
	if _, e = db.Exec("INSERT INTO candidates(normalized_host,registrable_domain,first_seen,last_seen,classification) VALUES('candidate.example','example',?,?,'needs_review')", stamp, stamp); e != nil {
		t.Fatal(e)
	}
	if _, e = db.Exec("INSERT INTO source_docs(type,external_id,canonical_url,query,retrieved_at,content_hash,independence_key,synthetic) VALUES('github','readme','https://github.com/one/list','proxy',?,'hash','github:one',0)", stamp); e != nil {
		t.Fatal(e)
	}
	if _, e = db.Exec("INSERT INTO sightings(candidate_id,source_doc_id,raw_value_sanitized,excerpt_sanitized,field,evidence_hash,discovered_at,last_seen,first_run_id,signals_json) VALUES(1,1,'https://candidate.example','real evidence','README','evidencehash',?,?,'old','[]')", stamp, stamp); e != nil {
		t.Fatal(e)
	}
	if _, e = db.Exec("INSERT INTO run_docs(run_id,source_doc_id,fresh) VALUES('old',1,1)"); e != nil {
		t.Fatal(e)
	}
	if _, e = db.Exec("INSERT INTO run_sightings(run_id,sighting_id) VALUES('old',1)"); e != nil {
		t.Fatal(e)
	}
	db.Close()
	upgraded, e := Open(path)
	if e != nil {
		t.Fatal(e)
	}
	defer upgraded.Close()
	cs, e := upgraded.Candidates("old", "", 0)
	if e != nil || len(cs) != 1 || len(cs[0].Evidence) != 1 || cs[0].Evidence[0].Excerpt != "real evidence" {
		t.Fatalf("migration lost source evidence: %+v %v", cs, e)
	}
	var version int
	if e = upgraded.DB.QueryRow("PRAGMA user_version").Scan(&version); e != nil || version != 3 {
		t.Fatalf("migration version %d %v", version, e)
	}
	if _, _, e = upgraded.Lookup("missing"); e != nil {
		t.Fatalf("cache schema unavailable after upgrade: %v", e)
	}
}

func TestHumanReviewAuditSurvivesRefreshAndBackup(t *testing.T) {
	s := openStore(t)
	startRun(t, s, "first")
	d := document("https://github.com/one/list", "github:one", time.Now().UTC())
	h := hit("candidate.example")
	if _, e := s.Ingest("first", d, []model.Hit{h}); e != nil {
		t.Fatal(e)
	}
	if e := s.Review(h.Host, "confirmed_benign", "Parent checked legitimate university service; token=secret-value"); e != nil {
		t.Fatal(e)
	}
	startRun(t, s, "second")
	h.Classification = "likely_proxy"
	h.Score = 95
	d.URL = "https://github.com/second/list"
	d.Text = "independent new claim"
	d.RetrievedAt = time.Now().UTC()
	if _, e := s.Ingest("second", d, []model.Hit{h}); e != nil {
		t.Fatal(e)
	}
	cs, e := s.Candidates("", h.Host, 0)
	if e != nil || len(cs) != 1 || cs[0].Classification != "confirmed_benign" || cs[0].Score != 0 || cs[0].ReviewStatus != "reviewed" {
		t.Fatalf("refresh overwrote review: %+v %v", cs, e)
	}
	reviews, e := s.Reviews(h.Host)
	if e != nil || len(reviews) != 1 || reviews[0]["classification"] != "confirmed_benign" || strings.Contains(reviews[0]["rationale"], "secret-value") {
		t.Fatalf("review audit/redaction: %+v %v", reviews, e)
	}
	for _, x := range []struct{ host, status, rationale string }{{h.Host, "invalid", "reason"}, {h.Host, "confirmed_unsafe", ""}, {"absent.example", "confirmed_benign", "reason"}} {
		if e = s.Review(x.host, x.status, x.rationale); e == nil {
			t.Fatalf("invalid review accepted: %+v", x)
		}
	}
	if count(t, s, "reviews") != 1 {
		t.Fatal("invalid review mutated audit")
	}
	backupPath := filepath.Join(t.TempDir(), "backup", "catalog.db")
	if e = s.Backup(backupPath); e != nil {
		t.Fatal(e)
	}
	if e = s.Backup(backupPath); e == nil {
		t.Fatal("backup overwrote existing file")
	}
	info, e := os.Stat(backupPath)
	if e != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("backup permissions %v %v", info, e)
	}
	backup, e := Open(backupPath)
	if e != nil {
		t.Fatal(e)
	}
	defer backup.Close()
	copy, e := backup.Candidates("", h.Host, 0)
	if e != nil || len(copy) != 1 || copy[0].Classification != "confirmed_benign" || len(copy[0].Evidence) != 2 {
		t.Fatalf("backup did not preserve catalog/evidence: %+v %v", copy, e)
	}
	history, e := backup.History(h.Host)
	if e != nil || len(history) != 2 {
		t.Fatalf("backup lost run history: %+v %v", history, e)
	}
	if count(t, backup, "reviews") != 1 {
		t.Fatal("backup lost audit")
	}
}

func TestIdenticalContentMirrorsShareIndependentGroup(t *testing.T) {
	s := openStore(t)
	startRun(t, s, "first")
	stamp := time.Now().UTC()
	for _, key := range []string{"github:one", "github:two", "forum:three"} {
		d := document("https://public-source.net/"+key, key, stamp)
		if _, e := s.Ingest("first", d, []model.Hit{hit("candidate.example")}); e != nil {
			t.Fatal(e)
		}
	}
	cs, e := s.Candidates("first", "", 0)
	if e != nil || len(cs) != 1 || cs[0].IndependentSources != 1 || len(cs[0].Evidence) != 3 {
		t.Fatalf("copied content inflated independence: %+v %v", cs, e)
	}
}

// Compare meaning, not a serialization detail such as fixed or trimmed nanos.
func sameTimestamp(raw string, expected time.Time) bool {
	parsed, err := time.Parse(time.RFC3339Nano, raw)
	return err == nil && parsed.Equal(expected)
}

func TestFractionalTimestampOrderingAndLegacyNormalization(t *testing.T) {
	early, err := time.Parse(time.RFC3339Nano, "2026-10-12T00:00:00.1Z")
	if err != nil {
		t.Fatal(err)
	}
	late, err := time.Parse(time.RFC3339Nano, "2026-10-12T00:00:00.15Z")
	if err != nil {
		t.Fatal(err)
	}
	// Variable precision reverses string order, despite late being 50ms later.
	if early.Format(time.RFC3339Nano) <= late.Format(time.RFC3339Nano) {
		t.Fatal("regression fixture does not expose lexical reversal")
	}
	path := filepath.Join(t.TempDir(), "legacy.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { s.Close() }()
	key := fetch.Hash([]byte("fractional source"))
	for i, stamp := range []time.Time{early, late} {
		id := []string{"early", "late"}[i]
		startRun(t, s, id)
		d := cachedDocument("https://github.com/source/list", key, id, stamp)
		if _, err = s.Ingest(id, d, []model.Hit{hit(id + ".example")}); err != nil {
			t.Fatal(err)
		}
	}
	if err = s.Put(key, fetch.CacheEntry{ETag: `"first"`, ValidatedAt: early}); err != nil {
		t.Fatal(err)
	}
	if ok, err := s.HasEvidence(key); err != nil || !ok {
		t.Fatalf("later evidence sorts before earlier cache validation: %v %v", ok, err)
	}
	// Simulate existing V3 timestamps written before the format correction.
	if _, err = s.DB.Exec("UPDATE source_docs SET retrieved_at=CASE content_hash WHEN ? THEN ? ELSE ? END", fetch.Hash([]byte("late")), late.Format(time.RFC3339Nano), early.Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	if _, err = s.DB.Exec("UPDATE fetch_cache SET validated_at=? WHERE cache_key=?", early.Format(time.RFC3339Nano), key); err != nil {
		t.Fatal(err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := s.HasEvidence(key); err != nil || !ok {
		t.Fatalf("legacy normalization changed evidence semantics: %v %v", ok, err)
	}
	var storedEarly, storedLate string
	if err = s.DB.QueryRow("SELECT MIN(retrieved_at),MAX(retrieved_at) FROM source_docs WHERE fetch_key=?", key).Scan(&storedEarly, &storedLate); err != nil {
		t.Fatal(err)
	}
	if !sameTimestamp(storedEarly, early) || !sameTimestamp(storedLate, late) || len(storedEarly) != 30 || len(storedLate) != 30 {
		t.Fatalf("legacy timestamps remain misordered: %q -> %q", storedEarly, storedLate)
	}
	startRun(t, s, "reuse")
	docs, hosts, sightings, err := s.Reuse("reuse", model.Reuse{Family: "github", Key: key, RetrievedAt: late, CacheState: "ttl"})
	if err != nil || docs != 1 || hosts != 1 || sightings != 1 {
		t.Fatalf("fractional reuse metrics: %d %d %d %v", docs, hosts, sightings, err)
	}
	cs, err := s.Candidates("reuse", "", 0)
	if err != nil || len(cs) != 1 || cs[0].Host != "late.example" || !sameTimestamp(cs[0].LastSeen, late) {
		t.Fatalf("lexical ordering resurrected earlier source version: %+v %v", cs, err)
	}
}
