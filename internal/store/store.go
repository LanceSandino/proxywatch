// Package store persists discovery runs, candidates, evidence, reviews, and migrations.
// Inputs: normalized documents, findings, source errors, and operator review actions.
// Outputs: transactional SQLite catalog state and queryable evidence history.
package store

import (
	"database/sql"
	"embed"
	"encoding/json"
	"fmt"
	_ "github.com/mattn/go-sqlite3"
	"os"
	"path/filepath"
	"proxywatch/internal/fetch"
	"proxywatch/internal/model"
	"sort"
	"strings"
	"time"
)

//go:embed migrations/*.sql
var migrations embed.FS

type Store struct{ DB *sql.DB }

func Open(path string) (*Store, error) {
	if path != ":memory:" {
		if e := os.MkdirAll(filepath.Dir(path), 0700); e != nil {
			return nil, e
		}
	}
	dsn := path
	if path != ":memory:" {
		dsn = "file:" + path + "?_journal_mode=WAL&_foreign_keys=on&_busy_timeout=5000"
	}
	db, e := sql.Open("sqlite3", dsn)
	if e != nil {
		return nil, e
	}
	db.SetMaxOpenConns(1)
	s := &Store{DB: db}
	if e = s.migrate(); e != nil {
		db.Close()
		return nil, e
	}
	if path != ":memory:" {
		_ = os.Chmod(path, 0600)
	}
	return s, nil
}
func (s *Store) migrate() error {
	if _, e := s.DB.Exec("PRAGMA foreign_keys=ON"); e != nil {
		return e
	}
	var v int
	if e := s.DB.QueryRow("PRAGMA user_version").Scan(&v); e != nil {
		return e
	}
	if v > 3 {
		return fmt.Errorf("database schema newer than this executable")
	}
	if v == 3 {
		return s.normalizeTimestamps()
	}
	files := []string{"migrations/001_initial.sql", "migrations/002_provenance_guards.sql", "migrations/003_refresh_history.sql"}
	tx, e := s.DB.Begin()
	if e != nil {
		return e
	}
	defer tx.Rollback()
	for _, name := range files[v:] {
		b, e := migrations.ReadFile(name)
		if e != nil {
			return e
		}
		if _, e = tx.Exec(string(b)); e != nil {
			return e
		}
	}
	if e = normalizeTimestampTx(tx); e != nil {
		return e
	}
	return tx.Commit()
}

func (s *Store) Close() error { return s.DB.Close() }
func (s *Store) Start(r model.Run) error {
	var other int
	if e := s.DB.QueryRow("SELECT COUNT(*) FROM runs WHERE synthetic != ?", r.Synthetic).Scan(&other); e != nil {
		return e
	}
	if other > 0 {
		return fmt.Errorf("synthetic and live runs require separate databases")
	}
	_, e := s.DB.Exec("INSERT INTO runs(id,started_at,status,config_hash,synthetic) VALUES(?,?,?,?,?)", r.ID, canonicalTimestamp(r.StartedAt), "running", r.ConfigHash, r.Synthetic)
	return e
}
func (s *Store) Finish(r model.Run) error {
	b, e := json.Marshal(r)
	if e != nil {
		return e
	}
	_, e = s.DB.Exec("UPDATE runs SET finished_at=?,status=?,metrics_json=? WHERE id=?", canonicalTimestamp(r.FinishedAt), r.Status, string(b), r.ID)
	return e
}
func (s *Store) Error(run string, e model.SourceError) error {
	_, err := s.DB.Exec("INSERT INTO source_errors(run_id,source_type,source_ref,code,message_redacted) VALUES(?,?,?,?,?)", run, e.Family, e.Ref, e.Code, e.Message)
	return err
}
func (s *Store) Ingest(run string, d model.Document, hits []model.Hit) (newHosts int, err error) {
	for _, h := range hits {
		if h.Classification != "discovered" && h.Classification != "needs_review" && h.Classification != "likely_proxy" {
			return 0, fmt.Errorf("collector cannot assign confirmed classification")
		}
	}
	tx, e := s.DB.Begin()
	if e != nil {
		return 0, e
	}
	defer tx.Rollback()
	now := d.RetrievedAt.UTC().Format(timestampLayout)
	if d.ContentHash == "" {
		d.ContentHash = fetch.Hash([]byte(d.Text))
	}
	if d.IndependenceKey == "" {
		d.IndependenceKey = d.Family + ":" + d.URL
	}
	_, e = tx.Exec(`INSERT INTO source_docs(type,external_id,canonical_url,query,retrieved_at,content_hash,independence_key,synthetic,fetch_key) VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(type,canonical_url,content_hash,synthetic) DO UPDATE SET retrieved_at=MAX(retrieved_at,excluded.retrieved_at),fetch_key=excluded.fetch_key`, d.Family, d.ExternalID, d.URL, d.Query, now, d.ContentHash, d.IndependenceKey, d.Synthetic, d.FetchKey)
	if e != nil {
		return 0, e
	}
	var docID int64
	e = tx.QueryRow("SELECT id FROM source_docs WHERE type=? AND canonical_url=? AND content_hash=? AND synthetic=?", d.Family, d.URL, d.ContentHash, d.Synthetic).Scan(&docID)
	if e != nil {
		return 0, e
	}
	_, e = tx.Exec("INSERT OR IGNORE INTO run_docs(run_id,source_doc_id,fresh) VALUES(?,?,?)", run, docID, !d.Cached && !d.Synthetic)
	if e != nil {
		return 0, e
	}
	for _, h := range hits {
		res, e := tx.Exec("INSERT OR IGNORE INTO candidates(normalized_host,registrable_domain,first_seen,last_seen,classification,score) VALUES(?,?,?,?,?,?)", h.Host, h.Registrable, now, now, h.Classification, h.Score)
		if e != nil {
			return 0, e
		}
		n, _ := res.RowsAffected()
		newHosts += int(n)
		var cid int64
		if e = tx.QueryRow("SELECT id FROM candidates WHERE normalized_host=?", h.Host).Scan(&cid); e != nil {
			return 0, e
		}
		// Human review always wins. Repeated source claims never confirm unsafe.
		_, e = tx.Exec(`UPDATE candidates SET last_seen=MAX(last_seen,?),score=CASE WHEN review_status='unreviewed' THEN MAX(score,?) ELSE score END,classification=CASE WHEN review_status='unreviewed' AND ? > score THEN ? ELSE classification END WHERE id=?`, now, h.Score, h.Score, h.Classification, cid)
		if e != nil {
			return 0, e
		}
		signals, _ := json.Marshal(h.Signals)
		hash := fetch.Hash([]byte(fmt.Sprintf("%d\x00%d\x00%s\x00%s\x00%s", cid, docID, h.URL, h.Excerpt, h.Field)))
		_, e = tx.Exec(`INSERT INTO sightings(candidate_id,source_doc_id,raw_value_sanitized,excerpt_sanitized,field,evidence_hash,discovered_at,last_seen,first_run_id,signals_json) VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(evidence_hash) DO UPDATE SET last_seen=MAX(last_seen,excluded.last_seen)`, cid, docID, h.URL, h.Excerpt, h.Field, hash, now, now, run, string(signals))
		if e != nil {
			return 0, e
		}
		_, e = tx.Exec("INSERT OR IGNORE INTO run_sightings(run_id,sighting_id) SELECT ?,id FROM sightings WHERE evidence_hash=?", run, hash)
		if e != nil {
			return 0, e
		}
	}
	return newHosts, tx.Commit()
}
func (s *Store) Candidates(run, query string, staleDays int) ([]model.Candidate, error) {
	clause := " WHERE normalized_host LIKE ?"
	args := []any{"%" + query + "%"}
	if run != "" {
		clause += " AND id IN (SELECT candidate_id FROM sightings JOIN run_sightings ON sighting_id=sightings.id WHERE run_id=?)"
		args = append(args, run)
	}
	rows, e := s.DB.Query("SELECT id,normalized_host,registrable_domain,first_seen,last_seen,classification,review_status,score FROM candidates"+clause+" ORDER BY normalized_host", args...)
	if e != nil {
		return nil, e
	}
	type entry struct {
		id int64
		c  model.Candidate
	}
	var entries []entry
	for rows.Next() {
		var x entry
		if e = rows.Scan(&x.id, &x.c.Host, &x.c.Registrable, &x.c.FirstSeen, &x.c.LastSeen, &x.c.Classification, &x.c.ReviewStatus, &x.c.Score); e != nil {
			rows.Close()
			return nil, e
		}
		entries = append(entries, x)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return nil, e
	}
	out := []model.Candidate{}
	for _, x := range entries {
		evidenceSQL := `SELECT d.canonical_url,d.type,d.external_id,s.raw_value_sanitized,s.excerpt_sanitized,s.field,s.signals_json,s.discovered_at,s.last_seen,s.first_run_id,d.content_hash,d.independence_key,d.synthetic FROM sightings s JOIN source_docs d ON d.id=s.source_doc_id WHERE s.candidate_id=? ORDER BY s.discovered_at,d.canonical_url`
		evidenceArgs := []any{x.id}
		if run != "" {
			evidenceSQL = strings.Replace(evidenceSQL, " ORDER BY", " AND s.id IN (SELECT sighting_id FROM run_sightings WHERE run_id=?) ORDER BY", 1)
			evidenceArgs = append(evidenceArgs, run)
		}
		erows, e := s.DB.Query(evidenceSQL, evidenceArgs...)
		if e != nil {
			return nil, e
		}

		for erows.Next() {
			var ev model.Evidence
			var sig string
			e = erows.Scan(&ev.SourceURL, &ev.SourceType, &ev.ExternalID, &ev.OriginalURL, &ev.Excerpt, &ev.Field, &sig, &ev.DiscoveredAt, &ev.LastSeen, &ev.RunID, &ev.ContentHash, &ev.IndependenceKey, &ev.Synthetic)
			if e != nil {
				erows.Close()
				return nil, e
			}
			if e = json.Unmarshal([]byte(sig), &ev.Signals); e != nil {
				erows.Close()
				return nil, e
			}
			x.c.Evidence = append(x.c.Evidence, ev)

		}
		e = erows.Err()
		erows.Close()
		if e != nil {
			return nil, e
		}
		x.c.IndependentSources = independentGroups(x.c.Evidence)
		rank(&x.c)
		seen, _ := time.Parse(time.RFC3339Nano, x.c.LastSeen)
		x.c.Stale = staleDays > 0 && time.Since(seen) > time.Duration(staleDays)*24*time.Hour
		out = append(out, x.c)
	}
	return out, nil
}
func (s *Store) Runs() ([]model.Run, error) {
	rows, e := s.DB.Query("SELECT metrics_json FROM runs WHERE status!='running' ORDER BY started_at")
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []model.Run{}
	for rows.Next() {
		var raw string
		var r model.Run
		if e = rows.Scan(&raw); e != nil {
			return nil, e
		}
		if e = json.Unmarshal([]byte(raw), &r); e != nil {
			return nil, e
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
func (s *Store) RunHosts(run string) ([]string, error) {
	cs, e := s.Candidates(run, "", 0)
	if e != nil {
		return nil, e
	}
	out := []string{}
	for _, c := range cs {
		out = append(out, c.Host)
	}
	sort.Strings(out)
	return out, nil
}
