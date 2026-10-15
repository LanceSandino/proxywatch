// Package store persists discovery runs, candidates, evidence, reviews, and migrations.
// Inputs: V1 cache, checkpoint, history, comparison, review, and backup operations.
// Outputs: durable incremental state and operator-facing catalog views.
package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"proxywatch/internal/extract"
	"proxywatch/internal/fetch"
	"proxywatch/internal/model"
	"strings"
	"time"
)

func (s *Store) Lookup(key string) (fetch.CacheEntry, bool, error) {
	var c fetch.CacheEntry
	var stamp string
	e := s.DB.QueryRow("SELECT etag,last_modified,validated_at FROM fetch_cache WHERE cache_key=?", key).Scan(&c.ETag, &c.LastModified, &stamp)
	if e == sql.ErrNoRows {
		return c, false, nil
	}
	if e != nil {
		return c, false, e
	}
	c.ValidatedAt, e = time.Parse(time.RFC3339Nano, stamp)
	return c, e == nil, e
}
func (s *Store) Put(key string, c fetch.CacheEntry) error {
	_, e := s.DB.Exec(`INSERT INTO fetch_cache(cache_key,etag,last_modified,validated_at) VALUES(?,?,?,?) ON CONFLICT(cache_key) DO UPDATE SET etag=excluded.etag,last_modified=excluded.last_modified,validated_at=excluded.validated_at`, key, c.ETag, c.LastModified, c.ValidatedAt.UTC().Format(timestampLayout))
	return e
}
func (s *Store) HasEvidence(key string) (bool, error) {
	var n int
	e := s.DB.QueryRow("SELECT COUNT(*) FROM source_docs d JOIN fetch_cache c ON c.cache_key=d.fetch_key WHERE d.fetch_key=? AND d.synthetic=0 AND d.retrieved_at>=c.validated_at", key).Scan(&n)
	return n > 0, e
}

// Reuse adds existing sanitized evidence to a refresh run; no source body is kept.
func (s *Store) Reuse(run string, v model.Reuse) (docs, hosts, sightings int, err error) {
	tx, e := s.DB.Begin()
	if e != nil {
		return 0, 0, 0, e
	}
	defer tx.Rollback()
	rows, e := tx.Query("SELECT id FROM source_docs d WHERE fetch_key=? AND type=? AND synthetic=0 AND retrieved_at=(SELECT MAX(retrieved_at) FROM source_docs WHERE fetch_key=d.fetch_key AND type=d.type)", v.Key, v.Family)
	if e != nil {
		return 0, 0, 0, e
	}
	var ids []int64
	for rows.Next() {
		var id int64
		if e = rows.Scan(&id); e != nil {
			rows.Close()
			return 0, 0, 0, e
		}
		ids = append(ids, id)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return 0, 0, 0, e
	}
	if len(ids) == 0 {
		return 0, 0, 0, fmt.Errorf("cache lacks processed source evidence")
	}
	now := v.RetrievedAt.UTC().Format(timestampLayout)
	for _, id := range ids {
		if _, e = tx.Exec("INSERT OR IGNORE INTO run_docs(run_id,source_doc_id,fresh) VALUES(?,?,0)", run, id); e != nil {
			return 0, 0, 0, e
		}
		if _, e = tx.Exec("INSERT OR IGNORE INTO run_sightings(run_id,sighting_id) SELECT ?,id FROM sightings WHERE source_doc_id=?", run, id); e != nil {
			return 0, 0, 0, e
		}
		// TTL cache reuse carries the original validation timestamp; a remote 304
		// carries a current timestamp. Only the latter advances freshness.
		if _, e = tx.Exec("UPDATE source_docs SET retrieved_at=MAX(retrieved_at,?) WHERE id=?", now, id); e != nil {
			return 0, 0, 0, e
		}
		if _, e = tx.Exec("UPDATE sightings SET last_seen=MAX(last_seen,?) WHERE source_doc_id=?", now, id); e != nil {
			return 0, 0, 0, e
		}
		if _, e = tx.Exec("UPDATE candidates SET last_seen=MAX(last_seen,?) WHERE id IN (SELECT candidate_id FROM sightings WHERE source_doc_id=?)", now, id); e != nil {
			return 0, 0, 0, e
		}
	}
	docs = len(ids)
	e = tx.QueryRow("SELECT COUNT(DISTINCT candidate_id),COUNT(*) FROM sightings WHERE source_doc_id IN (SELECT id FROM source_docs WHERE fetch_key=? AND type=? AND retrieved_at=(SELECT MAX(retrieved_at) FROM source_docs WHERE fetch_key=? AND type=?))", v.Key, v.Family, v.Key, v.Family).Scan(&hosts, &sightings)
	if e != nil {
		return 0, 0, 0, e
	}
	return docs, hosts, sightings, tx.Commit()
}
func (s *Store) Checkpoint(r model.Run) error {
	tx, e := s.DB.Begin()
	if e != nil {
		return e
	}
	defer tx.Rollback()
	for f, v := range r.Sources {
		b, e := json.Marshal(v)
		if e != nil {
			return e
		}
		status := "ok"
		if len(v.Errors) > 0 {
			status = "partial"
		}
		if _, e = tx.Exec(`INSERT INTO source_checkpoints(source_type,last_run_id,last_completed_at,status,metrics_json) VALUES(?,?,?,?,?) ON CONFLICT(source_type) DO UPDATE SET last_run_id=excluded.last_run_id,last_completed_at=excluded.last_completed_at,status=excluded.status,metrics_json=excluded.metrics_json`, f, r.ID, r.FinishedAt, status, string(b)); e != nil {
			return e
		}
	}
	return tx.Commit()
}
func (s *Store) Checkpoints() ([]map[string]any, error) {
	rows, e := s.DB.Query("SELECT source_type,last_run_id,last_completed_at,status,metrics_json FROM source_checkpoints ORDER BY source_type")
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var f, r, t, status, raw string
		if e = rows.Scan(&f, &r, &t, &status, &raw); e != nil {
			return nil, e
		}
		var stats model.SourceStats
		if e = json.Unmarshal([]byte(raw), &stats); e != nil {
			return nil, e
		}
		out = append(out, map[string]any{"source_type": f, "last_run_id": r, "last_completed_at": t, "status": status, "stats": stats})
	}
	return out, rows.Err()
}
func (s *Store) QueryCursor(key string) (int, error) {
	var p int
	e := s.DB.QueryRow("SELECT position FROM query_cursors WHERE config_hash=?", key).Scan(&p)
	if e == sql.ErrNoRows {
		return 0, nil
	}
	return p, e
}
func (s *Store) AdvanceQueryCursor(key string, p int) error {
	_, e := s.DB.Exec("INSERT INTO query_cursors(config_hash,position) VALUES(?,?) ON CONFLICT(config_hash) DO UPDATE SET position=excluded.position", key, p)
	return e
}

var terms = []string{"Doge Unblocker", "Holy Unblocker", "node-unblocker", "Shuttle proxy", "Nebula proxy", "Incognito proxy", "Shadow proxy", "Art Class proxy"}

func (s *Store) LearnVocabulary(d model.Document) error {
	if d.Synthetic {
		return nil
	}
	lower := strings.ToLower(d.Text)
	for _, term := range terms {
		i := strings.Index(lower, strings.ToLower(term))
		if i < 0 {
			continue
		}
		start, end := i-50, i+len(term)+80
		if start < 0 {
			start = 0
		}
		if end > len(d.Text) {
			end = len(d.Text)
		}
		ex := extract.Redact(strings.ToValidUTF8(d.Text[start:end], ""))
		_, e := s.DB.Exec("INSERT OR IGNORE INTO vocabulary(term,source_url,evidence_excerpt,first_seen) VALUES(?,?,?,?)", term, d.URL, ex, d.RetrievedAt.UTC().Format(timestampLayout))
		if e != nil {
			return e
		}
	}
	return nil
}
func (s *Store) Vocabulary() ([]map[string]string, error) {
	rows, e := s.DB.Query("SELECT term,source_url,evidence_excerpt,first_seen FROM vocabulary ORDER BY term LIMIT 8")
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []map[string]string{}
	for rows.Next() {
		var t, u, ex, seen string
		if e = rows.Scan(&t, &u, &ex, &seen); e != nil {
			return nil, e
		}
		out = append(out, map[string]string{"term": t, "source_url": u, "excerpt": ex, "first_seen": seen})
	}
	return out, rows.Err()
}

// Group shared origin keys and identical-content mirrors using connected groups.
func independentGroups(ev []model.Evidence) int {
	parent := map[string]string{}
	var find func(string) string
	find = func(k string) string {
		if _, ok := parent[k]; !ok {
			parent[k] = k
		}
		if parent[k] != k {
			parent[k] = find(parent[k])
		}
		return parent[k]
	}
	for _, v := range ev {
		if v.Synthetic {
			continue
		}
		a, b := find("origin:"+v.IndependenceKey), find("body:"+v.ContentHash)
		if a != b {
			parent[b] = a
		}
	}
	roots := map[string]bool{}
	for k := range parent {
		roots[find(k)] = true
	}
	return len(roots)
}
func rank(c *model.Candidate) {
	weight := 0
	benign := false
	for _, v := range c.Evidence {
		if v.Synthetic {
			continue
		}
		w := 10
		switch v.SourceType {
		case "github":
			w = 25
		case "youtube":
			w = 20
		case "forum", "flarum":
			w = 15
		}
		if w > weight {
			weight = w
		}
		for _, sig := range v.Signals {
			if sig == "benign_or_multiuse_context_requires_review" {
				benign = true
			}
		}
	}
	c.SourceConfidence = weight // Heuristic source weight, never a probability.
	if c.ReviewStatus != "unreviewed" {
		return
	}
	if benign {
		c.Classification = "needs_review"
		c.Score = 0
		return
	}
	if c.Score == 0 {
		return
	}
	bonus := c.IndependentSources - 1
	if bonus < 0 {
		bonus = 0
	}
	if bonus > 2 {
		bonus = 2
	}
	c.Score += bonus*15 + weight
	if c.Score > 95 {
		c.Score = 95
	}
}
func (s *Store) Review(host, status, rationale string) error {
	allowed := map[string]bool{"discovered": true, "needs_review": true, "likely_proxy": true, "confirmed_benign": true, "confirmed_unsafe": true}
	if !allowed[status] || strings.TrimSpace(rationale) == "" {
		return fmt.Errorf("review requires valid classification and rationale")
	}
	tx, e := s.DB.Begin()
	if e != nil {
		return e
	}
	defer tx.Rollback()
	var id int64
	if e = tx.QueryRow("SELECT id FROM candidates WHERE normalized_host=?", host).Scan(&id); e != nil {
		return fmt.Errorf("hostname not in catalog")
	}
	now := time.Now().UTC().Format(timestampLayout)
	if _, e = tx.Exec("INSERT INTO reviews(candidate_id,disposition,rationale,reviewed_at) VALUES(?,?,?,?)", id, status, extract.Redact(rationale), now); e != nil {
		return e
	}
	score := 0
	if status == "confirmed_unsafe" {
		score = 100
	}
	if _, e = tx.Exec("UPDATE candidates SET classification=?,review_status='reviewed',score=?,reviewed_at=? WHERE id=?", status, score, now, id); e != nil {
		return e
	}
	return tx.Commit()
}
func (s *Store) History(host string) ([]map[string]string, error) {
	rows, e := s.DB.Query(`SELECT r.id,r.started_at,r.status FROM runs r WHERE r.id IN (SELECT rs.run_id FROM run_sightings rs JOIN sightings sg ON sg.id=rs.sighting_id JOIN candidates c ON c.id=sg.candidate_id WHERE c.normalized_host=?) ORDER BY r.started_at`, host)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []map[string]string{}
	for rows.Next() {
		var id, t, status string
		if e = rows.Scan(&id, &t, &status); e != nil {
			return nil, e
		}
		out = append(out, map[string]string{"run_id": id, "started_at": t, "status": status})
	}
	return out, rows.Err()
}
func (s *Store) Reviews(host string) ([]map[string]string, error) {
	rows, e := s.DB.Query("SELECT disposition,rationale,reviewed_at FROM reviews WHERE candidate_id=(SELECT id FROM candidates WHERE normalized_host=?) ORDER BY reviewed_at", host)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []map[string]string{}
	for rows.Next() {
		var d, r, t string
		if e = rows.Scan(&d, &r, &t); e != nil {
			return nil, e
		}
		out = append(out, map[string]string{"classification": d, "rationale": r, "reviewed_at": t})
	}
	return out, rows.Err()
}
func (s *Store) Backup(path string) error {
	if _, e := os.Stat(path); e == nil {
		return fmt.Errorf("backup destination already exists")
	}
	if e := os.MkdirAll(filepath.Dir(path), 0700); e != nil {
		return e
	}
	if _, e := s.DB.Exec("VACUUM INTO ?", path); e != nil {
		return e
	}
	return os.Chmod(path, 0600)
}
func (s *Store) RunSightingCount(run string) (int, error) {
	var n int
	e := s.DB.QueryRow("SELECT COUNT(*) FROM run_sightings WHERE run_id=?", run).Scan(&n)
	return n, e
}
func (s *Store) RequireRun(run string) error {
	var n int
	if e := s.DB.QueryRow("SELECT COUNT(*) FROM runs WHERE id=?", run).Scan(&n); e != nil {
		return e
	}
	if n == 0 {
		return fmt.Errorf("unknown run ID")
	}
	return nil
}
func (s *Store) RunDocumentStats(run string) (map[string]model.SourceStats, error) {
	rows, e := s.DB.Query(`SELECT d.type,COUNT(*),SUM(rd.fresh),SUM(CASE WHEN EXISTS(SELECT 1 FROM sightings sg JOIN run_sightings rs ON rs.sighting_id=sg.id WHERE sg.source_doc_id=d.id AND rs.run_id=rd.run_id) THEN 1 ELSE 0 END) FROM run_docs rd JOIN source_docs d ON d.id=rd.source_doc_id WHERE rd.run_id=? GROUP BY d.type`, run)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := map[string]model.SourceStats{}
	for rows.Next() {
		var f string
		var stats model.SourceStats
		if e = rows.Scan(&f, &stats.Documents, &stats.FreshDocuments, &stats.CandidateDocuments); e != nil {
			return nil, e
		}
		out[f] = stats
	}
	return out, rows.Err()
}
