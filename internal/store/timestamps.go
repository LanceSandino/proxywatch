// Package store persists discovery runs, candidates, evidence, reviews, and migrations.
// Inputs: legacy and current RFC3339 timestamps stored in SQLite.
// Outputs: fixed-precision UTC values whose lexical and chronological orders agree.
package store

import (
	"database/sql"
	"time"
)

// Fixed nanosecond precision makes SQLite's lexicographic order chronological.
const timestampLayout = "2006-01-02T15:04:05.000000000Z"

func canonicalTimestamp(raw string) string {
	if t, e := time.Parse(time.RFC3339Nano, raw); e == nil {
		return t.UTC().Format(timestampLayout)
	}
	return raw
}
func (s *Store) normalizeTimestamps() error {
	tx, e := s.DB.Begin()
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if e = normalizeTimestampTx(tx); e != nil {
		return e
	}
	return tx.Commit()
}
func normalizeTimestampTx(tx *sql.Tx) error {
	for _, spec := range []struct {
		table, key string
		cols       []string
	}{
		{"runs", "id", []string{"started_at", "finished_at"}},
		{"source_docs", "id", []string{"retrieved_at"}},
		{"candidates", "id", []string{"first_seen", "last_seen", "reviewed_at"}},
		{"sightings", "id", []string{"discovered_at", "last_seen"}},
		{"reviews", "id", []string{"reviewed_at"}},
		{"fetch_cache", "cache_key", []string{"validated_at"}},
		{"source_checkpoints", "source_type", []string{"last_completed_at"}},
		{"vocabulary", "term", []string{"first_seen"}},
	} {
		for _, col := range spec.cols {
			rows, e := tx.Query("SELECT " + spec.key + "," + col + " FROM " + spec.table + " WHERE " + col + " IS NOT NULL AND length(" + col + ")!=30")
			if e != nil {
				return e
			}
			type item struct {
				key   any
				stamp string
			}
			var changes []item
			for rows.Next() {
				var x item
				if e = rows.Scan(&x.key, &x.stamp); e != nil {
					rows.Close()
					return e
				}
				next := canonicalTimestamp(x.stamp)
				if next != x.stamp {
					x.stamp = next
					changes = append(changes, x)
				}
			}
			e = rows.Err()
			rows.Close()
			if e != nil {
				return e
			}
			for _, x := range changes {
				if _, e = tx.Exec("UPDATE "+spec.table+" SET "+col+"=? WHERE "+spec.key+"=?", x.stamp, x.key); e != nil {
					return e
				}
			}
		}
	}
	return nil
}
