ALTER TABLE source_docs ADD COLUMN fetch_key TEXT NOT NULL DEFAULT '';
CREATE INDEX idx_docs_fetch_key ON source_docs(fetch_key);
-- HTTP validator metadata only: no raw API responses, bodies or identities.
CREATE TABLE fetch_cache (
 cache_key TEXT PRIMARY KEY, etag TEXT NOT NULL, last_modified TEXT NOT NULL, validated_at TEXT NOT NULL
);
CREATE TABLE source_checkpoints (
 source_type TEXT PRIMARY KEY, last_run_id TEXT NOT NULL REFERENCES runs(id), last_completed_at TEXT NOT NULL,
 status TEXT NOT NULL, metrics_json TEXT NOT NULL
);
CREATE TABLE query_cursors (
 config_hash TEXT PRIMARY KEY, position INTEGER NOT NULL CHECK(position>=0)
);
CREATE TABLE vocabulary (
 term TEXT PRIMARY KEY, source_url TEXT NOT NULL, evidence_excerpt TEXT NOT NULL, first_seen TEXT NOT NULL
);
PRAGMA user_version=3;
