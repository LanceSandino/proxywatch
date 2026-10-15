CREATE TABLE runs (
 id TEXT PRIMARY KEY, started_at TEXT NOT NULL, finished_at TEXT, status TEXT NOT NULL,
 config_hash TEXT NOT NULL, synthetic INTEGER NOT NULL CHECK(synthetic IN(0,1)), metrics_json TEXT NOT NULL DEFAULT '{}'
);
CREATE TABLE source_docs (
 id INTEGER PRIMARY KEY, type TEXT NOT NULL, external_id TEXT NOT NULL, canonical_url TEXT NOT NULL,
 query TEXT NOT NULL, retrieved_at TEXT NOT NULL, content_hash TEXT NOT NULL, independence_key TEXT NOT NULL,
 synthetic INTEGER NOT NULL CHECK(synthetic IN(0,1)), fetch_status TEXT NOT NULL DEFAULT 'ok',
 UNIQUE(type,canonical_url,content_hash,synthetic)
);
CREATE TABLE run_docs (
 run_id TEXT NOT NULL REFERENCES runs(id), source_doc_id INTEGER NOT NULL REFERENCES source_docs(id),
 fresh INTEGER NOT NULL CHECK(fresh IN(0,1)), PRIMARY KEY(run_id,source_doc_id)
);
CREATE TABLE candidates (
 id INTEGER PRIMARY KEY, normalized_host TEXT NOT NULL UNIQUE, registrable_domain TEXT NOT NULL,
 first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
 classification TEXT NOT NULL CHECK(classification IN ('discovered','needs_review','likely_proxy','confirmed_benign','confirmed_unsafe')),
 review_status TEXT NOT NULL DEFAULT 'unreviewed', score INTEGER NOT NULL DEFAULT 0, reviewed_at TEXT
);
CREATE TABLE sightings (
 id INTEGER PRIMARY KEY, candidate_id INTEGER NOT NULL REFERENCES candidates(id), source_doc_id INTEGER NOT NULL REFERENCES source_docs(id),
 raw_value_sanitized TEXT NOT NULL, excerpt_sanitized TEXT NOT NULL, field TEXT NOT NULL, evidence_hash TEXT NOT NULL UNIQUE,
 discovered_at TEXT NOT NULL, last_seen TEXT NOT NULL, first_run_id TEXT NOT NULL REFERENCES runs(id), signals_json TEXT NOT NULL
);
CREATE TABLE run_sightings (
 run_id TEXT NOT NULL REFERENCES runs(id), sighting_id INTEGER NOT NULL REFERENCES sightings(id),
 PRIMARY KEY(run_id,sighting_id)
);
CREATE TABLE source_errors (
 id INTEGER PRIMARY KEY, run_id TEXT NOT NULL REFERENCES runs(id), source_type TEXT NOT NULL, source_ref TEXT NOT NULL,
 code TEXT NOT NULL, message_redacted TEXT NOT NULL
);
CREATE TABLE reviews (
 id INTEGER PRIMARY KEY, candidate_id INTEGER NOT NULL REFERENCES candidates(id), disposition TEXT NOT NULL,
 rationale TEXT NOT NULL, reviewed_at TEXT NOT NULL
);
CREATE INDEX idx_candidate_seen ON candidates(last_seen);
CREATE INDEX idx_candidate_review ON candidates(review_status);
CREATE INDEX idx_docs_type ON source_docs(type);
CREATE INDEX idx_sightings_candidate ON sightings(candidate_id);
PRAGMA user_version=1;
