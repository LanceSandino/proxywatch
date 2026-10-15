-- Keep offline/parser validation evidence physically separate from live catalogs,
-- including simultaneous first writers and faulty adapters.
CREATE TRIGGER runs_one_mode BEFORE INSERT ON runs
WHEN EXISTS(SELECT 1 FROM runs WHERE synthetic != NEW.synthetic)
BEGIN SELECT RAISE(ABORT, 'synthetic and live runs require separate databases'); END;
CREATE TRIGGER run_docs_match_mode BEFORE INSERT ON run_docs
WHEN (SELECT synthetic FROM source_docs WHERE id=NEW.source_doc_id) !=
     (SELECT synthetic FROM runs WHERE id=NEW.run_id)
BEGIN SELECT RAISE(ABORT, 'source provenance does not match run mode'); END;
PRAGMA user_version=2;
