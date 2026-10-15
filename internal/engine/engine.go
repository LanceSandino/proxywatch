// Package engine orchestrates bounded source collection and evidence persistence.
// Inputs: validated configuration, selected adapters, run mode, and a SQLite store.
// Outputs: discovery run metrics, durable findings, source errors, and refresh state.
package engine

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"proxywatch/internal/config"
	"proxywatch/internal/extract"
	"proxywatch/internal/fetch"
	"proxywatch/internal/model"
	"proxywatch/internal/sources"
	"proxywatch/internal/store"
	"strings"
	"time"
)

func Discover(ctx context.Context, cfg config.Config, st *store.Store, names []string, offline bool) (r model.Run, err error) {
	for i := range names {
		names[i] = strings.ToLower(strings.TrimSpace(names[i]))
	}
	if len(names) == 0 {
		return r, fmt.Errorf("select at least one source")
	}
	for _, n := range names {
		if offline && n != "fixtures" {
			return r, fmt.Errorf("offline mode only permits fixtures")
		}
		if n == "fixtures" && !offline {
			return r, fmt.Errorf("fixtures require explicit --offline and a separate database")
		}
		if offline && len(names) != 1 {
			return r, fmt.Errorf("do not mix synthetic and live sources")
		}
	}
	b, _ := json.Marshal(cfg)
	originalHash := fetch.Hash(b)
	if cfg.ExpandQueries && !offline {
		vs, e := st.Vocabulary()
		if e != nil {
			return r, e
		}
		seen := map[string]bool{}
		for _, q := range cfg.Queries {
			seen[strings.ToLower(q)] = true
		}
		for _, v := range vs {
			if !seen[strings.ToLower(v["term"])] && len(cfg.Queries) < 50 {
				cfg.Queries = append(cfg.Queries, v["term"])
				seen[strings.ToLower(v["term"])] = true
			}
		}
	}
	cursor, e := st.QueryCursor(originalHash)
	if e != nil {
		return r, e
	}
	if len(cfg.Queries) > 0 {
		cursor = cursor % len(cfg.Queries)
		cfg.Queries = append(append([]string{}, cfg.Queries[cursor:]...), cfg.Queries[:cursor]...)
	}
	id := make([]byte, 12)
	if _, err = rand.Read(id); err != nil {
		return r, err
	}
	r = model.Run{ID: time.Now().UTC().Format("20060102T150405") + "-" + hex.EncodeToString(id), StartedAt: time.Now().UTC().Format(time.RFC3339Nano), ConfigHash: fetch.Hash(b), Synthetic: offline, Sources: map[string]*model.SourceStats{}}
	if err = st.Start(r); err != nil {
		return r, err
	}
	defer func() {
		r.FinishedAt = time.Now().UTC().Format(time.RFC3339Nano)
		if err != nil {
			r.Status = "failed"
		}
		if e := st.Finish(r); e != nil && err == nil {
			err = e
		}
		if err == nil {
			if e := st.Checkpoint(r); e != nil {
				err = e
			}
			if len(cfg.Queries) > 0 {
				if e := st.AdvanceQueryCursor(originalHash, (cursor+cfg.MaxQueries)%len(cfg.Queries)); e != nil {
					err = e
				}
			}
		}
	}()
	client := fetch.New(cfg)
	if !offline {
		client.SetCache(st, time.Duration(cfg.CacheHours)*time.Hour)
	}
	result := sources.Collect(ctx, cfg, client, names)
	r.Queries = result.Queries
	for _, n := range names {
		r.Sources[n] = &model.SourceStats{}
	}
	for n, a := range result.SourceAttempts {
		if r.Sources[n] == nil {
			r.Sources[n] = &model.SourceStats{}
		}
		r.Sources[n].Attempts = a
	}
	for n, a := range result.NetworkRequests {
		if r.Sources[n] == nil {
			r.Sources[n] = &model.SourceStats{}
		}
		r.Sources[n].NetworkRequests = a
	}
	for _, e := range result.Errors {
		if r.Sources[e.Family] == nil {
			r.Sources[e.Family] = &model.SourceStats{}
		}
		r.Sources[e.Family].Errors = append(r.Sources[e.Family].Errors, e)
		if err = st.Error(r.ID, e); err != nil {
			return r, err
		}
	}
	hosts := map[string]bool{}
	familyHosts := map[string]map[string]bool{}
	for _, d := range result.Documents {
		if d.Synthetic != r.Synthetic {
			return r, fmt.Errorf("source provenance does not match run mode")
		}
		if r.Sources[d.Family] == nil {
			r.Sources[d.Family] = &model.SourceStats{}
		}
		stats := r.Sources[d.Family]
		stats.Documents++
		if !d.Cached && !d.Synthetic {
			stats.FreshDocuments++
		}
		hits, discarded := extract.Document(d)
		stats.Extracted += len(hits)
		stats.Discarded += discarded
		if len(hits) > 0 {
			stats.CandidateDocuments++
		}
		newHosts, e := st.Ingest(r.ID, d, hits)
		if e != nil {
			return r, e
		}
		r.NewHosts += newHosts
		if err = st.LearnVocabulary(d); err != nil {
			return r, err
		}
		if familyHosts[d.Family] == nil {
			familyHosts[d.Family] = map[string]bool{}
		}
		for _, h := range hits {
			r.Sightings++
			if hosts[h.Host] {
				r.DuplicateHits++
			}
			hosts[h.Host] = true
			familyHosts[d.Family][h.Host] = true
		}
	}
	for _, v := range result.Reused {
		docs, _, sightings, e := st.Reuse(r.ID, v)
		if e != nil {
			return r, e
		}
		if r.Sources[v.Family] == nil {
			r.Sources[v.Family] = &model.SourceStats{}
		}
		stats := r.Sources[v.Family]
		stats.Documents += docs
		stats.Extracted += sightings
		stats.CacheHits++
		if v.CacheState == "not_modified" {
			stats.Revalidated++
		}
	}
	// Derive final per-run counts from persisted sightings so cache reuse cannot
	// masquerade as newly extracted/fresh documents or create duplicate identities.
	persisted, e := st.Candidates(r.ID, "", 0)
	if e != nil {
		return r, e
	}
	hosts = map[string]bool{}
	familyHosts = map[string]map[string]bool{}
	for _, c := range persisted {
		hosts[c.Host] = true
		for _, ev := range c.Evidence {
			if familyHosts[ev.SourceType] == nil {
				familyHosts[ev.SourceType] = map[string]bool{}
			}
			familyHosts[ev.SourceType][c.Host] = true
		}
	}
	for f, hs := range familyHosts {
		r.Sources[f].UniqueHosts = len(hs)
	}
	docStats, e := st.RunDocumentStats(r.ID)
	if e != nil {
		return r, e
	}
	for family, counts := range docStats {
		if r.Sources[family] == nil {
			r.Sources[family] = &model.SourceStats{}
		}
		r.Sources[family].Documents = counts.Documents
		r.Sources[family].FreshDocuments = counts.FreshDocuments
		r.Sources[family].CandidateDocuments = counts.CandidateDocuments
	}
	r.UniqueHosts = len(hosts)
	r.Sightings, err = st.RunSightingCount(r.ID)
	if err != nil {
		return r, err
	}
	r.DuplicateHits = r.Sightings - r.UniqueHosts
	r.Status = "complete"
	if ctx.Err() != nil {
		r.Status = "cancelled"
		return r, ctx.Err()
	}
	if len(result.Errors) > 0 {
		r.Status = "partial"
	}
	return r, nil
}
