// Package model defines discovery documents, evidence, candidates, and run reports.
// Inputs: normalized source and persistence data from collection modules.
// Outputs: stable contracts shared by the engine, store, CLI, and exporters.
package model

import "time"

type Document struct {
	FetchKey        string    `json:"fetch_key"`
	Family          string    `json:"source_type"`
	ExternalID      string    `json:"external_id"`
	URL             string    `json:"source_url"`
	Query           string    `json:"query"`
	Text            string    `json:"-"`
	Field           string    `json:"field"`
	IndependenceKey string    `json:"independence_key"`
	RetrievedAt     time.Time `json:"retrieved_at"`
	ContentHash     string    `json:"content_hash"`
	Synthetic       bool      `json:"synthetic"`
	Cached          bool      `json:"cached"`
}
type SourceError struct {
	Family  string `json:"source_type"`
	Ref     string `json:"source_ref"`
	Code    string `json:"code"`
	Message string `json:"message"`
}
type Reuse struct {
	Family      string    `json:"source_type"`
	Key         string    `json:"fetch_key"`
	RetrievedAt time.Time `json:"retrieved_at"`
	CacheState  string    `json:"cache_state"`
}
type Result struct {
	Reused          []Reuse        `json:"reused"`
	NetworkRequests map[string]int `json:"network_requests"`
	Documents       []Document     `json:"documents"`
	Errors          []SourceError  `json:"errors"`
	Attempts        int            `json:"attempts"`
	SourceAttempts  map[string]int `json:"source_attempts"`
	Queries         []string       `json:"queries"`
}
type Hit struct {
	Host           string   `json:"hostname"`
	Registrable    string   `json:"registrable_domain"`
	URL            string   `json:"original_url"`
	Excerpt        string   `json:"evidence_excerpt"`
	Field          string   `json:"field"`
	Signals        []string `json:"signals"`
	Classification string   `json:"classification"`
	Score          int      `json:"score"`
}
type Evidence struct {
	SourceURL       string   `json:"source_url"`
	SourceType      string   `json:"source_type"`
	ExternalID      string   `json:"external_id"`
	OriginalURL     string   `json:"original_url"`
	Excerpt         string   `json:"excerpt"`
	Field           string   `json:"field"`
	Signals         []string `json:"signals"`
	DiscoveredAt    string   `json:"discovered_at"`
	LastSeen        string   `json:"last_seen"`
	RunID           string   `json:"run_id"`
	ContentHash     string   `json:"content_hash"`
	IndependenceKey string   `json:"independence_key"`
	Synthetic       bool     `json:"synthetic"`
}
type Candidate struct {
	SourceConfidence   int        `json:"source_confidence"`
	Host               string     `json:"hostname"`
	Registrable        string     `json:"registrable_domain"`
	FirstSeen          string     `json:"first_seen"`
	LastSeen           string     `json:"last_seen"`
	IndependentSources int        `json:"independent_sources"`
	Classification     string     `json:"classification"`
	ReviewStatus       string     `json:"review_status"`
	Score              int        `json:"score"`
	Stale              bool       `json:"stale"`
	Evidence           []Evidence `json:"evidence"`
}
type SourceStats struct {
	CacheHits          int           `json:"cache_hits"`
	Revalidated        int           `json:"revalidated"`
	NetworkRequests    int           `json:"network_requests"`
	Attempts           int           `json:"attempts"`
	Documents          int           `json:"documents"`
	FreshDocuments     int           `json:"fresh_documents"`
	CandidateDocuments int           `json:"candidate_documents"`
	Extracted          int           `json:"extracted"`
	Discarded          int           `json:"discarded"`
	UniqueHosts        int           `json:"unique_hosts"`
	Errors             []SourceError `json:"errors"`
}
type Run struct {
	ID            string                  `json:"run_id"`
	StartedAt     string                  `json:"started_at"`
	FinishedAt    string                  `json:"finished_at"`
	Status        string                  `json:"status"`
	ConfigHash    string                  `json:"config_hash"`
	Synthetic     bool                    `json:"synthetic"`
	Queries       []string                `json:"queries"`
	Sources       map[string]*SourceStats `json:"sources"`
	UniqueHosts   int                     `json:"unique_hosts"`
	NewHosts      int                     `json:"new_hosts"`
	Sightings     int                     `json:"sightings"`
	DuplicateHits int                     `json:"duplicate_hits"`
}
