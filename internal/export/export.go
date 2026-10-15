// Package export serializes run-scoped catalog evidence in operator-selected formats.
// Inputs: ordered candidate records with provenance.
// Outputs: CSV, JSON, or normalized-hostname TXT streams.
package export

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"proxywatch/internal/model"
	"strconv"
)

func Write(w io.Writer, format string, cs []model.Candidate) error {
	switch format {
	case "json":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(cs)
	case "txt":
		for _, c := range cs {
			if _, e := fmt.Fprintln(w, c.Host); e != nil {
				return e
			}
		}
		return nil
	case "csv":
		c := csv.NewWriter(w)
		if e := c.Write([]string{"hostname", "registrable_domain", "first_seen", "last_seen", "independent_sources", "classification", "review_status", "score", "source_confidence", "stale", "source_url", "source_type", "external_id", "original_url", "discovery_timestamp", "evidence_excerpt", "field", "signals", "run_id", "content_hash", "independence_key", "provenance"}); e != nil {
			return e
		}
		for _, x := range cs {
			for _, v := range x.Evidence {
				sig, _ := json.Marshal(v.Signals)
				provenance := "live"
				if v.Synthetic {
					provenance = "SYNTHETIC"
				}
				if e := c.Write([]string{x.Host, x.Registrable, x.FirstSeen, x.LastSeen, strconv.Itoa(x.IndependentSources), x.Classification, x.ReviewStatus, strconv.Itoa(x.Score), strconv.Itoa(x.SourceConfidence), strconv.FormatBool(x.Stale), v.SourceURL, v.SourceType, v.ExternalID, v.OriginalURL, v.DiscoveredAt, v.Excerpt, v.Field, string(sig), v.RunID, v.ContentHash, v.IndependenceKey, provenance}); e != nil {
					return e
				}
			}
		}
		c.Flush()
		return c.Error()
	default:
		return fmt.Errorf("format must be csv, json, or txt")
	}
}
