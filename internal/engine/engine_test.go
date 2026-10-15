package engine

import (
	"context"
	"path/filepath"
	"proxywatch/internal/config"
	"proxywatch/internal/store"
	"testing"
)

func TestOfflineEndToEndIdempotency(t *testing.T) {
	s, e := store.Open(filepath.Join(t.TempDir(), "fixture.db"))
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	cfg := config.Config{MaxDocs: 10, MaxResults: 5, MaxQueries: 1, StaleDays: 30}
	a, e := Discover(context.Background(), cfg, s, []string{"fixtures"}, true)
	if e != nil {
		t.Fatal(e)
	}
	b, e := Discover(context.Background(), cfg, s, []string{"fixtures"}, true)
	if e != nil {
		t.Fatal(e)
	}
	if !a.Synthetic || a.UniqueHosts != 4 || a.NewHosts != 4 || b.NewHosts != 0 || b.UniqueHosts != 4 {
		t.Fatalf("bad fixture metrics: %+v %+v", a, b)
	}
	cs, e := s.Candidates(b.ID, "", 0)
	if e != nil {
		t.Fatal(e)
	}
	if len(cs) != 4 {
		t.Fatalf("identities duplicated: %d", len(cs))
	}
	for _, c := range cs {
		if c.IndependentSources != 0 {
			t.Fatal("synthetic evidence counted as independent live source")
		}
		for _, ev := range c.Evidence {
			if !ev.Synthetic || ev.Excerpt == "" || ev.SourceURL == "" || ev.RunID == "" {
				t.Fatal("missing synthetic evidence provenance")
			}
		}
	}
	var count int
	s.DB.QueryRow("SELECT COUNT(*) FROM sightings").Scan(&count)
	if count != 5 {
		t.Fatalf("repeat run duplicated evidence: %d", count)
	}
}
func TestOfflineDoesNotPermitLiveSources(t *testing.T) {
	for _, x := range []struct {
		names   []string
		offline bool
	}{{[]string{"fixtures", "github"}, true}, {[]string{"github"}, true}, {[]string{"fixtures"}, false}, {[]string{"Fixtures"}, false}, {[]string{" FIXTURES "}, false}} {
		if _, e := Discover(context.Background(), config.Config{}, nil, x.names, x.offline); e == nil {
			t.Fatal("mixed/offline source validation failed")
		}
	}
}
