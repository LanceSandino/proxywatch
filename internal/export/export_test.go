package export

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"proxywatch/internal/model"
	"reflect"
	"strings"
	"testing"
)

func TestEvidenceExportRoundTrip(t *testing.T) {
	cs := []model.Candidate{{Host: "candidate.real-domain.net", IndependentSources: 2, Classification: "needs_review", ReviewStatus: "unreviewed", Evidence: []model.Evidence{{SourceURL: "https://news.ycombinator.com/item?id=123", Excerpt: "context, with \"quotes\"\nand a new line", RunID: "run1", ContentHash: "hash", Signals: []string{"unverified"}}, {SourceURL: "https://github.com/project/list", Excerpt: "independent", RunID: "run2", Synthetic: true}}}}
	var b bytes.Buffer
	if e := Write(&b, "json", cs); e != nil {
		t.Fatal(e)
	}
	var got []model.Candidate
	if e := json.Unmarshal(b.Bytes(), &got); e != nil {
		t.Fatal(e)
	}
	if !reflect.DeepEqual(cs, got) {
		t.Fatal("JSON evidence lost")
	}
	b.Reset()
	if e := Write(&b, "csv", cs); e != nil {
		t.Fatal(e)
	}
	rows, e := csv.NewReader(&b).ReadAll()
	if e != nil {
		t.Fatal(e)
	}
	if len(rows) != 3 {
		t.Fatal("CSV evidence row count wrong")
	}
	index := map[string]int{}
	for i, h := range rows[0] {
		index[h] = i
	}
	if rows[1][index["evidence_excerpt"]] != cs[0].Evidence[0].Excerpt || rows[1][index["source_url"]] != cs[0].Evidence[0].SourceURL || rows[2][index["provenance"]] != "SYNTHETIC" {
		t.Fatal("CSV evidence/provenance lost")
	}
	if e := Write(&b, "xml", cs); e == nil {
		t.Fatal("invalid format accepted")
	}
}
func TestEmptyJSONCatalog(t *testing.T) {
	var b bytes.Buffer
	if e := Write(&b, "json", []model.Candidate{}); e != nil {
		t.Fatal(e)
	}
	if strings.TrimSpace(b.String()) != "[]" {
		t.Fatal("empty catalog must be []")
	}
}
func TestTXTInventoryContainsOnlyHostnames(t *testing.T) {
	var b bytes.Buffer
	cs := []model.Candidate{{Host: "one.real-domain.net"}, {Host: "two.real-domain.net"}}
	if e := Write(&b, "txt", cs); e != nil {
		t.Fatal(e)
	}
	if b.String() != "one.real-domain.net\ntwo.real-domain.net\n" {
		t.Fatal("TXT included unsupported metadata or lost hosts")
	}
}
