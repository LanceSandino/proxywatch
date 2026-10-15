package main

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"proxywatch/internal/model"
	"strings"
	"testing"
)

func capture(t *testing.T, args ...string) (string, error) {
	t.Helper()
	old := os.Stdout
	r, w, e := os.Pipe()
	if e != nil {
		t.Fatal(e)
	}
	os.Stdout = w
	err := run(args)
	w.Close()
	os.Stdout = old
	b, e := io.ReadAll(r)
	r.Close()
	if e != nil {
		t.Fatal(e)
	}
	return string(b), err
}
func TestV1OfflineCLIWorkflow(t *testing.T) {
	dir := t.TempDir()
	cfg, _ := filepath.Abs("../../config.example.yaml")
	db := filepath.Join(dir, "fixture.db")
	common := []string{"--config", cfg, "--db", db}
	command := func(name string, extra ...string) string {
		t.Helper()
		args := append([]string{name}, common...)
		args = append(args, extra...)
		out, e := capture(t, args...)
		if e != nil {
			t.Fatalf("%s: %v", name, e)
		}
		return out
	}
	var doctor map[string]any
	if e := json.Unmarshal([]byte(command("doctor")), &doctor); e != nil || doctor["version"] != "1.0" {
		t.Fatalf("bad doctor: %v", doctor)
	}
	var first, second model.Run
	if e := json.Unmarshal([]byte(command("discover", "--source", "fixtures", "--offline")), &first); e != nil {
		t.Fatal(e)
	}
	if e := json.Unmarshal([]byte(command("discover", "--source", "fixtures", "--offline")), &second); e != nil {
		t.Fatal(e)
	}
	if !first.Synthetic || first.NewHosts != 4 || second.NewHosts != 0 {
		t.Fatal("fixture workflow not isolated/idempotent")
	}
	var comparison struct {
		New  []string `json:"new_in_comparison"`
		Both []string `json:"observed_in_both"`
	}
	if e := json.Unmarshal([]byte(command("compare", "--from", first.ID, "--to", second.ID)), &comparison); e != nil || len(comparison.New) != 0 || len(comparison.Both) != 4 {
		t.Fatal("compare lost run identities")
	}
	host := "fixture-alpha.proxywatch-test.net"
	command("review", "--status", "confirmed_benign", "--rationale", "synthetic test review", host)
	var history struct {
		Observations []any `json:"observations"`
		Reviews      []any `json:"reviews"`
	}
	if e := json.Unmarshal([]byte(command("history", host)), &history); e != nil || len(history.Observations) != 2 || len(history.Reviews) != 1 {
		t.Fatal("history lost observations/audit")
	}
	var explanation []model.Candidate
	if e := json.Unmarshal([]byte(command("explain", host)), &explanation); e != nil || len(explanation) != 1 || explanation[0].Classification != "confirmed_benign" {
		t.Fatal("review did not persist")
	}
	var bl map[string]any
	if e := json.Unmarshal([]byte(command("blocklist", "--out-dir", filepath.Join(dir, "bl"))), &bl); e != nil || bl["block"].(float64) != 0 || bl["excluded"].(float64) != 4 {
		t.Fatalf("fixture catalog must not produce block entries: %v %v", bl, e)
	}
	if b, e := os.ReadFile(filepath.Join(dir, "bl", "pihole-block.txt")); e != nil || !strings.Contains(string(b), "0 exact hostnames") {
		t.Fatalf("blocklist file missing: %v", e)
	}
	txt := filepath.Join(dir, "hosts.txt")
	command("export", "--format", "txt", "--output", txt)
	b, e := os.ReadFile(txt)
	if e != nil || len(strings.Fields(string(b))) != 4 {
		t.Fatal("TXT export wrong")
	}
	command("export", "--format", "csv", "--output", filepath.Join(dir, "hosts.csv"))
	command("export", "--format", "json", "--output", filepath.Join(dir, "hosts.json"))
	backup := filepath.Join(dir, "backup.sqlite")
	command("backup", "--output", backup)
	out, e := capture(t, "candidates", "--config", cfg, "--db", backup)
	if e != nil {
		t.Fatal(e)
	}
	var cs []model.Candidate
	if e = json.Unmarshal([]byte(out), &cs); e != nil || len(cs) != 4 {
		t.Fatal("backup catalog differs")
	}
	if strings.TrimSpace(command("candidates", "--stale")) != "[]" {
		t.Fatal("current fixture flagged stale")
	}
	if strings.TrimSpace(command("vocabulary")) != "[]" {
		t.Fatal("synthetic vocabulary learned")
	}
	command("sources")
	badArgs := append([]string{"compare"}, common...)
	badArgs = append(badArgs, "--from", "nonexistent", "--to", second.ID)
	if _, e = capture(t, badArgs...); e == nil {
		t.Fatal("unknown comparison run accepted")
	}
}
