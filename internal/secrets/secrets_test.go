package secrets

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGetPrefersEnvironmentThenFile(t *testing.T) {
	t.Setenv("PW_TEST_KEY", "")
	t.Setenv("PW_TEST_KEY_FILE", "")
	if Get("PW_TEST_KEY") != "" {
		t.Fatal("unset secret not empty")
	}
	f := filepath.Join(t.TempDir(), "key.txt")
	if err := os.WriteFile(f, []byte("  from-file\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PW_TEST_KEY_FILE", f)
	if got := Get("PW_TEST_KEY"); got != "from-file" {
		t.Fatalf("file secret %q", got)
	}
	t.Setenv("PW_TEST_KEY", "from-env")
	if got := Get("PW_TEST_KEY"); got != "from-env" {
		t.Fatalf("env secret %q", got)
	}
}

func TestUnreadableFileIsAbsentNotFatal(t *testing.T) {
	t.Setenv("PW_TEST_KEY", "")
	t.Setenv("PW_TEST_KEY_FILE", filepath.Join(t.TempDir(), "missing"))
	if Get("PW_TEST_KEY") != "" {
		t.Fatal("missing file produced a secret")
	}
}

func TestValuesListsOnlyPresentSecrets(t *testing.T) {
	for _, n := range Names {
		t.Setenv(n, "")
		t.Setenv(n+"_FILE", "")
	}
	t.Setenv("GITHUB_TOKEN", "ghp_example")
	if v := Values(); len(v) != 1 || v[0] != "ghp_example" {
		t.Fatalf("values %v", v)
	}
}
