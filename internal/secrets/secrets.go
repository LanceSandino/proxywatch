// Package secrets resolves optional API credentials without persisting them.
// Inputs: NAME environment variables or NAME_FILE paths (Docker/Compose secrets).
// Outputs: trimmed credential strings; callers must never log or store them.
package secrets

import (
	"os"
	"strings"
)

// Names lists every credential ProxyWatch understands.
var Names = []string{"GITHUB_TOKEN", "YOUTUBE_API_KEY", "SEARCH_API_KEY"}

// maxSecretBytes bounds what a misconfigured *_FILE path can load.
const maxSecretBytes = 4096

// Get returns NAME from the environment, else the contents of the file named
// by NAME_FILE. A missing or unreadable file means the credential is absent.
func Get(name string) string {
	if v := strings.TrimSpace(os.Getenv(name)); v != "" {
		return v
	}
	path := os.Getenv(name + "_FILE")
	if path == "" {
		return ""
	}
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	b := make([]byte, maxSecretBytes)
	n, _ := f.Read(b)
	return strings.TrimSpace(string(b[:n]))
}

// Values returns every configured credential, for redaction of error text.
func Values() []string {
	out := []string{}
	for _, n := range Names {
		if v := Get(n); v != "" {
			out = append(out, v)
		}
	}
	return out
}
