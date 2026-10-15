// Package sources provides bounded adapters for configured public discovery sources.
// Inputs: deterministic synthetic documents used only by offline validation.
// Outputs: explicitly synthetic source records that never count toward live gates.
package sources

import "proxywatch/internal/fetch"

// Fixtures are synthetic parser inputs, never evidence for the live gate.
func (c *collector) fixtures() {
	fixtures := []struct{ id, text, field string }{
		{"synthetic-description", "SYNTHETIC video description: Interstellar proxy links https://fixture-alpha.proxywatch-test.net/path and https://fixture-beta.proxywatch-test.net", "video description"},
		{"synthetic-readme", "SYNTHETIC README: School proxy list [mirror](https://fixture-alpha.proxywatch-test.net/other) and fixture-gamma.proxywatch-test.net", "README"},
		{"synthetic-html", `<p>SYNTHETIC public page: Rammerhead proxy <a href="https://fixture-delta.proxywatch-test.net">test mirror</a></p>`, "public page"},
	}
	for _, f := range fixtures {
		before := len(c.result.Documents)
		c.add("fixtures", f.id, "https://fixtures.proxywatch-test.net/"+f.id, "", f.text, f.field, "synthetic:"+f.id, fetch.Response{})
		if len(c.result.Documents) > before {
			c.result.Documents[len(c.result.Documents)-1].Synthetic = true
		}
	}
}
