package platform

import "testing"

func TestClassify(t *testing.T) {
	cases := map[string]Scope{
		// Shared hosts: a DNS block would break unrelated tenants.
		"sites.google.com":                     SharedPath,
		"storage.googleapis.com":               SharedPath,
		"s3.amazonaws.com":                     SharedPath,
		"s3.us-east-1.amazonaws.com":           SharedPath,
		"s3-us-west-2.amazonaws.com":           SharedPath,
		"s3.dualstack.us-east-1.amazonaws.com": SharedPath,
		"cdn.jsdelivr.net":                     SharedPath,
		"SITES.GOOGLE.COM.":                    SharedPath,
		// Tenant subdomains: exact-host blocking is safe, the parent is not.
		"ow9bpeb.s3.amazonaws.com":                     Tenant,
		"ow9bpeb.s3.dualstack.us-east-1.amazonaws.com": Tenant,
		"d3i98h3wj731z8.cloudfront.net":                Tenant,
		"0800webdev.github.io":                         Tenant,
		"newinterstellar.onrender.com":                 Tenant,
		"sktechlink.jumpingcrab.com":                   Tenant,
		"canvas-math-tools-1.us-central1.run.app":      Tenant,
		// Parents of tenant platforms are never blockable themselves.
		"github.io":      Protected,
		"amazonaws.com":  Protected,
		"cloudfront.net": Protected,
		// Protected critical services and their subdomains.
		"github.com":        Protected,
		"mail.google.com":   Protected,
		"www.youtube.com":   Protected,
		"canvas.school.edu": Protected,
		// Ordinary dedicated hosts, including the held-out benchmarks.
		"stdyhb.jurematoz.com": Dedicated,
		"jitsi.math.uzh.ch":    Dedicated,
		"vaporized.help":       Dedicated,
	}
	for host, want := range cases {
		if got := Classify(host); got != want {
			t.Errorf("Classify(%q) = %q, want %q", host, got, want)
		}
	}
}

func TestBareTenantSuffixIsNotTenant(t *testing.T) {
	// A bare platform suffix is not a customer's host and must never be
	// treated as exact-host blockable tenant content.
	for _, host := range []string{"pages.dev", "vercel.app", "onrender.com", "mooo.com"} {
		if Classify(host) != Protected {
			t.Errorf("%s = %q, want protected", host, Classify(host))
		}
	}
}
