// Package platform decides how safely a hostname can be blocked at the DNS layer.
// Inputs: normalized exact hostnames from the catalog or extractor.
// Outputs: a blocking scope; it never fetches, resolves, or visits hosts.
package platform

import (
	"regexp"
	"strings"
)

type Scope string

const (
	// Dedicated hosts can be blocked exactly at DNS with no known collateral damage.
	Dedicated Scope = "dedicated"
	// Tenant hosts are per-customer subdomains of a shared platform. Block the
	// exact host only; the parent platform domain must never be blocked.
	Tenant Scope = "tenant_subdomain"
	// SharedPath hosts serve many unrelated tenants under one hostname. A DNS
	// block breaks legitimate use, so enforcement needs a URL-path rule.
	SharedPath Scope = "shared_path"
	// Protected hosts are critical services that ProxyWatch never auto-blocks.
	Protected Scope = "protected"
)

// Path-style object storage and document hosts where the tenant is in the path.
var sharedPathHosts = map[string]bool{
	"sites.google.com": true, "docs.google.com": true, "drive.google.com": true,
	"script.google.com": true, "storage.googleapis.com": true,
	"firebasestorage.googleapis.com": true, "s3.amazonaws.com": true,
	"cdn.jsdelivr.net": true, "codepen.io": true, "replit.com": true,
	"glitch.com": true, "jsfiddle.net": true, "stackblitz.com": true,
	"codesandbox.io": true, "dropbox.com": true, "www.dropbox.com": true,
	"dl.dropboxusercontent.com": true, "onedrive.live.com": true,
	"archive.org": true, "web.archive.org": true, "scratch.mit.edu": true,
}

// Regional path-style S3 endpoints, e.g. s3.us-east-1.amazonaws.com,
// s3-us-west-2.amazonaws.com and s3.dualstack.us-east-1.amazonaws.com.
var s3PathStyle = regexp.MustCompile(`^s3(?:[.-][a-z0-9-]+)?(?:\.dualstack\.[a-z0-9-]+)?\.amazonaws\.com$|^s3\.dualstack\.[a-z0-9-]+\.amazonaws\.com$`)

// Whole registrable domains or suffixes that are never auto-blocked. Source-code
// hosts are protected because repository links are citations, not destinations.
var protectedSuffixes = []string{
	"google.com", "googleapis.com", "gstatic.com", "googleusercontent.com",
	"youtube.com", "youtu.be", "ytimg.com", "github.com", "githubusercontent.com",
	"gitlab.com", "microsoft.com", "live.com", "office.com", "microsoftonline.com",
	"apple.com", "icloud.com", "amazon.com", "amazonaws.com", "cloudflare.com",
	"wikipedia.org", "khanacademy.org", "instructure.com", "goguardian.com",
	"edu", "gov", "mil",
}

// Shared platforms whose customers receive their own subdomain.
var tenantSuffixes = []string{
	"github.io", "gitlab.io", "pages.dev", "workers.dev", "vercel.app", "netlify.app",
	"onrender.com", "cloudfront.net", "amazonaws.com", "web.app", "firebaseapp.com",
	"glitch.me", "repl.co", "replit.app", "replit.dev", "herokuapp.com", "blogspot.com",
	"fly.dev", "railway.app", "koyeb.app", "surge.sh", "neocities.org", "b-cdn.net",
	"azurewebsites.net", "web.core.windows.net", "blob.core.windows.net", "translate.goog",
	"wixsite.com", "weebly.com", "notion.site", "lovable.app", "amplifyapp.com", "ipv64.net", "deno.dev", "codehs.me", "github.dev",
	"ddns.net", "duckdns.org", "mooo.com", "chickenkiller.com", "jumpingcrab.com",
	"ignorelist.com", "ddns-ip.net", "us.to", "eu.org", "run.app", "appspot.com",
}

func suffix(host, parent string) bool {
	return host == parent || strings.HasSuffix(host, "."+parent)
}

// Classify returns the blocking scope for an exact normalized hostname.
// Order matters: shared-path hosts sit inside protected registrable domains.
func Classify(host string) Scope {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if sharedPathHosts[host] || s3PathStyle.MatchString(host) {
		return SharedPath
	}
	for _, t := range tenantSuffixes {
		if host == t {
			return Protected // the platform itself, never one customer
		}
		if suffix(host, t) {
			return Tenant
		}
	}
	for _, p := range protectedSuffixes {
		if suffix(host, p) {
			return Protected
		}
	}
	return Dedicated
}
