# ProxyWatch

ProxyWatch finds school-proxy and "unblocked" websites that are being shared publicly, and turns them into blocklists a parent or IT team can review and load into a DNS filter.

New proxy mirrors (Interstellar, Ultraviolet, Rammerhead, Scramjet, Study Hub, "unblocked games" sites and many more) are published every week. They appear in YouTube descriptions and comments, GitHub link lists, forums and social posts, often well before commercial filters categorize them. ProxyWatch reads those public sources, records every hostname with its evidence, and writes:

- **Pi-hole / AdGuard Home lists.** Exact hostnames, split into a default *block* tier and optional *review* and *watch* tiers.
- **Path rules.** For proxies hosted on shared platforms (Google Sites, S3, Cloud Storage, jsDelivr…), where a DNS block would break legitimate use.
- **Parent-domain hints.** Domains that host many proxy subdomains, with a suggested wildcard rule for a human to approve.

## Why it exists

A parent noticed that a school-managed Chromebook could reach proxy sites over the family's home Wi-Fi, even though the device ran a school web filter. Filters and blocklists work from known lists, and the proxies rotate faster than those lists. ProxyWatch was built to watch the places where new links are announced, so a home network can block them early. It also keeps enough evidence that nobody has to trust a black box.

## Who it can help

- **Families** running Pi-hole, AdGuard Home or another DNS filter on their home network.
- **Schools and districts.** Feed the lists into a DNS or web filter as an early-warning source, and use the path rules for managed Chrome `URLBlocklist` policies.
- **Libraries, clubs, small offices and MSPs** that want a reviewable, evidence-backed list instead of an opaque category.
- **Researchers** studying how proxy and unblocker sites spread.

## How it works

```text
public sources ─▶ fetch (allow-listed hosts only) ─▶ extract hostnames ─▶ SQLite catalog ─▶ blocklist tiers
 GitHub, YouTube,   robots-aware, rate-limited,      normalize, redact,    evidence, runs,     block / review /
 Bluesky, Flarum,   size/time bounded, no            classify by context   history, reviews    watch, path rules,
 Hacker News        redirects followed                                                         parent hints
```

Safety rules built into the design:

- **Discovered sites are never visited or resolved.** Links are treated as untrusted text. Only approved source hosts are contacted.
- **Every hostname has evidence:** the source URL, a short redacted excerpt, timestamps and the run ID.
- **Appearing in a proxy search is not proof of harm.** Automatic labels are only `discovered`, `needs_review` or `likely_proxy`. Only a human review can set `confirmed_unsafe` or `confirmed_benign`.
- **Shared platforms are never DNS-blocked.** A proxy on `sites.google.com/view/x` becomes a path rule, not a block on Google Sites. Customer subdomains such as `x.onrender.com` are blocked exactly, never the parent platform. Major services (Google, YouTube, GitHub, Microsoft, Apple, `.edu`, `.gov`) are protected.
- **Each source fails independently.** A missing key or an outage lowers coverage, and the run reports it, but nothing breaks.

## Quick start (Docker)

You need Docker with Compose v2. The container uses about 15 MB of RAM and a fraction of one CPU; a run takes about a minute.

```bash
git clone https://github.com/LanceSandino/proxywatch.git
cd proxywatch
scripts/init-secrets.sh                 # empty key files: keyless sources still work
mkdir -p data output/blocklist
docker compose build
docker compose run --rm proxywatch doctor
docker compose run --rm proxywatch discover
docker compose run --rm proxywatch blocklist --out-dir /output/blocklist
```

On Linux, the container runs as UID 10001, so run `sudo chown -R 10001:10001 data output secrets` once first.

Each `discover` run rotates through the configured search terms. Run it daily, or a few times, to grow the catalog. `deploy/` has an optional systemd timer.

## The output

`output/blocklist/` contains:

| File | Use |
| --- | --- |
| `pihole-block.txt` | **Default list.** Hosts posted with explicit proxy-link context, or listed in a proxy-link compilation (a proxy-themed page with 10 or more distinct hosts), or reviewed as unsafe. |
| `pihole-review.txt` | Proxy-related or multi-use context. Look before enabling. |
| `pihole-watch.txt` | Seen in proxy sources without proxy context. Informational. |
| `path-rules.txt` / `.csv` | `host/path` rules for shared platforms. Use these in Chrome `URLBlocklist`, uBlock Origin (prefix `\|\|`) or a filtering proxy. |
| `parent-hints.csv` | Domains with 3 or more flagged subdomains, plus a suggested Pi-hole regex. Never applied automatically. |
| `blocklist.json` | Everything above, with reasons and source URLs. |

**Pi-hole v6:** In **Lists**, add `file:///path/to/output/blocklist/pihole-block.txt`, or serve the file over HTTP from your server. Then run `pihole -g`. **AdGuard Home:** In **Filters → DNS blocklists**, add the same file path or URL.

DNS sees hostnames, not URL paths. Path rules need endpoint control (a managed browser policy or an extension) or a TLS-inspecting proxy. They cannot be enforced on a device you don't manage.

Review a host and keep that decision across future runs:

```bash
docker compose run --rm proxywatch explain some.host.example
docker compose run --rm proxywatch review --status confirmed_benign --rationale "School's own site" some.host.example
```

Other commands: `candidates`, `export --format csv|json|txt`, `history`, `compare`, `runs`, `sources`, `vocabulary`, `backup`.

## API keys (all optional)

| Key | Free? | What it adds |
| --- | --- | --- |
| `GITHUB_TOKEN` (fine-grained, **no permissions**) | Yes | GitHub API limit rises from 60 to 5,000 requests/hour |
| `YOUTUBE_API_KEY` (restricted to YouTube Data API v3) | Yes, 10k units/day | YouTube search, descriptions and comments, the richest source of fresh links |
| `SEARCH_API_KEY` | Usually paid | A Brave-compatible web search API |

Keys are stored in git-ignored `secrets/` files and mounted as Docker secrets. They are never put in environment values, URLs, logs or the database. Setup steps: [docs/API-KEYS.md](docs/API-KEYS.md). Enable the commit guard with `git config core.hooksPath .githooks`.

## Configuration

`config.example.yaml` sets search terms, query sets, the allow-listed source hosts, GitHub repositories and YouTube videos to read, and every crawl limit (documents, results, bytes, timeouts, pacing). Fixtures for offline testing use a separate database:

```bash
docker compose run --rm proxywatch discover --source fixtures --offline --db /data/fixtures.db
```

## Limitations

- **Nothing is verified live.** A listed host may already be dead, or may be a compromised legitimate site. Review before blocking permanently, and use `confirmed_benign` to unblock.
- **Coverage depends on sources.** Without a YouTube key, the largest source of fresh links is missing. Reddit needs an approved OAuth app. Instagram and TikTok have no practical public API.
- **Proxies redeploy quickly.** A static list decays; run discovery regularly.
- **DNS filtering is easy to bypass.** A device using its own DNS, DoH or a VPN skips it. Pair it with blocking outbound DNS and known DoH endpoints at the router.
- **This is not a substitute for supervision**, or for a school's own device management.

## Roadmap

Still to do:

- [ ] **List-file adapters** for curated repositories, such as Markdown/JSON link lists beyond READMEs (e.g. ByePassHub `mainUnblockers.md`, Games-4.0 `Proxy-Links/*.json`).
- [ ] **Corroboration** against HaGeZi's DoH/VPN/Proxy-bypass list, used as a signal rather than a wholesale import.
- [ ] **Brand-prefix detection.** Proxy brands reuse subdomain prefixes (`stdyhb.`, `tungok.`…) across many unrelated domains.
- [ ] **Keyless YouTube coverage** through Invidious, plus urlscan.io, Common Crawl and Wayback lookups ([docs/keyless-sources.md](docs/keyless-sources.md)).
- [ ] **Statement coverage** raised to 85% or more (currently about 81%).
- [ ] **DNS log ingestion** from Pi-hole, to alert when a device on the network looks up a catalogued host.
- [ ] **Parent-reviewed, reversible block/unblock rules** pushed to Pi-hole, plus a small dashboard.

## Development

```bash
make test        # go test ./...
go test -race ./...
go vet ./...
make vulncheck   # govulncheck ./...
make fixture     # offline end-to-end run
```

CI runs formatting, vet, build, race tests, govulncheck and a container build on every push and pull request, and repeats them weekly.

Go 1.27, SQLite through `mattn/go-sqlite3` (CGO), and no other services. Layout: `cmd/proxywatch` (CLI), `internal/{config,sources,fetch,extract,engine,store,export,platform,blocklist,secrets}`. Architecture: [docs/architecture.md](docs/architecture.md). Settled design decisions: [DECISIONS.md](DECISIONS.md).

## Responsible use

ProxyWatch only reads public pages through official APIs and robots-permitted paths. It does not log in, bypass CAPTCHAs, scrape private content or visit the sites it lists. Evidence excerpts are redacted of emails, usernames and credentials. Please keep it that way in contributions. Report security issues privately ([SECURITY.md](SECURITY.md)).

## License

MIT. See [LICENSE](LICENSE). Contributions are welcome under the same license.
