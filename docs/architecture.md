# Implemented discovery architecture

`cmd/proxywatch` parses commands → `config` validates bounded YAML → `sources` retrieves approved public documents through `fetch` → `extract` normalizes/redacts exact hostname sightings → `engine` persists runs → `store` maintains SQLite WAL history → `export` produces evidence-bearing CSV/JSON/TXT → `blocklist` writes tiered DNS lists and path rules.

One process, one local SQLite catalog. No network listener or infrastructure service is needed. Adapters fail independently; configured caps bound queries, result counts, response bytes, timeouts and accepted documents. GitHub API issue arrays can contain several logical documents per HTTP response. The live acceptance report separately counts individually retrieved README and Firebase documents so bundled issue results do not inflate the minimum independently fetched-document gate.

Source contents are untrusted data. No downloaded instructions or scripts run, and extraction has no network code. API/search result URLs cannot authorize new hosts. Public HTML needs permitted robots paths; unavailable robots are an error. Exact allowlisting, public-IP checks, direct DNS address pinning, redirect rejection, bounded bodies and request timeouts constrain source fetches. A managed forward proxy is a trusted network boundary because it resolves upstream destinations.

SQLite migrations, transactions, uniqueness constraints and provenance triggers preserve evidence and separate offline/live databases. Source failures cannot delete candidates or confirm safe/unsafe status. Independent-source counts group shared video comments, repo documents and the entire HN forum conservatively; they are not a statistically calibrated accuracy measure.

V1 added Flarum first posts, validator-only SQLite caching, per-host pacing, bounded retries and quota cooldowns, refresh checkpoints, bounded learned vocabulary with query cursors, exact-content mirror grouping, human review audit, comparison/history/search and snapshot backups. Adapter namespaces stop one HTTP URL from mixing evidence across source families.

`platform` assigns each host a blocking scope (dedicated, tenant, shared-path or protected), and `blocklist` turns the catalog into tiered exact-host lists, path rules and parent hints. `secrets` resolves optional credentials from environment variables or secret files. Nothing in this repository changes DNS or any network device. Pi-hole integration, DNS log analysis and a dashboard are future work.
