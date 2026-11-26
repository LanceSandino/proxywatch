# Change log

```yaml
id: CU-PUBLIC-001
type: release
title: "Initial public release"
description: "Discovery CLI (GitHub, YouTube, Bluesky, Scope/Flarum, Hacker News adapters), SQLite evidence catalog with run history and human review, CSV/JSON/TXT exports, tiered Pi-hole blocklists with shared-platform path rules and parent hints, secret-file credentials, hardened Docker Compose deployment and optional systemd timer."
impact: high
affected_modules: ["cmd/proxywatch", "internal", "compose.yaml", "Dockerfile", "deploy"]
related_tests: ["go test -race ./..."]
author: "ProxyWatch maintainers"
timestamp: "2026-10-14T23:30:00Z"
```

```yaml
id: CU-PUBLIC-002
type: fix
version: "1.0.1"
title: "Security release 1.0.1: Go 1.27.3, Debian trixie and dependency updates"
description: "Builds with Go 1.27.3 (go directive 1.27.3; Dockerfile golang:1.27.3-trixie and debian:trixie-slim runtime, both pinned by digest, replacing Go 1.25.1 and bookworm). Go 1.25 is out of support. Fixes GO-2026-6809 (CVE-2026-111943, crypto/x509) and GO-2026-5970 (CVE-2026-56852, golang.org/x/text infinite loop, x/text 0.37.0 -> 0.43.0), both reported reachable by govulncheck. Updates go-sqlite3 to 1.14.52 and x/net to 0.61.0. Adds a CI workflow (gofmt, vet, build, race tests, govulncheck, container build and doctor) on push, pull request and weekly, a make vulncheck target, and Dependabot for Go modules, Docker images and GitHub Actions."
impact: medium
affected_modules: ["go.mod", "go.sum", "Dockerfile", "Makefile", ".github/workflows/ci.yml", ".github/dependabot.yml", "README.md"]
related_tests: ["go test -race ./...", "make vulncheck", "TestV1OfflineCLIWorkflow", "TestMigrationPersistenceAndFutureSchemaRejection", ".github/workflows/ci.yml"]
author: "ProxyWatch maintainers"
timestamp: "2026-10-24T12:45:00Z"
```

```yaml
id: CU-PUBLIC-003
type: fix
title: "Go 1.27.4 and golang.org/x/net 0.62.0"
description: "Builds with Go 1.27.4 (go directive 1.27.4; Dockerfile golang:1.27.4-trixie pinned by digest, replacing 1.27.3). Fixes GO-2026-6859 (net/http, fixed in go1.27.4) and GO-2026-6860 (golang.org/x/net/html, reached through extract.go html.Parse; x/net 0.61.0 -> 0.62.0), both reported reachable by the weekly govulncheck run on main and failing CI there and on the open Dependabot pull requests."
impact: medium
affected_modules: ["go.mod", "go.sum", "Dockerfile"]
related_tests: ["make vulncheck", "go test -race ./...", ".github/workflows/ci.yml"]
author: "ProxyWatch maintainers"
timestamp: "2026-11-25T23:35:00Z"
```

```yaml
id: CU-PUBLIC-004
type: fix
version: "1.0.2"
title: "Security release 1.0.2: Go 1.27.4, x/net 0.63.0, go-sqlite3 1.14.53 and Debian 13.8 runtime"
description: "Releases CU-PUBLIC-003 and the follow-up dependency updates. Builds with Go 1.27.4 (GO-2026-6859, net/http) and golang.org/x/net 0.63.0 (GO-2026-6860, fixed in 0.62.0; reachable through extract.go html.Parse), both reported reachable by govulncheck on 1.0.1. Updates go-sqlite3 to 1.14.53 and the indirect golang.org/x/text to 0.44.0, and refreshes the debian:trixie-slim runtime image pinned by digest from Debian 13.7 to 13.8."
impact: medium
affected_modules: ["go.mod", "go.sum", "Dockerfile"]
related_tests: ["go test -race ./...", "make vulncheck", ".github/workflows/ci.yml"]
author: "ProxyWatch maintainers"
timestamp: "2026-11-26T00:15:00Z"
```
