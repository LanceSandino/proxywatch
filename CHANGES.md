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
id: CU-20261024-01
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
