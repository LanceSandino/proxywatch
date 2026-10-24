# Decisions

- D-001 (2026-10-14, active): Pi-hole lists contain exact hostnames only; parent/wildcard blocks are suggested in parent-hints.csv and never applied automatically.
- D-002 (2026-10-14, active): Shared-path hosts (Google Sites/Docs/Drive, path-style S3, storage.googleapis.com, jsDelivr, CodePen, Replit, Glitch) never enter a DNS list; their proxy tenants are recorded as path rules for later browser-policy or proxy enforcement.
- D-003 (2026-10-14, active): Protected services (Google, YouTube, GitHub, Microsoft, Apple, .edu/.gov) and bare tenant-platform suffixes are never auto-blocked.
- D-004 (2026-10-14, active): Being listed in a proxy-link compilation qualifies a host for the default block tier, but the catalog classification stays needs_review; only a human review sets confirmed_unsafe.
- D-005 (2026-10-14, active): Discovered destinations are never visited or resolved; synthetic fixture evidence is never a block input.
- D-006 (2026-10-14, active): Credentials are read from NAME or NAME_FILE only; Compose uses secret files, YouTube keys travel in headers, and no credential is persisted or logged.
- D-007 (2026-10-24, active): The go directive and the Dockerfile build and runtime images track the latest patched Go release on current Debian stable, pinned by digest, and CI runs govulncheck on every push, pull request and weekly, so a stale toolchain is reported rather than shipped.
