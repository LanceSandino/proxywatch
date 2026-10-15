#!/bin/bash
# Purpose: create private, git-ignored credential files for Docker Compose secrets.
# Usage: scripts/init-secrets.sh            (creates empty files; empty = not configured)
#        scripts/init-secrets.sh github_token   (prompts without echo and stores one value)
set -euo pipefail
cd "$(dirname "$0")/.."
umask 077
mkdir -p secrets
chmod 700 secrets
for name in github_token youtube_api_key search_api_key; do
  [ -f "secrets/$name" ] || : > "secrets/$name"
  chmod 600 "secrets/$name"
done
if [ "${1:-}" != "" ]; then
  case "$1" in github_token|youtube_api_key|search_api_key) ;; *) echo "unknown secret: $1" >&2; exit 2;; esac
  read -r -s -p "Paste value for $1 (input hidden): " value; echo
  printf '%s' "$value" > "secrets/$1"
  unset value
  echo "stored secrets/$1 ($(wc -c < "secrets/$1" | tr -d ' ') bytes)"
fi
if [ "$(uname)" = "Linux" ] && [ "$(id -u)" = "0" ]; then
  # The container runs as 10001; Compose bind-mounts these files as-is.
  chown -R 10001:10001 secrets
fi
git check-ignore -q secrets/github_token && echo "secrets/ is git-ignored"
