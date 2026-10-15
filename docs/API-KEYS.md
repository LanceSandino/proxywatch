# API keys: optional, least-privilege, never committed

Purpose: how to create and store the optional ProxyWatch credentials safely.

ProxyWatch runs without any keys. Sources that work keylessly are Scope/Flarum forums, Hacker News, Bluesky search via `api.bsky.app`, and the public GitHub REST API at 60 requests/hour. A key only raises limits or unlocks a source.

| Credential | Unlocks | Cost | Needed scope |
| --- | --- | --- | --- |
| `GITHUB_TOKEN` | GitHub limit rises from 60 to 5,000 requests/hour, plus issue/code search pacing headroom | Free | **No permissions.** Public repositories, read-only |
| `YOUTUBE_API_KEY` | YouTube search, video descriptions and public comments, where most fresh links are posted | Free, 10,000 quota units/day; one `search.list` costs 100 | API restriction: YouTube Data API v3 only |
| `SEARCH_API_KEY` | A Brave-compatible web search API | Usually paid now | Search API only |

## How keys are stored

- In Docker Compose, keys live in `secrets/<name>` files. These files are git-ignored and mode `600`. They are mounted at `/run/secrets/` and read through `*_FILE` variables, so they never appear in `docker inspect`, `.env` or process environments.
- When running the CLI on the host, export `GITHUB_TOKEN=...` in your shell, or point `GITHUB_TOKEN_FILE` at a private file.
- In code:
  - The YouTube key is sent in the `X-Goog-Api-Key` header, never in a URL.
  - Error messages replace any configured key value with `[REDACTED]`.
  - Cache keys keep only one-way hashes.
  - Raw API responses are never written to disk.
- Turn on the commit guard once per clone with `git config core.hooksPath .githooks`. It refuses any commit that stages token-shaped strings, `.env` or `secrets/`.

```bash
scripts/init-secrets.sh
```

That creates empty secret files; an empty file means the source is not configured. To store one value with hidden input:

```bash
scripts/init-secrets.sh github_token
```

## GitHub fine-grained token (5 minutes)

1. GitHub → **Settings → Developer settings → Personal access tokens → Fine-grained tokens → Generate new token**.
2. Name it `proxywatch-readonly` and set an expiration of 90 days or less.
3. Under **Repository access**, choose **Public repositories (read-only)**.
4. Leave **every permission at "No access"**. ProxyWatch only reads public data.
5. Generate the token, then run `scripts/init-secrets.sh github_token` and paste it at the prompt. Do not paste it into chat, issues or shell history.
6. Verify with `docker compose run --rm proxywatch doctor`. The output should include `"github_token_present": true`.

If the token leaks, revoke it on the same page. With no permissions it can only read public data, so the blast radius is limited to your rate limit.

## YouTube Data API v3 key (10 minutes)

1. Open <https://console.cloud.google.com/> and create a project named `proxywatch`. No billing account is needed for the free quota.
2. Go to **APIs & Services → Library → YouTube Data API v3 → Enable**.
3. Go to **APIs & Services → Credentials → Create credentials → API key**.
4. Click **Edit API key**:
   - Under **API restrictions**, choose **Restrict key** and select only **YouTube Data API v3**.
   - Under **Application restrictions**, choose **IP addresses** if your home IP is stable, and add the server's public IP. Otherwise leave it at None; the API restriction still applies.
5. Optionally, open **APIs & Services → YouTube Data API v3 → Quotas** to lower the daily cap below 10,000 units.
6. Run `scripts/init-secrets.sh youtube_api_key`, paste the key, and verify with `doctor`.

The default config stays within the free quota: `max_queries: 4` × 100 units for search, plus about 1 unit per video and comment page. Rotate the key in the Credentials page if it is ever exposed.
