# Public source research — 2026-10-12

These are live HTTP research observations from this workspace, not acceptance-gate results. The collector must fetch its own documents; saved research copies must never be used to satisfy the live gate. No discovered proxy, game, or benchmark destination was visited. No exact benchmark hostname was used in any search query.

## Accessible independent community documents

Hacker News is a usable second source family alongside GitHub. Its official Firebase API exposes independent public comment documents. Public search through the Algolia HN API located these leads organically using the broad project vocabulary.

| Independently fetched document (HTTP 200) | Original public evidence URL | Link/context seen in the actual document |
| --- | --- | --- |
| `https://hacker-news.firebaseio.com/v0/item/46600074.json` | `https://news.ycombinator.com/item?id=46600074` | `https://neonarc.app/`; author describes “free unblocked games” and “school/work networks.” This is a game lead, not proof of a proxy or maliciousness. |
| `https://hacker-news.firebaseio.com/v0/item/35034522.json` | `https://news.ycombinator.com/item?id=35034522` | `https://eaglercraft.ru`; discussion says “playing it in school” and “unblocked games sites.” |
| `https://hacker-news.firebaseio.com/v0/item/12812512.json` | `https://news.ycombinator.com/item?id=12812512` | `http://unblockedallgames.com/unblocked-games/happy-wheels`; also an unrelated Wikipedia role-playing-game link. Preserve the distinction. |
| `https://hacker-news.firebaseio.com/v0/item/41575101.json` | `https://news.ycombinator.com/item?id=41575101` | `https://github.com/binary-person/rammerhead`; independent comment describes a “stateful HTTP proxy” syncing cookies/localStorage. |
| `https://hacker-news.firebaseio.com/v0/item/12123527.json` | `https://news.ycombinator.com/item?id=12123527` | `https://github.com/nfriedly/node-unblocker`; author describes a “web proxy for evading government/corporate/school/etc. filters.” Also includes `www.whatsmyua.com`, which is a user-agent utility, not a proxy claim. |

Research HTTP statuses, source URLs, fetch timestamps, SHA-256 hashes, and excerpts limited to 240 characters are in `docs/research-evidence/manifest.json`. Full responses and author identities are not retained. A separate live HTML fetch of `https://news.ycombinator.com/item?id=46600074` also returned HTTP 200, 4,287 bytes, containing `neonarc.app`.

Robots observations:

- `https://hacker-news.firebaseio.com/robots.txt` returned HTTP 200: `Allow: /*.json$`, `Allow: /*.json?*$`, `Disallow: /`. The item JSON paths above are permitted by the specific allow rules.
- `https://news.ycombinator.com/robots.txt` returned HTTP 200 and `Crawl-delay: 30`; `/item` is allowed. Respect the 30-second delay if fetching HN HTML pages.
- `https://hn.algolia.com/robots.txt` returned HTTP 404. Use its public API, with bounded queries/results rather than crawling its UI.

Recommended query parameters for the Algolia HN API:

```json
{
  "query": "\"unblocked games\"",
  "tags": "comment",
  "hitsPerPage": 20,
  "advancedSyntax": "true",
  "typoTolerance": "false",
  "removeWordsIfNoResults": "none"
}
```

Other organically used terms were `"school proxy"`, `"Rammerhead"`, `"GoGuardian" "proxy"`, and `"node-unblocker"`. The precise quoted GoGuardian/proxy query returned zero hits; this is a query outcome, not source unavailability. Default fuzzy matching for `Rammerhead` returned many unrelated “hammerhead” comments, so explicit exact phrase settings materially improve relevance. Extract only comment text and intended story content, not author avatar/profile metadata or search-engine-highlight boilerplate. Fetch each matched item separately through the official API to provide independent document hashes and reliable canonical source URLs. Do not log comment author identities in discovery exports.

Suggested bounded seeds for the configurable public-source adapter are the five JSON URLs above, with approved fetch host `hacker-news.firebaseio.com`. A dedicated HN adapter can perform quoted queries, validate numeric IDs, fetch item documents, and preserve `https://news.ycombinator.com/item?id=...` as evidence. The source family is `forum`, not `github`, even when a comment links to GitHub. Group repeated documents and syndicated text when calculating independence.

## Other source probes and exact limitations

| Source | Actual live observation | Why skipped / how to enable |
| --- | --- | --- |
| Scope/Flarum | Initial `https://scope.flarum.cloud/robots.txt` HTTP 403 twice; homepage HTTP 403. Later collector/research recheck: robots HTTP 404 and approved `/u/Arch-` HTTP 200. | Source availability changed during the session. Current HTML is a Flarum profile shell with embedded metadata, not a useful static discussion/link-list body. Public Flarum API parsing remains future adapter work; details below. No login or challenge bypass. |
| Reddit | `https://www.reddit.com/robots.txt` HTTP 200 explicitly `Disallow: /`; an initial public `https://www.reddit.com/r/Unblockers/.json?limit=5` probe returned HTTP 403. No further Reddit page/JSON crawling. | Public web crawling prohibited and access blocked. Approved Reddit Data API credentials/access are required; `REDDIT_CLIENT_ID` and `REDDIT_CLIENT_SECRET` absent. Use permitted OAuth API access, not old.reddit or another host to evade restrictions. |
| Bluesky | `https://public.api.bsky.app/robots.txt` HTTP 200 explicitly allows public APIs; `https://public.api.bsky.app/xrpc/app.bsky.feed.searchPosts?q=school%20proxy&limit=10` returned HTTP 403 twice. | Public API search inaccessible from this workspace; API-host/network restriction or service policy remains unverified. `BLUESKY_IDENTIFIER` and `BLUESKY_APP_PASSWORD` absent. Retry permitted public API on deployment; add authorized session support only if needed and available. |
| YouTube | `YOUTUBE_API_KEY` absent. No video description/comment result was invented. | Official YouTube Data API project/key needed; retain approved video seeds `rEgMbShYszQ`, `xanQQme-mvg`, `YHN3C5Ag4yk`, `4p4_gvuim4Y` from blueprint. A configured adapter should fetch metadata/descriptions and bounded comments/replies; disabled comments/private/deleted videos are per-document failures. |
| GitHub | Keyless `https://api.github.com/search/repositories?q=school+proxy+links&per_page=5` HTTP 200 returned actual public repositories. `GITHUB_TOKEN` absent. `https://raw.githubusercontent.com/titaniumnetwork-dev/Ultraviolet/main/README.md` HTTP 200, 3,196 characters with actual proxy-project and other URLs. | Repository search and public README discovery can run without credentials. Code search needs authorized access; never silently represent unavailable code search as successful. |
| npm registry | `https://registry.npmjs.org/@titaniumnetwork-dev/ultraviolet` HTTP 200 with package metadata/readme; `/robots.txt` HTTP 200 actually resolves an npm package named `robots.txt`, not a crawler policy. | Optional public metadata API, not needed for gate. Its syndicated GitHub README is not independent corroboration; do not count a second family solely for mirrored content. Parse documented metadata fields rather than arbitrary signatures/tarball URLs. |
| Titanium documentation | `https://docs.titaniumnetwork.org/robots.txt` and homepage HTTP 403. | Access unavailable; stop crawling and record. |
| DEV Community | `https://dev.to/api/articles?tag=unblocker&per_page=5` HTTP 403. | Public API unavailable from workspace; no bypass. |
| TikTok / Instagram / Facebook | No authorized credentials or approved public-comment API access supplied; no login automation or comment scraping attempted. | Implement only after official authorized metadata/comment access is practical. Record prerequisite, not fabricated “zero matches.” |
| Search engine fallback | DuckDuckGo HTML query returned HTTP 202 challenge-like HTML; Google search HTTP 200 returned generic search HTML, not used as evidence or collector input. The available web-search connector returned `isError=true` with empty content. | Use configured approved API provider for future search. These probes contribute no discovered candidates or gate documents. |

Two GitHub search-result repository guessed README paths returned HTTP 404 (`JavaScriptMika/Shadow-Links/master/README.md` and `awesomeguy27539/proxy/main/README.md`), while `Ljduley12/proxy-links-for-school/main/README.md` returned a 92-character “still looking for links” README with zero URLs. These are source failures/zero-content outcomes, not useful evidence. Obtain the actual default branch/file through repository APIs rather than guessing indefinitely.

### Later Scope and authoritative-control recheck

A normal request using `User-Agent: ProxyWatch/1.0 (+discovery research)` received HTTP 404 for Scope robots (no published policy), followed by HTTP 200 for the explicitly approved `https://scope.flarum.cloud/u/Arch-` seed, containing 28,196 characters and title **Archerist - Scope**. The HTML included a normal Flarum `Loading...` / JavaScript-enabled fallback and embedded forum metadata: “Community chat to escape school (ANTI-LIGHTSPEED). An evolution from SocialVoid,” `canViewForum: true`, and an API URL at `/api`. It referenced standard Flarum JavaScript assets. No CAPTCHA, suspension, archive, or unavailable notice was detected; the Cloudflare reference was an analytics beacon, not evidence of a challenge.

The current static-page adapter sees asset/canonical/FreeFlarum footer links, including `scope.flarum.cloud` and `freeflarum.com`. These do not establish proxy destinations or community discussion coverage. The profile shell requires parsing the public embedded resource JSON and/or using permitted public Flarum discussion/post APIs for useful comment evidence. No additional API requests or JavaScript execution were performed during this initial recheck; bounded subsequent API research is documented below. Initial HTTP 403 observations remain recorded honestly and are not treated as the final availability state.

After discovery, a single authoritative-control check of `https://wiki.math.uzh.ch/public/books/public-wiki/page/jitsi` returned HTTP 503. No exact-host search or destination visit was performed. The legitimate Jitsi classification comes from the user and blueprint; its official wiki could not be independently validated live in this workspace. Record that distinction in benchmark outcomes rather than implying successful authoritative retrieval.

### Bounded anonymous Flarum API research

After robots became HTTP 404 and the approved source became accessible, six anonymous public API requests were made, paced one second apart, without login, JavaScript execution, or destination fetches. These are research, not collector gate documents.

| API parameters on `https://scope.flarum.cloud/api/discussions` | HTTP result | Practical finding |
| --- | --- | --- |
| `filter[q]=proxy`, `page[limit]=5`, `include=posts` | 400 | This requested include is not usable on this list endpoint. |
| `filter[q]=StudyHub`, `page[limit]=5`, `include=posts` | 400 | Same failure; not interpreted as zero matches. |
| `filter[q]=Interstellar`, `page[limit]=5`, `include=posts` | 400 | Same failure. |
| `filter[q]=proxy`, `page[limit]=5`, no include | 200; 19,705 bytes | Five matching discussions; next-page link present. Default includes posts **and users/badges/tags**, so use explicit minimal includes. |
| `filter[q]=StudyHub`, `page[limit]=5`, `include=firstPost` | 200; 52,424 bytes | Five discussions; next-page link present. Included resource type is **posts only**, with actual `contentHtml` link lists. |
| `filter[q]=Interstellar`, `page[limit]=5`, `include=firstPost` | 200; 55,990 bytes | Five discussions; no next-page link. Included resource type is **posts only**, with actual proxy-list first posts. |

Examples of actual public source evidence:

- `https://scope.flarum.cloud/d/903`, title “PROXYS (MASSIVE DROP!)”, first post ID `16128`: starts with `https://safe.cafebarocco.cl`, `https://meri.cafemeridiano.com.br`, `https://rent.cheap-car-rental.com`, and additional listed domains.
- `https://scope.flarum.cloud/d/772`, title “Proxys”, first post ID `15132`: includes `https://auroraok.schovat.net`, `https://auroraok.schneiderhome.us`, and other mirrors.
- `https://scope.flarum.cloud/d/823`, first post ID `15568`: includes Amazon S3 paths/virtual-host URLs. Deduplicate **exact hostnames**, while recognizing a shared hosting hostname alone does not identify a single hosted proxy application.
- `https://scope.flarum.cloud/d/151`, title “Proxys To Bring This Dead Server To Life”, first post ID `2317`: section “Ghost:” lists `https://d3i98h3wj731z8.cloudfront.net/` and other CloudFront hostnames.
- `https://scope.flarum.cloud/d/202`, title “Proxies, Games, and More. Everything on here. Check it out!”, first post ID `3326`: includes `https://socialstudies.imagenesmagenta.com/` with “Reds Exploit Center” context and other labeled links.

Recommended adapter: allowlisted origin, explicit `include=firstPost`, `page[limit]=5`, bounded query set and pagination, parse only discussion `id`/`title` and included post `id`/`number`/`contentHtml`, with evidence URL `https://scope.flarum.cloud/d/<discussion-id>/<post-number>`. Resolve `relationships.firstPost.data.id` rather than assuming response order. A selected additional post fetch should use numeric IDs from the permitted response. Default full includes should be avoided; no author records or full response snapshots were retained by this research. A search match can come from a later post rather than the first post, so first-post coverage alone is incomplete and must be stated honestly.

The successful exact executable URL shape is generated by Python `urllib.parse.urlencode({'filter[q]':'StudyHub','page[limit]':5,'include':'firstPost'})`, yielding `https://scope.flarum.cloud/api/discussions?filter%5Bq%5D=StudyHub&page%5Blimit%5D=5&include=firstPost`. All network requests used standard `urllib.request` with `Accept: application/vnd.api+json`; no access-restriction workaround was needed.

## Official quota documentation checked live

All three official documentation requests returned HTTP 200 on 2026-10-12:

- `https://developers.google.com/youtube/v3/determine_quota_cost`: current documentation says default **100 `search.list` calls/day**, **100 `videos.insert` calls/day**, and **10,000 units/day combined for all other endpoints**. Search and insert have separate buckets; **each search call costs 1**, including pagination. Daily quotas reset at midnight Pacific. Confirm actual assigned quotas in Google Cloud Console; do not implement the obsolete “each search costs 100 units against one 10,000-unit pool” assumption.
- `https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api`: anonymous core REST limit **60 requests/hour**, associated with originating IP; authenticated user limit generally **5,000/hour**. Shared egress can exhaust the anonymous budget.
- `https://docs.github.com/en/rest/search/search`: anonymous search limit **10 requests/minute**, authenticated search **30/minute** except code search **10/minute**; code search requires authentication. Honor actual rate headers and secondary limits in addition to configured pacing.

## Commands actually executed

Probes used Python standard-library `urllib.request.urlopen(url, timeout=20)` and reported actual status or `HTTPError`, with `json.load` for API responses. Independent initial probes were batched with `concurrent.futures.ThreadPoolExecutor`; follow-up decisions were sequential. No API credentials were printed. The following are representative exact executable research commands; URL tables above record the complete meaningful probe outcomes.

```bash
python3 - <<'PY'
import urllib.request, json, urllib.parse
for term in ['"school proxy"', '"unblocked games"', '"Rammerhead"', '"GoGuardian" "proxy"', '"node-unblocker"']:
    u='https://hn.algolia.com/api/v1/search?'+urllib.parse.urlencode({
        'query':term, 'tags':'comment', 'hitsPerPage':20,
        'advancedSyntax':'true', 'typoTolerance':'false', 'removeWordsIfNoResults':'none'})
    r=urllib.request.urlopen(u,timeout=20)
    d=json.load(r)
    print(term,r.status,d['nbHits'])
PY
```

```bash
python3 - <<'PY'
import urllib.request, json
for item in ['46600074','35034522','12812512','41575101','12123527']:
    u='https://hacker-news.firebaseio.com/v0/item/'+item+'.json'
    r=urllib.request.urlopen(u,timeout=20)
    d=json.load(r)
    print(u,r.status,d.get('text',''))
PY
```

The research command additionally used UTC `datetime.now` and `hashlib.sha256` for `docs/research-evidence/manifest.json`. Temporary raw responses were deleted after extracting short excerpts; no author fields are retained. This folder is explicitly research-only. Its contents are not injected into the collector.
