# Configuration

Settings come from four places. A command-line flag beats its environment variable, which beats `sites.json`, which beats `config.json`.

| File | Holds |
|---|---|
| `config.json` (optional) | Global defaults for every site: `options`, `allowDomains`, `blockDomains`, `volatileScripts`, and rule settings (`rules`, `customRules`, `suppress`). Start from `config.example.json` |
| `sites.json` | The sites to scan and per-site settings. Its `options` override `config.json`'s, and the domain lists are combined. Start from `sites.example.json`. Optional when you pass `--urls` or `--sitemap` |

Rule settings are covered in [Rules](rules.md).

## sites.json

### Per site (`sites[]`)

| Key | Purpose |
|---|---|
| `name` | Label used in reports and by `--site` |
| `urls` | Pages to load (or the start pages for crawl and sitemap modes) |
| `firstParty` | Domains that count as "yours", including CDNs. Defaults to the URLs' root domains |
| `profiles` | Per-site override of `options.profiles` |
| `mode` | `url` (default: only the listed URLs), `crawl` or `sitemap`. See [Discovery modes](discovery.md) |
| `maxPages` / `depth` | Crawl and sitemap page cap (default 25, `0` = no cap) and crawl link depth (default 2) |
| `sitemap` | Sitemap URL or local file for sitemap mode (default: `robots.txt` `Sitemap:` lines, then `/sitemap.xml`) |
| `includeSubdomains` | Let crawl and sitemap modes visit other subdomains of the same domain (default `false`) |
| `exclude` | Regexes for URLs that crawl and sitemap modes should skip |
| `interactions` | Custom interaction steps or script hooks. See [Custom interactions](interactions.md) |
| `userAgent` | Browser user agent for this site (see `options.userAgent`) |
| `headers` / `cookies` / `storageState` | Logged-in scanning for this site. See [Logged-in scans](#logged-in-scans) |
| `session` | `"page"` (default, fresh cookies per page) or `"site"` (cookies carry from page to page). See [Sessions](#sessions-fresh-or-shared-cookies) |
| `domXssCanary` | `true` to run the [DOM-XSS canary](security-checks.md#dom-xss-canary-opt-in) on this site |
| `rules` / `customRules` / `suppress` | Rule settings for this site. See [Rules](rules.md) |

### Global (`options`)

| Key | Purpose |
|---|---|
| `profiles` | `["desktop"]`, `["mobile"]` or both. Some skimmers only target mobile |
| `waitMs` | Final wait after interaction, for delayed payloads (default 4000) |
| `idleBeforeInteractMs` | Quiet wait after load and before interacting, so timer-delayed scripts are labeled "idle wait" rather than blamed on scroll or typing (default 2000) |
| `timeoutMs` | Page load timeout (default 45000) |
| `concurrency` | Pages scanned in parallel (default 3) |
| `exerciseForms` | `false` to skip filling form fields (for example, on sites with autosave or abandoned-cart capture) |
| `traceOrigins` | `false` to turn off the *loaded by* trail (default on) |
| `userAgent` | Browser user agent: a string for all profiles, or `{ "desktop": "…", "mobile": "…" }`. Default: a current desktop Chrome UA, and Pixel 7 Chrome for mobile |
| `interactions` | Custom interactions for every site that doesn't define its own |
| `mode` / `maxPages` / `depth` | Defaults for every site's `mode`, `maxPages` and `depth` |

### Top level (either file)

| Key | Purpose |
|---|---|
| `allowDomains` | Trusted vendors. Medium and low hits on their scripts are downgraded to low; high hits are never downgraded |
| `blockDomains` | Known-bad domains. Any request to one is a high finding |
| `volatileScripts` | Scripts whose content legitimately changes all the time (GTM, reCAPTCHA, ad tags). Hash changes are ignored, but pattern rules still apply |
| `rules` / `customRules` / `suppress` | Rule settings for every site (in `config.json`). See [Rules](rules.md) |

## Command-line reference

Run the scanner as `./scan` (or `node scan.mjs`, or `scripthound` after `npm link`). `./scan --help` (or `-h`) prints a summary of these. A mistyped flag, a flag missing its value, or a stray argument stops with a one-line error, a "did you mean" suggestion where one fits, and exit code 2.

Most flags have an environment-variable equivalent, which is handy in CircleCI and Docker.

| Flag | Env var | Default | Purpose |
|---|---|---|---|
| `--config <file>` | | `sites.json` | Site list and options. Optional when you pass `--urls` or `--sitemap` |
| `--global-config <file>` | `SCAN_GLOBAL_CONFIG` | `config.json` | Global defaults and rule settings. Optional |
| `--disable-rule <id>` | `SCAN_DISABLE_RULES` (comma-separated) | | Turn a rule off for this run (repeatable). See [Rules](rules.md) |
| `--list-rules` | | | Print every rule with its effective setting and exit. Add `--site` for one site's view |
| `-h`, `--help` | | | Print usage and exit |
| `--baseline <file>` | | `baseline.json` | Baseline to compare against. A missing file means no change detection |
| `--out <dir>` | | `reports` | Where reports and `baseline.next.json` are written |
| `--urls <list>` | `SCAN_URLS` | | Comma- or space-separated URLs. Replaces the sites in `sites.json` |
| `--site <name>` | `SCAN_SITE` | | Scan only this named site from `sites.json` |
| `--mode <m>` | `SCAN_MODE` | `url` | `url`, `crawl` or `sitemap`. See [Discovery modes](discovery.md) |
| `--sitemap <url\|file>` | `SCAN_SITEMAP` | | Sitemap to read. Implies `--mode sitemap` |
| `--max-pages <n>` | `SCAN_MAX_PAGES` | `25` | Page cap per site for crawl and sitemap modes (`0` = no cap) |
| `--depth <n>` | `SCAN_DEPTH` | `2` | How many links deep crawl mode goes |
| `--include-subdomains` | `SCAN_INCLUDE_SUBDOMAINS=1` | off | Let crawl and sitemap modes visit other subdomains of the same domain |
| `--interactions <v>` | `SCAN_INTERACTIONS` | | Custom interactions for this run (repeatable): inline JSON, a `.json` file, a `.js`/`.mjs` hook, or inline JavaScript. Replaces any in `sites.json`. See [Custom interactions](interactions.md#from-the-command-line) |
| `--user-agent <ua>` | `SCAN_USER_AGENT` | built-in Chrome UA | Browser user agent for every site and profile |
| `--header "Name: value"` | `SCAN_HEADERS` (one per line) | | Extra request header for a logged-in scan, sent only to the site's own hosts (repeatable) |
| `--cookie "name=value"` | `SCAN_COOKIES` (`a=1; b=2`) | | Cookie set before loading pages (repeatable). A value without `=` is a cookie file, like `curl -b`. See [Cookie jars](#cookie-jars) |
| `--cookie-jar <file>` | `SCAN_COOKIE_JAR` | | After the scan, write all cookies to a curl-compatible jar file, like `curl -c`. See [Cookie jars](#cookie-jars) |
| `--storage-state <file>` | `SCAN_STORAGE_STATE` | | Playwright storage-state file (cookies + localStorage) from a recorded login |
| `--session <page\|site>` | `SCAN_SESSION` | `page` | Fresh cookies per page, or one shared session per site. See [Sessions](#sessions-fresh-or-shared-cookies) |
| `--dom-xss-canary` | `SCAN_DOM_XSS_CANARY=1` | off | Extra load per page to find DOM-XSS sinks. See [Security checks](security-checks.md#dom-xss-canary-opt-in) |
| `--show-cookies` | `SCAN_SHOW_COOKIES=1` | off | Add the cookie inventory to the console output. Turns on `console` output |
| `--show-headers` | `SCAN_SHOW_HEADERS=1` | off | Add the main document's response headers (security headers marked present/missing) and the request headers the browser sent to the console output. Cookie values are masked unless `--show-values`; headers and cookies you supplied are always masked. Turns on `console` output |
| `--show-html` | `SCAN_SHOW_HTML=1` | off | Save each page's HTML as sent by the server and the rendered DOM after scripts to `<out>/html/`, print the server HTML (first 200 lines) and a summary of what scripts added. Turns on `console` output. See [Reports](reports.md#html-as-sent-vs-rendered---show-html) |
| `--show-values` | `SCAN_SHOW_VALUES=1` | off | Add full cookie and storage values to the lists you asked for (both lists if neither) and to reports, which then get a warning banner. Values you supplied stay masked. See [Seeing the values](security-checks.md#seeing-the-values---show-values) |
| `--show-storage` | `SCAN_SHOW_STORAGE=1` | off | Add the browser-storage inventory (local/session storage, IndexedDB, caches, service workers) to the console output. Turns on `console` output. See [Browser storage](security-checks.md#browser-storage-inventory) |
| `--format <list>` | `SCAN_FORMAT` | `html,md` | Any of `html`, `md`, `console`, `json` (`report.json` is always written; build CSVs from it with [jq](jq-recipes.md)). The `--show-*` views go to every chosen output. See [Reports](reports.md#where-the-views-go) |
| `--show-scripts` | `SCAN_SHOW_SCRIPTS=1` | off | Add the third-party script loader tree to the console output. Turns on `console` output. See [Reports](reports.md#script-tree---show-scripts) |
| `--color <when>` | `NO_COLOR` / `FORCE_COLOR=1` | `auto` | Terminal colors: `auto` (on when output is a terminal), `always` or `never` |
| `--update-baseline` | | off | Overwrite the baseline file with this run's results |
| `--fail-on <level>` | `SCAN_FAIL_ON` | `none` | Exit 1 if any finding is at or above `high`, `medium` or `low` |
| | `SCAN_PROXY` | | Route the browser and sitemap fetches through a proxy (`http://host:port`) |
| | `SCAN_IGNORE_TLS=1` | off | Accept invalid TLS certificates. **Only for testing behind a TLS-intercepting proxy; never set it in CI** |

## Sessions: fresh or shared cookies

By default **every page is a first visit**: each URL gets a brand-new browser with no cookies or `localStorage`, and nothing carries over. `--session` (or `"session"` on a site or in `options`) changes that:

| Value | Behavior | Use it for |
|---|---|---|
| `page` (default) | Fresh cookies and storage for every page | Detection. Some skimmers fire only once per visitor and set a flag (a cookie or `localStorage` key) afterwards, so a carried-over flag could hide them on later pages |
| `site` | One visitor: cookies and `localStorage` carry from page to page, **in the order listed** (crawl mode: discovery order). That site's pages run one after another instead of in parallel, and each browser profile gets its own session | Journeys (home → cart → checkout), sites where consent or region is set on the first page, logged-in flows that pick up more cookies as you browse |

```bash
./scan --urls https://shop.example.com/,https://shop.example.com/cart,https://shop.example.com/checkout --session site
```

In the cookie inventory, cookies brought over from an earlier page are labeled **earlier page**. Shared-session pages get their own baseline entries (`…|site-session`), so switching modes doesn't produce false "new" findings. Login details ([below](#logged-in-scans)) apply on every page in either mode.

## Logged-in scans

Pages behind a login (account pages, saved-card checkouts, B2B portals) need the browser to be logged in. There are three ways to do that, and they can be combined:

| Option | Config key (site or `options`) | Use it for |
|---|---|---|
| `--storage-state auth.json` | `"storageState": "auth.json"` | A real login recorded once: `npx playwright codegen --save-storage=auth.json https://shop.example.com/account/login` (log in, then close the window). It holds cookies and `localStorage` |
| `--cookie "name=value"` | `"cookies": "a=1; b=2"` or `[{ "name": …, "value": …, "domain"?, "path"?, "httpOnly"?, "secure"?, "sameSite"? }]` | A session cookie you already have |
| `--header "Name: value"` | `"headers": { "Authorization": "Bearer …" }` | Header-based auth (APIs, staging basic auth, a WAF bypass header) |

```bash
./scan --urls https://shop.example.com/account --storage-state auth.json
./scan --urls https://staging.example.com/ --header "Authorization: Basic ${STAGING_AUTH}"
SCAN_COOKIES="session_id=$SESSION" ./scan --site "Example Client"
```

```json
"sites": [{
  "name": "Example Client",
  "urls": ["https://shop.example.com/account/orders"],
  "storageState": "auth/example-client.json",
  "headers": { "X-Scanner-Token": "${env:SCANNER_TOKEN}" },
  "cookies": "store_view=default"
}]
```

**Safety:**
- **Headers only go to the site's own hosts** (`firstParty`). Third-party scripts, trackers and ad servers on the page never receive them, so an `Authorization` header can't leak.
- **Cookies** default to the page's own host, path `/` and `Secure` on HTTPS. Set `domain` to cover subdomains.
- **Values never appear in reports.** Reports say "Logged-in scan: headers X-Scanner-Token; cookies store_view; storage state example-client.json", and the cookie inventory labels your cookies "you (auth)".
- **Keep secrets out of `sites.json`.** Use `${env:NAME}` in header and cookie values (the scan stops if the variable isn't set), and keep storage-state files out of git: they contain live session cookies. `.gitignore` already ignores `auth.json`, `auth/` and `*.auth.json`.
- **Logged-in pages get their own baseline entries** (`url|profile|auth`), separate from anonymous visits to the same URL.
- **Use a dedicated test account.** The submission guard still blocks form submissions, but logged-in pages may autosave or track activity through scripts. Session cookies also expire, so re-record `auth.json` when scans start showing the login page.

## Cookie jars

Cookie files work like curl's `-b` and `-c`:

| curl | Here | Does |
|---|---|---|
| `-b cookies.txt` | `--cookie cookies.txt` | Load cookies before scanning. Any `--cookie` value without `=` is read as a file: curl/Netscape jar format, or Playwright JSON (a storage state or a plain cookie array). Expired cookies are skipped |
| `-c cookies.txt` | `--cookie-jar cookies.txt` | After the scan, write every cookie from every page to the file in Netscape format, which curl and wget can read too |
| `-b jar -c jar` | `--cookie jar.txt --cookie-jar jar.txt` | Each run starts with the previous run's cookies, like a returning visitor |

```bash
./scan --urls https://shop.example.com/ --cookie-jar shop.cookies.txt                              # save
./scan --urls https://shop.example.com/checkout --cookie shop.cookies.txt                          # reuse
./scan --site "Example Client" --cookie shop.cookies.txt --cookie-jar shop.cookies.txt             # returning visitor
curl -b shop.cookies.txt https://shop.example.com/account                                         # works with curl too
```

In `sites.json`, `"cookies": "auth/shop.cookies.txt"` (a string without `=`) loads a jar too, relative to `sites.json`.

- **A jar holds cookie values,** since that's its purpose. It's written readable by you only (mode 600), and `.gitignore` ignores `*.cookies.txt`, `cookies.txt` and `*.jar`. Reports still never include values.
- **Merging:** with the default `--session page`, cookies from all pages are merged into one jar, and a later page wins when two pages set the same cookie.
- **In the inventory,** loaded cookies are labeled **cookie jar**. Like other cookies you supply, they're left out of the baseline, and those pages get the `|auth` baseline key, because a visit with preset cookies isn't a first visit.
- **Not to be confused with `--session site`,** which carries cookies between pages *within* a run. A jar carries them *between runs*, or to other tools.

## User agent

By default, desktop scans use a Chrome-on-Windows user agent and mobile scans use an Android Chrome one. Both carry the **real version of the bundled browser engine**, so the user agent, the browser's actual features and its client hints all agree. The `sec-ch-ua*` headers and `navigator.userAgentData` are set to match the user agent (Google Chrome brands, platform, mobile), including for a custom user agent. Without this, headless Chromium announces "HeadlessChrome" in its client hints, which bot-detection services and some skimmers check: one real store served the scanner a 3 KB stub page until this was fixed. To set your own, from most to least specific:

1. `--user-agent "…"` or `SCAN_USER_AGENT` (every site and profile)
2. `sites[].userAgent`
3. `options.userAgent`

In `sites.json` the value can be a string, or `{ "desktop": "…", "mobile": "…" }` so mobile scans don't send a desktop UA. A custom UA is also used for sitemap and `robots.txt` fetches.

A recognizable UA helps if a client's firewall needs to allowlist the scanner. Skimmers often go quiet for anything that looks like a bot, though, so keep the default for routine scans.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Finished, whether or not there were findings (unless `--fail-on` tripped) |
| `1` | The `--fail-on` threshold was hit, or an unexpected error occurred (for example an unreadable `sites.json`) |
| `2` | Bad arguments, or nothing to scan |
