# CLAUDE.md

Guidance for Claude (and humans) working on ScriptHound.

## What this is

**ScriptHound** ("sniffs out malicious front-end code"; brand files in `brand/`, see `brand/README.md`; Docker Hub image `kanopi/script-hound`, overview text in `docs/docker-hub.md`; source `github.com/kanopi/script-hound`; release steps in `docs/development.md`) is a passive front-end security scanner: headless Chromium loads pages like a real visitor and reports three things. **Compromise** (malicious code of any kind: skimmers, injected/obfuscated scripts and loaders, miners, cloaked redirects, CSS keyloggers, payloads in storage). **Weaknesses** (OWASP Client-Side Top 10: DOM-XSS sinks, vulnerable libraries, CSP/headers/SRI with a suggested CSP, exposed secrets, cookie and storage issues). **Change and inventory** (every script, stylesheet, domain, cookie and storage key, where it came from, and what changed vs a baseline; PCI DSS 6.4.3/11.6.1). Card skimmers are one important case, not the whole scope; don't write docs or messages that imply otherwise. It never sends attack payloads (not a DAST tool). It runs locally, in Docker or in CircleCI. Its output is a report artifact. It is **report-only by default**: it exits 0 unless `--fail-on` is set.

User-facing docs: `README.md` (usage: install, task-by-task examples, reading results, limits) and `docs/` (details); contributor docs in `docs/development.md` (tests, adding rules, layout, releases). When you add or change a flag, env var, config key, report field or behavior, update the matching page in `docs/` (the CLI/env table lives in `docs/configuration.md`) and keep the README short. **New flags also go in `USAGE` in `lib/usage.mjs`**; a test fails if any option in `OPTIONS` (scan.mjs) is missing from `--help`.

## Commands

```bash
npm ci                                  # install (Playwright version pinned in package.json)
npm test                                # end-to-end test against a local fake shop: must pass before committing
./scan                                  # scan using sites.json + baseline.json → reports/ (wrapper for node scan.mjs)
./scan --urls https://a.com/            # ad-hoc scan
./scan --help                           # usage
npm run baseline                        # scan and overwrite baseline.json
```

`make` lists task shortcuts: `make check` (Playwright version check + tests in Docker; works without local Chromium), `make docker-test`, `make check-versions`, `make validate-ci`, `make scan URL=… ARGS="…"`.

Rule configuration: `config.json` (global, optional; `--global-config`) and per-site `rules` / `customRules` / `suppress` in `sites.json`; `--disable-rule <id>`; `--list-rules`. See `docs/rules.md`.

Logged-in scans: `--header`, `--cookie`, `--storage-state` (site keys `headers`/`cookies`/`storageState`, `${env:NAME}` expansion). Views: `--show-headers` (main-document response/request headers; secrets masked), `--show-html` (server HTML + rendered DOM saved to `<out>/html/`, excerpt kept out of report.json). Posture: `--dom-xss-canary`, `--show-cookies`, `--show-storage`, `--show-values` (adds values to the lists asked for; reports get a warning banner; supplied cookies stay masked); see `docs/security-checks.md`.

Flags: `--config`, `--baseline`, `--out`, `--urls`, `--site`, `--mode url|crawl|sitemap`, `--sitemap URL|file`, `--max-pages`, `--depth`, `--include-subdomains`, `--format html,md,console`, `--user-agent`, `--color auto|always|never`, `--show-scripts`, `--show-cookies`, `--session page|site`, `--dom-xss-canary`, `--header`, `--cookie` (name=value, or a cookie file), `--cookie-jar`, `--storage-state`, `--global-config`, `--disable-rule`, `--list-rules`, `--interactions` (repeatable: inline JSON, .json, .js/.mjs, or inline JS; parsed by `parseInteractionsArg`), `--update-baseline`, `--fail-on none|high|medium|low`.
Env equivalents: `SCAN_URLS`, `SCAN_SITE`, `SCAN_MODE`, `SCAN_SITEMAP`, `SCAN_MAX_PAGES`, `SCAN_DEPTH`, `SCAN_INCLUDE_SUBDOMAINS=1`, `SCAN_FORMAT`, `SCAN_USER_AGENT`, `SCAN_SHOW_SCRIPTS=1`, `SCAN_INTERACTIONS`, `SCAN_FAIL_ON`. Also `SCAN_PROXY` (route the browser through a proxy) and `SCAN_IGNORE_TLS=1` (testing behind a TLS-intercepting proxy only; never set it in CI).

## Layout

| File | Role |
|---|---|
| `scan` | Executable POSIX-sh wrapper: resolves its real path (symlinks), checks Node ≥ 20 and `node_modules`, then `exec node scan.mjs "$@"`. Also the `scripthound` npm bin |
| `scan.mjs` | CLI entry: loads config, runs pages with limited concurrency, evaluates them, writes reports and `baseline.next.json`, applies the `--fail-on` gate |
| `lib/page-scan.mjs` | One page load: captures script bodies via `response`, all request hosts, WebSockets, workers, inline scripts, iframes, forms, meta refresh, suspicious `on*` handlers; scrolls and exercises forms |
| `lib/origin.mjs` | Provenance over CDP: request initiators + `Debugger.scriptParsed` stacks → per-script/per-domain `origin { delivered, trail[], hint }`; `whereToLook()` |
| `lib/discover.mjs` | Crawl scope (`makeScope`), URL normalization, sitemap reading (indexes, .gz, robots.txt), `spreadPick` sampling |
| `lib/usage.mjs` | `--help` text (`USAGE`) and friendly parse errors with "did you mean" (`argError`) |
| `lib/rules.mjs` | Rule settings: `PAGE_RULES` (ids of page/baseline checks), `BUILTIN_RULES`, custom rule compiler, suppressions, `effectiveRules` (precedence), `applyRuleSettings` (run last in `evaluatePage`) |
| `config.example.json` | Template for the global `config.json` (options, domain lists, rule settings) |
| `lib/css.mjs` | CSS rules (`CSS_RULES`: keylogger, hidden whitespace payload, script URLs, legacy code) and `analyzeCss`. Stylesheets are captured in `page-scan` (external via `response`, inline `<style>` from the DOM) |
| `lib/storage.mjs` | Browser-storage inventory per frame origin (`collectStorage`: local/session storage, IndexedDB read-only, Cache Storage, service workers), `classify`/`preview` (masked), and the card honeytoken `findDummyCard` (raw/URL/hex/base64/double-base64 of `DUMMY_CARD`) |
| `lib/cookiejar.mjs` | curl-style cookie files: `parseCookieJar` (Netscape incl. `#HttpOnly_`, or Playwright JSON) and `writeCookieJar` (Netscape, mode 0600). Jars hold values on purpose; reports never do |
| `lib/brand.mjs` | Name, tagline, colors, version, and `brandSvg(name)`: reads `brand/*.svg` at runtime and strips the C2PA `<metadata>` before inlining. Used by the HTML report (header logo, favicon), Markdown title, console header and `--help` |
| `brand/` | Brand assets (do not edit; they carry C2PA content credentials). SVGs are copied into the Docker image; `brand/png` and `Claude outputs/` are not |
| `lib/csp.mjs` | `suggestCsp(pages)`: a Report-Only policy per site from each domain's per-type origins (`domains[].sources`), inline-script hashes or a nonce (rotating content), `'unsafe-eval'` only when page code really used eval (`page.evalCount`; the scanner's own evaluate calls are excluded in `startOriginTrace`) |
| `lib/posture.mjs` | Passive security checks: headers/CSP (`headerChecks`, `cspScriptWeaknesses`), SRI, mixed content, session cookies, storage tokens, DOM-XSS canary result |
| `lib/vulndb.mjs` | Vulnerable-library detection with the vendored Retire.js DB (`data/retire-jsrepository.json`, Apache-2.0; `make update-vulndb`) |
| `data/` | Vendored data files with their attribution (`data/README.md`; required notices in `NOTICE`) |
| `LICENSE`, `NOTICE` | Apache-2.0 text; copyright and third-party notices |
| `lib/gtm.mjs` | Parses a GTM container's `"tags"` array (`parseGtmTags`) and matches scripts to tag IDs (`matchGtmTags`). Tag names aren't in published containers |
| `lib/interactions.mjs` | Custom interaction steps/script hooks from `sites.json` (`runInteractions`, `validateInteractions`) and the submission guard (`startSubmissionGuard`) |
| `interactions/example.mjs` | Example script hook |
| `lib/heuristics.mjs` | `RULES` array of pattern checks run on every script body; `analyzeCode()` |
| `lib/evaluate.mjs` | Turns a page inventory into `issues[]` (heuristics, page-level checks, baseline diff); `baselineEntry()` and `pageId()` |
| `lib/report.mjs` | Renders `report.html` (self-contained, always every view), `report.md` and console (requested views, sharing the same line renderers via `viewSections`). No CSV: spreadsheets come from `report.json` via `docs/jq-recipes.md`, so keep `report.json` field names stable and update that doc's structure section when they change |
| `lib/util.mjs` | Hashing, host/root-domain helpers (`tldts`), inline-script normalization, `mapLimit`, `runQueue` (job queue that can grow, used by crawl) |
| `test/run-test.mjs` | Spins up two local HTTP servers (first-party shop and third-party "attacker"); runs clean baseline → clean rescan → infected rescan → gate |
| `test/rules/` | Rule regression samples: `positive/` must fire `skimmer-field-harvest`, `negative/` must not fire any high rule |
| `test/site/` | Fixtures: `index.html` (checkout), `miner.html`, `js/app.js.clean` / `js/app.js.infected`, `js/tag.js` (tag-manager stand-in with a `debugger;` trap), `about/deep/deeper.html` (crawl), `sitemap*.xml` (`BASE` placeholder) |
| `Makefile` | Task shortcuts (`make` lists them): install, scan/crawl/sitemap/tree/rules, docker-build (`PLATFORM=`)/push (multi-arch `kanopi/script-hound:<version>` + `:latest`, Docker Hub)/test/scan/smoke, check, update-vulndb. `docker-test` installs jq in the throwaway container so the jq-recipes test runs |
| `docs/` | User docs: `jq-recipes` (tested against a real report), `how-it-works`, `configuration` (all flags/env/keys), `discovery`, `interactions`, `reports`, `circleci`, `docker` |
| `sites.example.json` | Config template (`sites.json` is per-deployment and committed by the user) |
| `.circleci/config.yml` | Parameter-gated `scripthound` workflow (`run-fe-scan` (name kept for existing schedules), `scan-urls`, `scan-site`, `fail-on`…); artifacts under `scripthound/` |
| `Dockerfile` | Standalone image: entrypoint `node /app/scan.mjs`, working dir `/data` (mount the dir holding `sites.json`/`baseline.json`) |

## Data model

- **Page key** = `url|profile` (profile is `desktop` or `mobile`). The baseline is keyed by this.
- **Script key**: external scripts use `origin + pathname`, with the query string dropped to ignore cache-busters. Inline scripts use `inline#<16-char hash of normalized code>`. Normalization strips hex/long tokens, digits and whitespace so rotating nonces don't create noise.
- **Baseline entry** = `{ domains: [host…], scripts: { key: sha256 | "inline" } }`.
- **Issue** = `{ severity: high|medium|low|info, type, message, rule?, script?, match?, line?, column?, context?, htmlLine?, host?, preview?, origin?, phase? }`. Issues are sorted by severity. `line`/`column`/`context` locate a pattern-rule match in the script; `htmlLine` is the same spot in the page HTML for server-sent inline scripts.
- **Phase** (`script.phase`, `domain.phase`, `issue.phase`) = when it first appeared: `load` → `idle` → `mouse` → `scroll` → `form-input` → `after-interaction` (names in `PHASES`, `lib/util.mjs`). Inline scripts get theirs from `Debugger.scriptParsed` timing. Informational only; it doesn't change severity.
- **Cookie** (`page.cookies[]`) = `{ name, domain, path, thirdParty, httpOnly, secure, sameSite, session, expiresDays, setBy: server|javascript|"you (auth)"|"cookie jar"|"earlier page" }`, with no values.
- **Storage** (`page.storage[]`) = `{ origin, thirdParty, type: localStorage|sessionStorage, key, size, kind, preview, firstWritten: phase }`; also `page.indexedDB[]`, `page.cacheStorage[]`, `page.serviceWorkers[]`, `page.cardDataFound[]`. Write phases come from CDP `DOMStorage` events in `startOriginTrace`. Previews are ≤70 chars with JWTs masked; full values never leave `page-scan`.
- **Storage code checks**: every stored value (local/session storage, IndexedDB samples, Cache Storage bodies, service-worker code, OPFS text, `window.name`, `history.state`, cookies) goes through `analyzeCode` (and `analyzeCss` for cached CSS), also after base64-decoding, via `inspect()` in `page-scan`. Findings land in `page.storageFindings` and become `suspicious-code` / `code-in-storage` issues. Caches and service workers skip `code-in-storage` (code is expected there).
- **CSS rules** must pass the same FP corpus check (the library set's ~210 `.css` files): currently 0 hits.
- **Honeytoken**: the dummy card number typed by `exerciseForms` is `DUMMY_CARD` (lib/storage.mjs). Change it in one place only; `card-data-in-storage` depends on it.
- **Sessions**: default `page` = fresh browser context per page (better for detection: skimmers often fire once per visitor). `site` = per-site, per-profile chain (`site.chains`) that runs sequentially and passes `context.storageState()` to the next page (`opts.carriedState`). Page key gets `|site-session` (and `|auth` for logged-in scans). The baseline stores `domain|name` with ID-like parts collapsed.
- **Origin** = `{ delivered: html|injected|unknown, via: "how it got here, with a location" (e.g. "inserted by gtm.js?id=X:415:252"), parent: "html"|script URL|inline key|null (direct loader, used by the --show-scripts tree), trail: [label…] (nearest loader first, ending in "page HTML" when traced), hint, request? }`. Informational only. It must **not** change severities.

## Conventions and rules

- **Dynamic code** (eval/new Function/WebSocket payloads, self-removing inline scripts) is read from `Debugger.getScriptSource` in `applyOrigins` and added to `scripts[]` (`dynamic: true`) only when a rule fires. It's never baselined.
- **Origin tracing must not disturb the page.** No init scripts or prototype hooks (skimmers detect them). The CDP debugger runs with `setBreakpointsActive(false)` + `setSkipAllPauses` + auto-resume. Without that, a `debugger;` trap halts the script and hides the payload (covered by `test/site/js/tag.js`).
- **Discovery never leaves the site** and only reads `href`s. Keep the skip list (`SKIP_PATH` in `lib/discover.mjs`) for logout/admin/add-to-cart URLs.
- **The submission guard must stay on.** `startSubmissionGuard` answers non-GET Document requests with 204 (not `failRequest`: that loads `chrome-error://` and looks like an off-site redirect). It is what makes custom clicks on submit buttons safe.
- **Posture checks stay passive and low.** No attack payloads; the only probe is the opt-in DOM-XSS canary, which uses the URL fragment (never sent to the server). Keep posture severities at info/low/medium so they never drown out compromise findings.
- **Auth values never reach reports or third parties.** Extra headers are applied with `context.route` to first-party hosts only; reports carry names only (`sites[].auth`). Tests assert both.
- **License:** Apache-2.0 (`LICENSE`), copyright Kanopi Studios. `NOTICE` carries third-party notices (Retire.js) and must ship with every distribution (copied into the Docker image; `make docker-smoke` checks). Vendored files need a compatible license and their notice added to `NOTICE`. The name and logo are trademarks, not licensed.
- **Branding:** the product name is ScriptHound (Script in navy, Hound in amber). Use the simple marks for small sizes (favicon, report header) and the full logo in the README. Never put the brand name in the default user agent or anything a site sees, except the dummy email `scripthound@example.invalid` (so site owners can recognise test entries).
- **Look like a real browser, consistently.** The default UA is built from the real engine major (`browser.version()`), and `applyUaOverride` sets `Emulation.setUserAgentOverride` with matching `userAgentMetadata`, so `sec-ch-ua` never says "HeadlessChrome". A test asserts it. Any new page/context (like the canary probe) must call `applyUaOverride` too.
- **Never submit forms.** `exerciseForms` only fills fields, dispatches change/blur events and types key by key. Do not add clicks on submit buttons or `form.submit()`.
- **ESM only** (`.mjs`, `"type": "module"`). Node ≥ 20. Keep dependencies minimal: currently `playwright` and `tldts` only.
- **The Playwright version is pinned in three places:** `package.json`, the Docker image tag in `.circleci/config.yml` and the `FROM` line in `Dockerfile` (`mcr.microsoft.com/playwright:vX.Y.Z-noble`). Bump all three together.
- **Report-only default.** Don't change the default `fail-on` away from `none`. Users opt in.
- **Severity discipline:**
  - `high` is for patterns that are rarely legitimate: decoded eval, card-field exfiltration, miners, decoded redirects, off-site page redirect, blocklisted domain.
  - Anything that common libraries plausibly do belongs in `medium` or `low`.
  - `allowDomains` may downgrade medium/low hits to low but must **never** downgrade `high`.
  - Explicit rule settings (`config.json`/site `rules`, `suppress`, `--disable-rule`) *may* turn off or lower anything, because they're a deliberate choice. They must always be visible in the report (`sites[].rules`, "Rule changes in effect", `page.suppressed`, `originalSeverity`). Never apply them silently.
  - A new page-level or baseline check needs an entry in `PAGE_RULES` (`lib/rules.mjs`), or config can't reference its id.
- **Changed first-party scripts stay flagged** (medium). Skimmers are commonly appended to theme/plugin JS on disk, so don't exempt first-party files from change detection.
- `volatileScripts` suppresses only hash-change findings. Pattern rules still run on those scripts.
- The HTML report must stay self-contained (no external CSS/JS/fonts) because it's opened from CircleCI artifacts.
- Escape everything rendered into HTML with `escapeHtml`.

## Adding or changing a heuristic rule

1. Add an entry to `RULES` in `lib/heuristics.mjs` with an `id`, a `severity`, a `description` and a `test(code)` that returns `{ match, index }` (or `null`). `index` is the character offset of the hit; `analyzeCode` turns it into `line`/`column`/`context`. Keep regexes bounded (e.g. `[\s\S]{0,200}`, not `.*`) to avoid catastrophic backtracking on multi-MB bundles.
2. **Co-occurrence rules must use proximity**, not "anywhere in the file". Big SDKs (gtag.js, fbevents.js, Stripe.js) contain every ingredient somewhere. Follow `skimmerTest`: `PROXIMITY` window, whole-file only under `SMALL_FILE`.
3. Add samples to `test/rules/positive/` with a `// expect: rule-id[, rule-id]` first line (must fire, with a location) and to `test/rules/negative/` (legitimate look-alikes: must not fire anything above low). Positive samples must be **inert**: `.example` destinations, fake keys (`sk_test_EXAMPLE…`). Base them on published write-ups and cite the source in a comment.
4. **Run the false-positive check** before shipping or raising severity. Install popular packages with `--ignore-scripts` into a scratch dir *outside* this repo: jquery, jquery-ui, react, react-dom, vue, bootstrap, gsap, swiper, chart.js, select2, jquery-validation, three, video.js, lodash, axios, alpinejs, card-validator, payment, cleave.js, imask, plus the look-alikes ethers@5, web3, rrweb, posthog-js, @sentry/browser, mixpanel-browser, @amplitude/analytics-browser, socket.io-client, sockjs-client, localforage, store2, garlicjs, @adyen/adyen-web, braintree-web, @paypal/paypal-js. **Also download vendor SDKs** (gtag.js, gtm.js, fbevents.js, analytics.js, js.stripe.com/v3, PayPal SDK, Braintree client/hosted-fields, Razorpay checkout.js, LinkedIn insight, Clarity, reCAPTCHA, Datadog). Run `analyzeCode` over the `dist`/`.min.js` files plus the SDKs. Current result: ~3,200 files, **0 high, 0 medium, 29 low**. A `high` rule must produce zero hits. (History: the old "anywhere in the file" `skimmer-field-harvest` flagged gtag.js, fbevents.js, Stripe.js and Razorpay high, and was rewritten with proximity + an external destination requirement.)
   - Proximity helpers must return false when the ingredient is absent: `near = (list, i) => list.length > 0 && (whole || …)`. A version without the length check made every small file "near" everything.
5. `npm test` (or `make check`) must pass.

## Testing gotchas

- The test servers run in the same Node process as the test runner, so scans **must** be spawned asynchronously (`promisify(execFile)`). `execFileSync` blocks the event loop and every page load times out. With async exec, the exit status is on `err.code`, not `err.status`.
- Assert that pages actually loaded (`!page.error && scripts.length > 0`) before asserting "no findings". Otherwise a load failure passes the clean checks without testing anything.
- The test copies its last reports to `test/sample-report/` (gitignored).

## Known limits (don't over-promise in docs or reports)

- By default it sees anonymous, first-visit page loads. Logged-in scans (`--storage-state`/`--cookie`/`--header`), `--session site` and custom interactions narrow the gap, but payloads gated on geography, real cart contents or a completed checkout can still be missed.
- Posture checks are passive. It is not a DAST tool: no attack payloads (the DOM-XSS canary only uses the URL fragment).
- It sends no form submissions, but autosave or abandoned-cart features may record the dummy entry `scripthound@example.invalid`. Sites with those features can set `"exerciseForms": false`.
- The rules are heuristics. Reports and docs should frame medium/low as "review", not "malware".

## Likely next steps (not built yet)

Slack webhook and/or Teamwork task creation from `report.json`, a JUnit output for CircleCI's Tests tab, auto-PR of `baseline.next.json`, and GTM tag names via the GTM API (published containers only carry tag IDs).
