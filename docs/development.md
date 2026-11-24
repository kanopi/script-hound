# Development

Working on ScriptHound itself: setup, tests, adding rules, project layout and releases. For using it, see the [README](../README.md). `CLAUDE.md` holds the same conventions in more detail, plus the internal data model.

## Setup

```bash
make install     # npm ci + Playwright's Chromium (version pinned in package.json)
make             # list every make target
```

Requirements: Node.js 20+, and Docker for `make check`. The code is ESM only (`.mjs`), and has two runtime dependencies: `playwright` and `tldts`. Keep it that way unless there's a strong reason.

## Make targets

| Target | Does |
|---|---|
| `make install` | `npm ci` and Playwright's Chromium |
| `make scan URL=…` / `make crawl URL=…` / `make sitemap SITEMAP=…` / `make tree URL=…` | Shortcuts for `./scan` (extra flags via `ARGS="…"`) |
| `make rules` | List every rule and its effective setting |
| `make baseline` | Scan `sites.json` and overwrite `baseline.json` |
| `make test` | Run the test suite locally |
| `make docker-test` | Run the test suite inside the Playwright image (no local Chromium needed; installs `jq` so the jq recipes are tested too) |
| `make docker-build` / `make docker-scan URL=…` / `make docker-shell` | Build the image, scan with it, or open a shell in it |
| `make docker-smoke` | Check the built image runs and contains the vulnerability database, `jq` and the brand SVGs |
| `make docker-build PLATFORM=linux/amd64` | Build for x86 from an ARM Mac |
| `make docker-push` | Build amd64 + arm64 and push `kanopi/script-hound:<version>` and `:latest` to Docker Hub |
| `make check-versions` | Playwright pinned to the same version everywhere |
| `make validate-ci` | `circleci config validate` |
| `make check` | `check-versions`, `docker-test`, then `docker-smoke`. **Run before committing** |
| `make update-vulndb` | Refresh the vulnerable-library database from Retire.js |
| `make clean` | Remove generated reports |

## Tests

`make check` (or `make test` with a local Chromium) runs `test/run-test.mjs`, an end-to-end suite of nearly 200 checks:

- **Two local servers:** a first-party "shop" (`test/site/`) and a third-party "attacker".
- **The main flow:** scan the clean shop and write a baseline, rescan it (must be quiet despite a rotating nonce), then swap in an infected `app.js` and rescan. The skimmer, the injected script, the new domain and the changed file must all be found, with locations, trails and the tree view.
- **Feature checks:** every flag and output (discovery modes, interactions, the submission guard, logged-in scans, cookie jars, sessions, storage and CSS checks, the CSP suggestion, headers and HTML views, rule configuration, `--help` and argument errors, branding).
- **Rule fixtures (no browser):** every file in `test/rules/positive/` must trigger the rule named in its `// expect:` header, with a location. Nothing in `test/rules/negative/` may trigger anything above low.
- **Docs:** every recipe in `docs/jq-recipes.md` is run against a real report (when `jq` is available), and every CLI option must appear in `--help`.

The last run's reports are copied to `test/sample-report/` (gitignored), which is handy for checking HTML changes.

**Gotchas when writing tests:**
- The test servers run in the same Node process as the runner, so scans must be spawned asynchronously (`promisify(execFile)`). `execFileSync` blocks the event loop and every page load times out. The exit status is on `err.code`.
- Assert that a page actually loaded (`!page.error && page.scripts.length > 0`) before asserting "no findings". Otherwise a load failure passes the check without testing anything.
- The bare test server has no security headers, so posture rules fire everywhere. "Clean" checks filter to compromise findings (`real()` in the runner).
- Scans in tests point `SCAN_GLOBAL_CONFIG` at a missing file, so your own `config.json` can't affect them.

## Adding or changing a rule

Detection rules live in `lib/heuristics.mjs` (JavaScript), `lib/css.mjs` (CSS), `lib/evaluate.mjs` (page-level and baseline checks) and `lib/posture.mjs` (security posture).

1. **Write the rule.** Pattern rules are an entry in `RULES` (or `CSS_RULES`) with `id`, `severity`, `description` and `test(code)` returning `{ match, index }` or `null`. Keep regexes bounded (`[\s\S]{0,200}`, not `.*`): they run on multi-MB bundles.
2. **Look for ingredients that appear together, not just anywhere in the file.** Big SDKs (gtag.js, fbevents.js, Stripe.js) contain every suspicious ingredient somewhere. Follow `skimmerTest`'s `PROXIMITY` window, and make "near" false when an ingredient is absent.
3. **Register page-level ids** in `PAGE_RULES` (`lib/rules.mjs`), so config can reference them.
4. **Add samples:**
   - `test/rules/positive/` must fire. Start the file with `// expect: rule-id`.
   - `test/rules/negative/` holds legitimate look-alikes that must not fire.
   - Positive samples must be **inert** (`.example` hosts, fake keys) and based on published write-ups, with the source cited in a comment.
5. **Run the false-positive check** before shipping a rule or raising its severity:
   - Install popular packages with `npm install --ignore-scripts` into a scratch folder **outside** this repo: jQuery and jQuery UI, React, Vue, Bootstrap, GSAP, Swiper, Chart.js, Select2, jquery-validation, Three.js, Video.js, Lodash, Axios, Alpine, card-validator, payment, Cleave.js and IMask.
   - Add the look-alikes: ethers@5, web3, rrweb, posthog-js, @sentry/browser, mixpanel-browser, @amplitude/analytics-browser, socket.io-client, sockjs-client, localforage, store2, garlicjs, @adyen/adyen-web, braintree-web and @paypal/paypal-js.
   - Download vendor SDKs: gtag.js, gtm.js, fbevents.js, analytics.js, Stripe.js v3, PayPal, Braintree, Razorpay, LinkedIn Insight, Clarity, reCAPTCHA and Datadog.
   - Run `analyzeCode` (or `analyzeCss` over the `.css` files) on every `dist`/`.min.js` file. A **high** rule must have zero hits. The current baseline is about 3,200 files with 0 high, 0 medium and 29 low.
6. **Document it:** the rule tables in `docs/how-it-works.md` or `docs/security-checks.md`, and what it fires on.
7. **Try it on a few real sites** before calling it done. Several rules were tightened after real sites showed false positives that the test samples didn't.

Severity guidance: **high** only for patterns that are rarely legitimate; anything common libraries plausibly do is medium or low. `allowDomains` never lowers a high finding. Explicit config (`config.json`, suppressions) can, but it's always shown in the report.

## Project layout

| Path | What |
|---|---|
| `scan` | Shell wrapper (`./scan`, the `scripthound` npm bin): checks Node and dependencies, then runs `scan.mjs` |
| `scan.mjs` | CLI: options, config, discovery, the job queue, outputs, baseline, the `--fail-on` gate |
| `lib/page-scan.mjs` | One page visit: inventory, interaction phases, storage, cookies, headers, HTML capture |
| `lib/origin.mjs` | Where things came from (DevTools protocol): trails, `via`, runtime-code checks, GTM matching |
| `lib/heuristics.mjs`, `lib/css.mjs` | JavaScript and CSS pattern rules |
| `lib/evaluate.mjs` | Turns a page into findings; baseline diff |
| `lib/posture.mjs`, `lib/csp.mjs`, `lib/vulndb.mjs` | Security posture, the suggested CSP, vulnerable libraries |
| `lib/storage.mjs`, `lib/cookiejar.mjs` | Browser-storage inventory and honeytoken; curl-style cookie files |
| `lib/interactions.mjs`, `lib/discover.mjs`, `lib/gtm.mjs` | Custom steps and the submission guard; crawl and sitemap; GTM containers |
| `lib/rules.mjs` | Rule settings, custom rules, suppressions |
| `lib/report.mjs`, `lib/usage.mjs`, `lib/brand.mjs` | Reports and console, `--help`, brand assets |
| `data/` | Vendored Retire.js vulnerability database (see `data/README.md`) |
| `brand/` | Logo and brand files (don't edit; see `brand/README.md`) |
| `test/` | `run-test.mjs`, the fake shop in `test/site/`, rule samples in `test/rules/` |
| `docs/` | User documentation |

## Versions and dependencies

- **Playwright** is pinned in three places, which must match: `package.json`, the `FROM` line in `Dockerfile`, and the image in `.circleci/config.yml`. Bump all three together. `make check-versions` verifies it.
- **The vulnerability database** (`data/retire-jsrepository.json`, from Retire.js, Apache-2.0) is checked in so scans work offline. Refresh it with `make update-vulndb`, run `make check`, and commit `data/`.

## Docker images and releases

The image is published on Docker Hub as [`kanopi/script-hound`](https://hub.docker.com/r/kanopi/script-hound).

**Releasing a version:**

1. Bump `version` in `package.json` (semver: patch for fixes, minor for new checks or options, major for breaking changes to options or `report.json`).
2. `make check`. Everything must pass, including the image smoke test.
3. Commit and tag: `git tag v1.2.0 && git push --tags`.
4. `docker login`, then `make docker-push`. This builds amd64 and arm64 and pushes `kanopi/script-hound:1.2.0` and `:latest` as one multi-arch image, with the version in its OCI labels.
5. Check it with `docker run --rm kanopi/script-hound:1.2.0 --help` (the first line shows the version) and on Docker Hub.
6. If usage changed, update the Docker Hub overview: paste `docs/docker-hub.md` (below its header comment) into the repository's Overview. The short description is in the same comment.

**Notes:**

- **Architecture:** the base image is multi-arch. `make docker-build` builds for your machine only (arm64 on Apple Silicon), which is fine locally but fails on x86 servers. Only publish with `make docker-push`. See [Docker](docker.md).
- **Image contents:** the image holds `scan.mjs`, `lib/`, `data/`, the brand SVGs and `jq`. Tests, reports, configs, baselines, PNG exports and previews are excluded by `.dockerignore`.
- **Version number:** comes from `package.json`, and shows in `--help`, the console and reports.

## Documentation conventions

- **Keep the README about usage.** Details go in `docs/`.
- **Document new options in three places:** `USAGE` in `lib/usage.mjs` (a test enforces this), the table in `docs/configuration.md`, and the page for the feature.
- **New report fields:** keep `report.json` field names stable, and update the structure section in `docs/jq-recipes.md` when they change.
- **Severity language:** describe medium and low findings as "review", not "malware". ScriptHound covers compromise, weaknesses *and* change, so don't describe it as only a skimmer scanner.

## License

Apache-2.0 (`LICENSE`). Copyright and third-party attributions are in `NOTICE`, which must ship with every distribution: both files are copied into the Docker image, and `make docker-smoke` checks they're there.

- **Third-party additions:** if you vendor another dataset or file, check its license is compatible, and add its required notice to `NOTICE`.
- **Contributions:** they're accepted under Apache-2.0 (section 5).

## Brand

The name and logo are Kanopi Studios trademarks, not covered by the Apache license (see `brand/README.md`). The product name is **ScriptHound**: "Script" in navy (`#14213D`), "Hound" in amber (`#F77F00`). The tagline is "Sniffs out malicious front-end code". Use the simple marks at small sizes (favicon, report header) and the full logo in the README. `lib/brand.mjs` reads the SVGs at runtime and strips their C2PA metadata before inlining them. Don't put the brand name in the default user agent or anything else a scanned site sees, apart from the dummy form email.
