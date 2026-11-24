# jq recipes

`report.json` holds everything the scanner found, and is always written. Build spreadsheets, summaries and checks from it with [jq](https://jqlang.org/) (`brew install jq`, `apt-get install jq`, or the copy in the scanner's Docker image: `docker run --rm -v "$PWD":/data --entrypoint jq kanopi/script-hound …`). Anything ending in `| @csv` produces CSV, so redirect it to a file and open it in a spreadsheet.

Every recipe reads `reports/report.json`. Change the path if you used `--out`.

## Findings

**All findings as CSV**, one row per finding:

```bash
jq -r '["site","page","severity","rule","message","script","line","column","via"],
  (.sites[] as $s | $s.pages[] as $p | $p.issues[]
   | [$s.name, $p.url, .severity, (.rule // .type), .message, (.script // .host // ""), (.line // ""), (.column // ""), (.origin.via // "")])
  | @csv' reports/report.json > findings.csv
```

**Only high and medium**, as a quick list:

```bash
jq -r '.sites[].pages[] as $p | $p.issues[]
  | select(.severity == "high" or .severity == "medium")
  | "\(.severity | ascii_upcase)\t\(.rule // .type)\t\($p.url)\t\(.message)"' reports/report.json
```

**Count high findings** (for a custom gate in a script; `--fail-on` does this built in):

```bash
jq '[.sites[].pages[].issues[] | select(.severity == "high")] | length' reports/report.json
```

## PCI DSS 6.4.3 script inventory

Every external script on every page, with how it got there, what loaded it, its hash and any rule flags. The last column, `business_justification`, is left empty for you to fill in:

```bash
jq -r '["site","page","script","party","delivered","via","loaded_by","sha256","flags","business_justification"],
  (.sites[] as $s | $s.pages[] as $p | $p.scripts[] | select(.inline | not)
   | [$s.name, $p.url, .url, (if .thirdParty then "3rd-party" else "1st-party" end),
      (.origin.delivered // ""), (.origin.via // ""), ((.origin.trail // []) | join(" <- ")),
      .sha256, ([.flags[]? | "\(.severity):\(.rule)"] | join(" ")), ""])
  | @csv' reports/report.json > script-inventory.csv
```

To limit it to payment pages, add `select($p.paymentPage)` after `$p.scripts[]`.

**Payment pages: third-party script tags without SRI:**

```bash
jq -r '.sites[].pages[] | select(.paymentPage) | .url as $u
  | .scriptTags[] | select(.integrity == "") | "\($u)\t\(.src)"' reports/report.json
```

## Third parties

**Third-party hosts across all sites**, most widespread first:

```bash
jq -r '[.sites[] as $s | $s.pages[] as $p | $p.domains[] | select(.thirdParty) | {site: $s.name, host}]
  | group_by(.host) | map({host: .[0].host, sites: (map(.site) | unique | join(", ")), pages: length})
  | sort_by(-.pages) | .[] | "\(.pages)\t\(.host)\t\(.sites)"' reports/report.json
```

**New third-party hosts compared with a previous report:**

```bash
jq -r --slurpfile old previous/report.json '
  ([$old[0].sites[].pages[].domains[] | select(.thirdParty) | .host] | unique) as $before
  | [.sites[].pages[].domains[] | select(.thirdParty) | .host] | unique
  | map(select(. as $h | $before | index($h) | not))
  | if length == 0 then "no new third-party hosts" else .[] end' reports/report.json
```

**Scripts added through Google Tag Manager**, with the container and tag:

```bash
jq -r '[.sites[].pages[].scripts[] | select(.origin.gtm)
  | {container: .origin.gtm.container,
     tags: ([.origin.gtm.tags[] | "tag \(.id) (\(.type))"] | join(" or ") | if . == "" then "not identified" else . end),
     script: (if .inline then .key else .url end)}]
  | unique_by(.script) | .[] | "\(.container)\t\(.tags)\t\(.script)"' reports/report.json
```

## Cookies and storage

**Cookie inventory as CSV:**

```bash
jq -r '["site","page","name","domain","party","set_by","httpOnly","secure","sameSite"],
  (.sites[] as $s | $s.pages[] as $p | $p.cookies[]?
   | [$s.name, $p.url, .name, .domain, (if .thirdParty then "3rd-party" else "1st-party" end), .setBy, .httpOnly, .secure, (.sameSite // "")])
  | @csv' reports/report.json > cookies.csv
```

**localStorage / sessionStorage keys as CSV:**

```bash
jq -r '["site","page","origin","type","key","kind","size","first_written"],
  (.sites[] as $s | $s.pages[] as $p | $p.storage[]?
   | [$s.name, $p.url, .origin, .type, .key, .kind, .size, (.firstWritten // "")])
  | @csv' reports/report.json > storage.csv
```

With `--show-values`, add `.value` to the row for full values. That file then holds live values, so treat it as sensitive.

## Security posture

**Vulnerable libraries:**

```bash
jq -r '.sites[].pages[] as $p | $p.issues[] | select(.type == "vulnerable-library")
  | "\(.library.name) \(.library.version)\t\(.severity)\t\($p.url)\t\(.script)"' reports/report.json
```

**Security-header problems per page:**

```bash
jq -r '.sites[].pages[] | . as $p
  | [.issues[] | select(.type | test("csp-missing|csp-weak|hsts-missing|clickjacking-unprotected|nosniff-missing|referrer-policy-missing")) | .type]
  | select(length > 0) | "\($p.url)\t\(join(", "))"' reports/report.json
```

Header findings are reported once per site in crawl and sitemap mode (the rest carry `alsoOn`), so the list is short.

## Where things are in report.json

```
meta                 run time, page count, modes, baselineUsed, containsValues
summary              { high, medium, low, info } counts
sites[]              name, mode, session, rules (changes in effect), auth (names only), pages[]
  pages[]            one per URL and browser profile
    url, finalUrl, profile, status, error, paymentPage, authenticated, sharedSession
    issues[]         findings: severity, type, rule, message, script, host, match, line, column,
                     context, htmlLine, phase, origin { delivered, via, trail[], hint, gtm }, alsoOn,
                     originalSeverity (if config changed it), library (vulnerable-library)
    suppressed[]     findings hidden by a suppression, with suppressedBy
    scripts[]        url or inline key, host, thirdParty, inline, dynamic, size, sha256, phase,
                     flags[] (rule, severity, match, line, column), libs[], origin { … }
    stylesheets[]    url or inline key, host, thirdParty, size, sha256, flags[]
    domains[]        host, thirdParty, types[], count, phase, origin
    cookies[]        name, domain, thirdParty, setBy, httpOnly, secure, sameSite, session,
                     expiresDays (value only with --show-values)
    storage[]        origin, thirdParty, type, key, kind, size, preview, firstWritten (value with --show-values)
    indexedDB[], cacheStorage[], serviceWorkers[], opfs[], windowName, historyState
    responseHeaders[], requestHeaders[], responseStatus   (main document; secrets masked)
    scriptTags[]     src, integrity (for SRI checks)
    iframes[], forms[], websockets[], interactions[], blockedSubmissions[]
    html             { server, rendered } file paths and tag counts (with --show-html)
```

The rule ids used in `type`/`rule` are listed by `./scan --list-rules` and in [How it works](how-it-works.md) and [Security checks](security-checks.md).
