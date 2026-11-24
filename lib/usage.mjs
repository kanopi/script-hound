// `--help` text and friendly errors for bad command-line arguments.

export const USAGE = `ScriptHound: sniffs out malicious front-end code.
Loads pages like a visitor and reports malicious code, front-end security weaknesses and changes.

Usage:
  ./scan [options]            (or: scripthound [options] after npm link, or node scan.mjs [options])
  ./scan --urls https://example.com/ --format console

What to scan:
  --urls <list>            Comma/space-separated URLs (replaces sites.json)      [SCAN_URLS]
  --site <name>            Only this site from sites.json                         [SCAN_SITE]
  --mode <url|crawl|sitemap>  How pages are found (default url)                   [SCAN_MODE]
  --sitemap <url|file>     Sitemap to read (implies --mode sitemap)               [SCAN_SITEMAP]
  --max-pages <n>          Page cap per site for crawl/sitemap (default 25, 0 = none) [SCAN_MAX_PAGES]
  --depth <n>              Crawl link depth (default 2)                           [SCAN_DEPTH]
  --include-subdomains     Let crawl/sitemap visit other subdomains               [SCAN_INCLUDE_SUBDOMAINS=1]

How pages are visited:
  --interactions <v>       Custom steps: inline JSON, a .json file, a .js/.mjs hook,
                           or inline JS (repeatable; replaces sites.json ones)    [SCAN_INTERACTIONS]
  --user-agent <ua>        Browser user agent for every site and profile         [SCAN_USER_AGENT]
  --session <page|site>    page (default): every page is a first visit, fresh cookies;
                           site: cookies/storage carry from page to page, in order [SCAN_SESSION]
  --dom-xss-canary         Extra load per page with an inert marker in the URL #fragment,
                           to find DOM-XSS sinks (never sent to the server)       [SCAN_DOM_XSS_CANARY=1]

Logged-in scans (values never appear in reports; use \${env:NAME} in config for secrets):
  --header "Name: value"   Extra request header, sent only to the site's own hosts (repeatable) [SCAN_HEADERS, one per line]
  --cookie "name=value"    Cookie to set before loading pages (repeatable)       [SCAN_COOKIES="a=1; b=2"]
  --cookie <file>          Without "=": load a cookie file (curl/Netscape jar or Playwright JSON), like curl -b
  --cookie-jar <file>      After the scan, write all cookies to a curl-compatible jar (mode 600), like curl -c
                           (use the same file for both to carry cookies between runs) [SCAN_COOKIE_JAR]
  --storage-state <file>   Playwright storage state (cookies + localStorage), e.g. from
                           npx playwright codegen --save-storage=auth.json <login-url> [SCAN_STORAGE_STATE]

Files:
  --config <file>          Sites and per-site settings (default sites.json)
  --global-config <file>   Global defaults and rule settings (default config.json) [SCAN_GLOBAL_CONFIG]
  --baseline <file>        Baseline to compare against (default baseline.json)
  --update-baseline        Overwrite the baseline with this run's results
  --out <dir>              Report folder (default reports)

Rules:
  --disable-rule <id>      Turn a rule off for this run (repeatable)             [SCAN_DISABLE_RULES]
  --list-rules             Print every rule and its effective setting, then exit
  --fail-on <level>        Exit 1 on findings at/above none|high|medium|low (default none) [SCAN_FAIL_ON]

Output:
  --format <list>          html,md,console,json (default html,md; report.json always; for CSV use jq,
                           see docs/jq-recipes.md)                                [SCAN_FORMAT]
  --show-scripts           Add the third-party script loader tree to console output [SCAN_SHOW_SCRIPTS=1]
  --show-cookies           Add the cookie inventory (who set what) to console output [SCAN_SHOW_COOKIES=1]
  --show-storage           Add localStorage/sessionStorage, IndexedDB, caches and service workers to console output [SCAN_SHOW_STORAGE=1]
  --show-headers           Add the main document's response and request headers to console output (security
                           headers marked present/missing; cookie and supplied values masked) [SCAN_SHOW_HEADERS=1]
  --show-html              Save each page's server HTML and rendered DOM (after scripts) to <out>/html/, print
                           the server HTML and a summary of what scripts added      [SCAN_SHOW_HTML=1]
  --show-values            Show cookie and storage VALUES in the lists you asked for (--show-cookies and/or
                           --show-storage; both if neither) and in reports. Reports then contain live values:
                           treat them as sensitive [SCAN_SHOW_VALUES=1]
  --color <when>           auto|always|never (default auto)                      [NO_COLOR / FORCE_COLOR]

Other:
  -h, --help               Show this help

Environment only: SCAN_PROXY=http://host:port (browser proxy), SCAN_IGNORE_TLS=1 (testing only, never in CI).
Exit codes: 0 finished, 1 --fail-on threshold hit or unexpected error, 2 bad arguments or nothing to scan.

Examples:
  ./scan                                                     # sites.json + baseline.json
  ./scan --urls https://shop.example.com/ --mode crawl --max-pages 50
  ./scan --sitemap https://shop.example.com/sitemap.xml --format html,md
  ./scan --urls https://shop.example.com/ --show-scripts --format console

Docs: README.md and docs/ (configuration.md has every option).`;

// Edit distance, for "did you mean" suggestions on mistyped flags.
function distance(a, b) {
  const d = Array.from({ length: a.length + 1 }, (_, i) => [i, ...Array(b.length).fill(0)]);
  for (let j = 1; j <= b.length; j++) d[0][j] = j;
  for (let i = 1; i <= a.length; i++)
    for (let j = 1; j <= b.length; j++) d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
  return d[a.length][b.length];
}

/** Turn a parseArgs error into one helpful line (plus a suggestion when a flag looks mistyped). */
export function argError(err, optionNames) {
  const msg = String(err?.message || err);
  const unknown = /Unknown option '(-{1,2}[^']+)'/.exec(msg);
  if (unknown) {
    const name = unknown[1].replace(/^-+/, '').split('=')[0];
    const best = optionNames.map((o) => [o, distance(name, o)]).sort((a, b) => a[1] - b[1])[0];
    const hint = best && best[1] <= Math.max(2, Math.floor(name.length / 3)) ? ` Did you mean --${best[0]}?` : '';
    return `Unknown option ${unknown[1]}.${hint}`;
  }
  const missing = /Option '([^']+)' argument missing/.exec(msg);
  if (missing) return `Option ${missing[1].replace(/^-\w, /, '')} needs a value.`;
  const positional = /Unexpected argument '([^']+)'/.exec(msg);
  if (positional) {
    const v = positional[1];
    return /^https?:\/\//i.test(v) ? `Unexpected argument '${v}'. To scan a URL, use --urls ${v}` : `Unexpected argument '${v}'. Options start with --.`;
  }
  return msg.split('\n')[0];
}
