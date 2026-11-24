# Reports

`report.json` and `baseline.next.json` are always written to the output folder (`--out`, default `reports`). Choose the other formats with `--format` (or `SCAN_FORMAT`), comma-separated. The default is `html,md`. For spreadsheets, use the [jq recipes](jq-recipes.md).

| Format | Output |
|---|---|
| `html` | `report.html`: self-contained (opens from CircleCI artifacts), with findings plus collapsible script and domain inventories for each page |
| `md` | `report.md`: a findings summary, printed in the CircleCI log |
| `console` | Findings printed to the terminal |
| `json` | `report.json` (always written anyway): everything, for other tooling |

## Where the views go

The `--show-*` views (`--show-scripts`, `--show-cookies`, `--show-storage`, `--show-headers`, `--show-html`) appear in every output:

| Output | Views |
|---|---|
| HTML | **Always all of them**, as collapsed sections: script inventory and loader tree, cookies, browser storage, headers, stylesheets, and the HTML view (links, what scripts changed, and a server-HTML excerpt when `--show-html` ran) |
| Console | The views you asked for |
| Markdown | The views you asked for, as code blocks under each page. Without flags it stays findings-only, since it's printed in the CircleCI log |
| JSON | Always everything (the HTML itself stays in `<out>/html/`). Build spreadsheets and summaries from it with [jq recipes](jq-recipes.md) |

## What each finding includes

Where it applies, each finding includes:

- **Severity, rule and message.** The rule is the id of what fired, for example `skimmer-field-harvest` or `new-domain`. See the rule tables in [How it works](how-it-works.md#3-pattern-rules).
- **Where in the code** (pattern rules): the script, `line N, col N`, the page-HTML line for server-sent inline scripts, the match (for the skimmer rule, which field and which destination host) and a snippet of the surrounding code.
- **Via:** how the script got onto the page, for example `<script src> in page HTML, line 42`, `inserted by gtm.js?id=GTM-ABC:415:252`, `ES module import by index.js`, `loaded inside iframe …`, or `created by loader.js:1:86` for [code that arrived at runtime](how-it-works.md#code-that-arrives-at-runtime). For anything added through Google Tag Manager it ends with the container and tag, for example `· GTM-WWZFMZRX: tag ID 37 (type: Custom HTML)`. See [Which GTM tag added it](how-it-works.md#which-gtm-tag-added-it).
- **First seen:** the [phase](how-it-works.md#2-interaction) in which it first appeared, when that wasn't page load (for example *scroll*, *form input* or *custom: open card form*).
- **Delivered:** in the page HTML, or added at runtime.
- **Loaded by:** the trail back to the page HTML, for example `gtm.js?id=GTM-ABC ← inline script ← page HTML`.
- **Where to look:** a hint for where to start digging.

See [How it works](how-it-works.md#5-where-it-came-from) for how these are worked out, and treat them as leads, not proof.

## HTML

Each page has a findings table and two collapsible inventories:

- **Script inventory:** every script, labeled 1st-party, 3rd-party or inline, with how it got there and what loaded it, when it appeared (interaction-triggered loads in bold), size, hash, and rule flags with their line:column.
- **Domains contacted:** every host, labeled 1st or 3rd party, with request types, counts, which script made the first request, and when.
- **Browser storage:** `localStorage`/`sessionStorage` keys for the page and its iframes (kind, size, when first written, masked preview), plus IndexedDB, Cache Storage and service workers. See [Browser storage inventory](security-checks.md#browser-storage-inventory). Add `--show-storage` for the same list in the console.
- **Stylesheets:** every external stylesheet and inline `<style>`, with hash and CSS rule flags. See [CSS](security-checks.md#css).
- **Cookies:** every cookie after the visit: first- or third-party, who set it (server, JavaScript, or you for logged-in scans), flags and expiry. See [Cookie inventory](security-checks.md#cookie-inventory). Add `--show-cookies` for the same list in the console.

If a page had [custom interactions](interactions.md), its step log is shown too.

## Spreadsheets (CSV)

There's no CSV output. `report.json` has everything, and `jq` turns it into CSV for findings, a PCI DSS 6.4.3 script inventory, cookies, storage and more. See [jq recipes](jq-recipes.md).

## Console

Findings are grouped by site and page, with a blank line between findings and indented detail lines:

```
━━━ shop.example.com (crawl) ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

● https://shop.example.com/checkout (desktop) — 2 finding(s) · 1 script(s) loaded only after interaction

    HIGH    skimmer-field-harvest  Reads payment card fields and sends them to an external host
            in         https://shop.example.com/js/theme.js
            at         line 2, col 72
            match      card field "cc_number" read and sent to img-cdn-stat.example
            code       …var d={n:document.querySelector('[name=cc_number]').value,c:document.querySelector('[name=cvv]')…
            via        <script src> in page HTML, line 42
            loaded by  page HTML
            look       This script is referenced in the server's HTML and served from this site: compare the file on disk…
```

The page line also shows the custom-step log (✓/✗) and any blocked form submissions.

### Headers (`--show-headers`)

The main document's response headers, with the status code, plus the request headers the browser sent. Security headers (CSP, HSTS, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`) are highlighted, and any that are missing are listed. Cookie values in `Set-Cookie` and `Cookie` are masked unless you add `--show-values`, and headers and cookies you supplied are always masked. Both lists are also in the HTML report (collapsed, under "Headers") and `report.json`.

### HTML as sent vs rendered (`--show-html`)

For each page, two files are saved in `<out>/html/`:

- `NNN-<host>_<path>-<profile>.server.html`: the HTML exactly as the server sent it.
- `NNN-<host>_<path>-<profile>.rendered.html`: the page after scripts ran, which is what the visitor actually got.

The console prints the server HTML (first 200 lines, then the path to the full file) and a summary of what scripts changed:

```
    HTML
      server (as sent):     reports/html/000-www.example.com_home-desktop.server.html (341.8 KB, 4288 lines)
      rendered (after JS):  reports/html/000-www.example.com_home-desktop.rendered.html (1.6 MB, 10315 lines)
      changed by scripts:   +73 <script>, +5 <iframe>, +9 <input>, +19 <style>, +4 <link>, +147 <img>, +597 <div>
```

Comparing the two (`diff`, or any diff tool) is the quickest way to see what was injected at runtime. The HTML report links both files. `report.json` keeps only the paths and counts, not the HTML.

### Colors

Severities are colored (high red, medium yellow, low cyan, clean green), and labels and hints are dimmed. Colors are on automatically when the output is a terminal and off when it's piped or logged. To override, use `--color always` or `--color never`, or the standard `NO_COLOR` and `FORCE_COLOR=1` environment variables. With Docker, add `-t` so the container sees a terminal.

### Script tree (`--show-scripts`)

`--show-scripts` adds a loader tree of third-party scripts under each page. It also turns on `console` output.

```
    Third-party scripts (98 across 15 hosts)
      page HTML
      ├─ https://shop.example.com/js/theme.js (1st-party)  CHANGED FLAGGED high: skimmer-field-harvest@2:72
      │  │  ↳ <script src> in page HTML, line 42
      │  └─ https://img-cdn-stat.example/p.js  NEW
      │        ↳ inserted by theme.js:2:310
      └─ inline script inline#9d968aa65048785b
         │  ↳ inline <script> in page HTML, line 515
         └─ https://www.googletagmanager.com/gtm.js?id=GTM-TH8KRSBJ
            │  ↳ inserted by inline script inline#9d968aa65048785b, line 519
            └─ https://connect.facebook.net/en_US/fbevents.js  ON FORM INPUT
                  ↳ inserted by gtm.js?id=GTM-TH8KRSBJ:415:252 · GTM-TH8KRSBJ: tag ID 37 (type: Custom HTML)
      loader not traced (browser-internal, eval/dynamic code, or tracing off)
      └─ https://www.datadoghq-browser-agent.com/datadog-logs.js
```

- **The root is the page HTML**, and each script sits under whatever loaded it.
- **Third-party scripts are shown in full.** First-party files and inline scripts appear dimmed, and only where they lead to a third-party script.
- **Under each node, `↳` says how it got there:** a `<script src>` or inline `<script>` at a given page-HTML line, `inserted by <file>:<line>:<col>` (the exact spot in the loader's code), an ES module import, or loading inside an iframe.
- **Tags:**
  - `NEW` and `CHANGED`: compared with the baseline.
  - `FLAGGED <severity>: <rule>@<line>:<col>`: every pattern rule that fired on that script, and where.
  - `ON <phase>`: the script only loaded after an interaction (`after idle wait` for timer loads).
- **ES module chunks** are linked to the file that imports them. **Scripts inside iframes** (for example Shopify web-pixel sandboxes) sit under their iframe document.
- **Long runs collapse.** After four untagged sibling scripts from the same host, the rest become "… N more from host". Anything tagged NEW, CHANGED, FLAGGED or ON … is never collapsed.
- **"Loader not traced"** holds scripts started by code the browser can't attribute, such as `eval` output or browser-internal loads.
