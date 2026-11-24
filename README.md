<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="brand/scripthound-logo-dark.svg">
    <img src="brand/scripthound-logo.svg" alt="ScriptHound: sniffs out malicious front-end code" height="96">
  </picture>
</p>

# ScriptHound

**ScriptHound sniffs out malicious front-end code.** It loads your pages in a real (headless) Chrome like a visitor would, interacts with them, and reports what's running in the browser that's malicious, unsafe or unexpectedly changed.

| | What it finds |
|---|---|
| **Compromise** | Skimmers, injected and obfuscated scripts, malicious loaders, cryptominers, cloaked redirects, CSS keyloggers, hidden iframes, and payloads stashed in browser storage. Code that only arrives at runtime is checked too |
| **Weaknesses** | DOM-XSS sinks, known-vulnerable libraries, missing or weak CSP (with a suggested policy), missing security headers and SRI, mixed content, exposed secrets, insecure cookies and storage. This is the OWASP Client-Side Top 10 |
| **Change** | Every script, stylesheet, domain, cookie and storage key, where each came from (down to the GTM tag), and what changed since the last scan. Supports PCI DSS 6.4.3 / 11.6.1 |

It's **passive**: it behaves like a visitor and never sends attack payloads or submits forms. For active penetration testing, pair it with a DAST tool such as OWASP ZAP.

## Install

**With Node.js 20+:**

```bash
git clone https://github.com/kanopi/script-hound.git && cd script-hound
make install          # npm ci + Playwright's Chromium
./scan --help
```

Run `npm link` once to get a `scripthound` command you can use from any folder. `./scan` works from anywhere too, and reports are written to the folder you run it in.

**With Docker** (no Node needed). The image is on Docker Hub as [`kanopi/script-hound`](https://hub.docker.com/r/kanopi/script-hound), for both Intel/AMD and ARM:

```bash
docker pull kanopi/script-hound
docker run --rm -t --ipc=host -v "$PWD":/data kanopi/script-hound --help
```

Or build it from this repo with `docker build -t kanopi/script-hound .`

In Docker, your current folder is mounted at `/data`, so config files are read from it and reports are written back to it. See [Docker](docs/docker.md).

## Usage

### Scan a page

```bash
./scan --urls https://shop.example.com/ --format console
```

The console shows the findings. `reports/report.html` has the full report: findings, where each script came from, and inventories of scripts, domains, cookies, storage and headers. Add more pages with commas: `--urls https://shop.example.com/,https://shop.example.com/checkout`.

Pick pages an attacker would aim at: checkout, donate, login, contact and lead forms, and the home page.

### Scan a whole site

```bash
./scan --urls https://shop.example.com/ --mode crawl --max-pages 50       # follow links on the site
./scan --sitemap https://shop.example.com/sitemap.xml --max-pages 40      # pages from the sitemap
```

Neither mode ever leaves the site. See [Discovery modes](docs/discovery.md).

### Monitor sites on a schedule

List your sites once, record a known-good baseline, then scan regularly. Each scan reports what's new or changed since the baseline.

```bash
cp sites.example.json sites.json     # your sites, pages and first-party domains
cp config.example.json config.json   # optional: global defaults and rule settings
./scan --update-baseline             # first scan of known-clean sites → baseline.json
./scan                               # later scans compare against it
```

Run it on a schedule in CircleCI ([CircleCI](docs/circleci.md)) or any scheduler. After reviewing changes that turn out to be legitimate (a deploy, a vendor update), accept them with `./scan --update-baseline`, or copy `reports/baseline.next.json` over `baseline.json`.

### Investigate a finding

These views add detail to the console (the HTML report always has all of them):

```bash
./scan --urls https://shop.example.com/ --show-scripts     # tree of what loaded each third-party script, down to the GTM tag
./scan --urls https://shop.example.com/ --show-cookies     # every cookie, and whether the server or JavaScript set it
./scan --urls https://shop.example.com/ --show-storage     # localStorage, IndexedDB, caches, service workers…
./scan --urls https://shop.example.com/ --show-headers     # response and request headers
./scan --urls https://shop.example.com/ --show-html        # HTML as sent vs after scripts ran, saved to reports/html/
```

Add `--show-values` to see cookie and storage values (the report then contains live values). Each finding names the rule that fired, the file, line and column, how the script got onto the page, and where to look. See [Reports](docs/reports.md).

### Scan logged-in pages

```bash
npx playwright codegen --save-storage=auth.json https://shop.example.com/login   # log in once, close the window
./scan --urls https://shop.example.com/account --storage-state auth.json
./scan --urls https://staging.example.com/ --header "Authorization: Basic …"
./scan --urls https://shop.example.com/ --cookie cookies.txt --cookie-jar cookies.txt   # curl-style cookie jar
```

Headers are only sent to the site's own hosts, and values never appear in reports. See [Logged-in scans](docs/configuration.md#logged-in-scans).

### Open a payment form or a cart first

Some skimmers only appear after a visitor opens a "Pay by card" panel or a cart drawer. Script those steps:

```bash
./scan --urls https://shop.example.com/checkout \
  --interactions '[{"click":"text=Pay by card","label":"open card form"},{"wait":1500}]'
```

Steps can also live in `sites.json` or a JavaScript file. Forms are never submitted, even if a step clicks "Pay". See [Custom interactions](docs/interactions.md).

### Fail a CI build

By default ScriptHound only reports. To fail a job when something serious turns up:

```bash
./scan --fail-on high        # exit 1 on any high finding (or: medium, low)
```

### Tune the rules

```bash
./scan --list-rules                          # every rule and its current setting
./scan --disable-rule obfuscator-io          # turn one off for this run
```

To turn rules off or change their severity permanently, silence one false positive, or add your own patterns, use `config.json` and `sites.json`. Every change is listed in the report. See [Rules](docs/rules.md).

### Spreadsheets and summaries

`reports/report.json` holds everything. [jq recipes](docs/jq-recipes.md) turn it into CSVs (findings, a PCI 6.4.3 script inventory, cookies, storage) and quick summaries.

## Reading the results

| Severity | Means |
|---|---|
| **High** | Investigate now. Patterns that are rarely legitimate: decoded `eval`, card-data harvesting, miners, off-site redirects, a CSS keylogger… |
| **Medium** | Review. Suspicious, but some legitimate code does it, such as a new third-party script or a vulnerable library |
| **Low / Info** | Notes and weaknesses worth knowing about, such as missing headers or a new first-party file |

The rules are heuristics, tested to have no high or medium hits across about 3,200 popular library files and vendor SDKs. A medium or low finding means "take a look", not "malware". The *loaded by* trails and *where to look* hints are leads, not proof.

## Common options

| Option | Does |
|---|---|
| `--urls <list>` / `--site <name>` | Pages to scan / one site from `sites.json` |
| `--mode crawl\|sitemap`, `--sitemap <url>`, `--max-pages <n>` | Find pages for you |
| `--format html,md,console,json` | Outputs (default `html,md`; `report.json` is always written) |
| `--show-scripts\|cookies\|storage\|headers\|html`, `--show-values` | Extra detail in the console and Markdown |
| `--storage-state`, `--cookie`, `--header`, `--cookie-jar` | Logged-in scans |
| `--interactions <steps>` | Scripted clicks, typing and waits |
| `--session page\|site` | Fresh cookies per page (default), or one visitor across the site |
| `--user-agent <ua>` | Custom user agent (desktop and/or mobile browsers are set with `profiles` in `sites.json`) |
| `--dom-xss-canary` | Extra check for DOM-XSS sinks |
| `--update-baseline`, `--fail-on <level>` | Accept changes, gate a build |
| `--list-rules`, `--disable-rule <id>` | Inspect and adjust rules |

`./scan --help` lists everything, and [Configuration](docs/configuration.md) documents every option, environment variable and config key.

## Documentation

| Doc | Covers |
|---|---|
| [How it works](docs/how-it-works.md) | Interaction phases, detection rules, runtime code, where-it-came-from trails, GTM tags, baseline diff, severities |
| [Security checks](docs/security-checks.md) | Headers, CSP and the suggested policy, SRI, vulnerable libraries, secrets, cookies, browser storage, CSS, the DOM-XSS canary, OWASP mapping |
| [Configuration](docs/configuration.md) | `config.json` and `sites.json`, every flag and environment variable, sessions, logged-in scans, cookie jars, user agent, exit codes |
| [Rules](docs/rules.md) | Turning rules off, changing severity, suppressing a false positive, custom rules |
| [Discovery modes](docs/discovery.md) | Single URL, crawl and sitemap modes |
| [Custom interactions](docs/interactions.md) | Scripted steps (JSON, JavaScript, command line) and the form-submission guard |
| [Reports](docs/reports.md) | HTML, Markdown, JSON and console output, and where each view goes |
| [jq recipes](docs/jq-recipes.md) | Spreadsheets and summaries from `report.json` |
| [CircleCI](docs/circleci.md) | Scheduled and on-demand runs, parameters, artifacts |
| [Docker](docs/docker.md) | Running, building for other architectures, publishing |
| [Development](docs/development.md) | Working on ScriptHound: tests, adding rules, project layout, releases |
| [Brand](brand/README.md) | Logo files, colors and usage |

## License

ScriptHound is licensed under the [Apache License 2.0](LICENSE). Copyright 2026 Kanopi Studios. It includes the [Retire.js](https://github.com/RetireJS/retire.js) vulnerability database (also Apache-2.0); see [NOTICE](NOTICE).

The name "ScriptHound" and the logo are trademarks of Kanopi Studios and aren't covered by the license. You're welcome to use and modify the code, but please don't use the name or logo for a fork or a different product. See [brand/README.md](brand/README.md).

## Limits

- By default it sees what a first-time, anonymous visitor sees on the pages it loads. Logged-in scans, shared sessions and interactions cover more, but a skimmer that only targets certain countries, or only a real checkout with items in the cart, can still be missed. Consider server-side file-integrity monitoring as well.
- It's passive: it finds XSS sinks and the results of an injection, but doesn't try to inject anything.
- It never submits forms, but sites with autosave or abandoned-cart features may record its dummy entry (`scripthound@example.invalid`). Set `"exerciseForms": false` for those sites.
