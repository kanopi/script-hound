# How ScriptHound works

ScriptHound looks for three things: **compromise** (malicious code of any kind), **weaknesses** (front-end security issues) and **change** (what's new or different since the baseline). It does that passively, as a visitor would.

For each URL, in a desktop and/or mobile browser profile, it runs through six stages. The rules below cover compromise. Weaknesses (headers, CSP, libraries, XSS sinks, cookies, storage, CSS) are in [Security checks](security-checks.md).

## 1. Inventory

It records every external and inline script with its SHA-256 hash, every domain contacted, WebSockets, workers, iframes, form actions and meta refreshes.

## 2. Interaction

Some payloads only run once a visitor does something, so the scanner acts like one. It goes through these phases in order:

| Phase | What happens |
|---|---|
| page load | Navigation until the network goes quiet |
| idle wait | A short pause (default 2s, `options.idleBeforeInteractMs`), so timer-delayed scripts aren't blamed on the interactions |
| mouse movement | Moves the mouse across the page |
| scroll | Scrolls to the bottom |
| form input | Fills visible form fields with dummy data and types a card number key by key, so keyloggers and skimmers that only fire on input get a chance to run |
| custom steps | Any [custom interactions](interactions.md) configured for the page, one phase per step |
| after interaction | A final wait (`options.waitMs`, default 4s) to catch delayed reactions |

**It never submits forms.** A guard answers any form-style navigation with `204 No Content`, so the browser stays on the page, and records each blocked attempt. The built-in steps never click buttons or links. [Custom steps](interactions.md) can click, and the guard still applies.

Every script and domain records the phase it first appeared in. Anything that only loads once the "visitor" scrolls, types or completes a custom step is tagged in the reports (for example `ON FORM INPUT` in the console tree), because skimmers often wait for a human. See [Reading the phase tags](#reading-the-phase-tags).

## 3. Pattern rules

Every script body (external and inline) is checked against the rules in `lib/heuristics.mjs`. Each finding names the rule that fired and **where**: line, column and the surrounding code. For a server-sent inline script, it also gives the matching line in the page's HTML source.

| Severity | Rule | Fires on |
|---|---|---|
| high | `skimmer-field-harvest` | A card field (`cc_number`, `cvv`, `card-number`…) and a read of its value or a listener, within 1,500 characters of each other (or anywhere in a standalone file under 20 KB), plus one of these nearby: **(a)** a send (Image beacon, `sendBeacon`, WebSocket, `fetch`, XHR, `$.ajax`) to an external URL, and the finding names the host; **(b)** a send to a decoded or runtime-built address (`fetch(atob(…))`, `'https://' + btoa(n) + '.com'`); or **(c)** the data stashed in `localStorage`/`sessionStorage` for a separate routine to upload later. Payment processors' own domains (Stripe, Braintree, PayPal, Adyen, Square…) don't count as destinations unless a Stripe secret key is nearby. Look-alike domains always count |
| high | `stripe-secret-key` | A Stripe secret or restricted key (`sk_live_…`, `rk_test_…`) in page code. Front ends only ever need publishable `pk_` keys. In 2026, skimmers used secret keys to write stolen cards into the attacker's own Stripe account |
| high | `remote-code-exec` | Running code that just arrived over the network: `new Function(event.data)`, `eval(xhr.responseText)`, or `eval`/`new Function` inside a `fetch(…).then(…)` chain |
| high | `whitespace-decode` | A payload hidden as spaces and tabs (for example after the CSS in a `.css` file), turned back into bits and characters |
| high | `blockchain-loader` | Reads a smart contract (`eth_call`) and uses the result to load or run code ("EtherHiding") |
| high | `fake-gtm-loader` | A snippet that looks like Google Tag Manager's but calls `atob()`. The real GTM snippet never decodes anything |
| high | `eval-decoded` | `eval(atob(…))`, `Function(unescape(…))`: running hidden code |
| high | `script-injection-decoded` | `src = atob(…)`: loading a script from a hidden address |
| high | `encoded-redirect` | `location = atob(…)` |
| high | `cryptominer` | Known in-browser miner names (CoinHive, CryptoLoot…) |
| medium | `form-harvest-generic` | Every `input, select, textarea` read, encoded (hex, XOR or base64) and sent. These harvesters carry no card-field names at all. Medium, because session-replay tools also read inputs |
| medium | `credential-harvest` | A password field selector and a beacon-style send close together. Selectors that *exclude* passwords (`:not([type=password])`) don't count |
| medium | `keylogger` | A document- or window-wide key listener that collects key data (`buf += e.key`, `log.push(e.keyCode)`). Shortcut handlers that only check keys don't count |
| medium | `cloaked-redirect` | Redirect that depends on referrer, user agent or cookie |
| medium | `document-write-script` | `document.write('<script…')` |
| medium | `charcode-blob` / `hex-escape-density` | Long `fromCharCode(…)` or `\xNN` payloads |
| low | `base64-blob` | A 1,500+ character base64 string that isn't an image or font |
| low | `obfuscator-io` | 25+ `_0x1a2b`-style identifiers |

### Code that arrives at runtime

Many skimmers never exist as a normal script file. A loader fetches the real payload and runs it with `eval` or `new Function`. The payload can come from a WebSocket, from Stripe customer metadata, from a comment in the site's own 404 page, or from a blockchain contract. Some inline scripts also delete themselves after running.

The browser still compiles that code, and the scanner reads it at that point, through the same DevTools session it uses for tracing. Everything the browser compiled that isn't in the final page is pattern-checked. Anything that trips a rule appears in the report as *dynamically created code* or *inline script removed after running*, with the trail back to the code that ran it. Code that trips nothing is left out of the report. This code is never baselined: it's only pattern-checked.

## 4. Page-level checks

| Severity | Rule | Fires on |
|---|---|---|
| high | `offsite-redirect` | The page redirected to another site |
| high | `blocklisted-domain` | A request to a domain in `blockDomains` |
| medium | `meta-refresh` | A `<meta http-equiv="refresh">` that sends the page to a third-party URL |
| medium | `hidden-iframe` | A hidden third-party iframe |
| medium | `offsite-form` | A form that posts to a third-party host |
| medium | `websocket` | A WebSocket to a third-party host |
| high | `handler-runs-decoded-code` | An inline `on*` attribute that runs decoded code, e.g. `<svg onload="setTimeout(atob('…'))">` or `<img src onerror="eval(atob(…))">` |
| medium | `obfuscated-handler` | An inline `on*` attribute with `atob`, `eval`, `fromCharCode` or `\x` escapes that doesn't run them directly |
| low | `handler-loads-script` | An inline `on*` attribute that creates a `<script>`, with its URL. Usually a CDN fallback (`onerror` → load a backup copy), but also a known injection trick |

## 5. Where it came from

For each script, and for the first request to each domain, the report shows:

- **Delivered:** whether the code was in the HTML the server sent, or added at runtime.
- **Loaded by:** a best-effort trail, for example `gtm.js?id=GTM-ABC ← inline script ← page HTML`.
- **Where to look:** a hint such as theme templates, a first-party file, a third-party vendor, or a named GTM, Tealium or Adobe container.
- **GTM tag:** for anything added through Google Tag Manager, the container and the tag that added it, for example `GTM-WWZFMZRX: tag ID 37 (type: Custom HTML)`. See [Which GTM tag added it](#which-gtm-tag-added-it).

The trail comes from the browser's own record of what requested what, through the DevTools protocol, without injecting anything into the page. Some loads the browser doesn't attribute: ES module chunks are linked to the file that imports them, and scripts inside iframes are linked to the iframe. Treat the trail as a lead, not proof. Set `options.traceOrigins: false` to turn it off.

### Which GTM tag added it

A published GTM container (`gtm.js?id=GTM-…`) contains every tag's code and its numeric **tag ID**, but not the tag **names**. Google keeps names only in the GTM admin. The scanner keeps each container it sees and matches every script GTM adds against the container's tags:

- **Custom HTML tags:** by the script's URL, or by the injected inline code itself.
- **Built-in and template tags:** by the IDs in the script's URL, for example the conversion ID in `gtag/js?id=AW-736740096` matches the Google Ads Conversion Tracking tag with that ID.
- **Scripts loaded by a GTM-added script** inherit the tag ("via its parent").

The report shows the **tag ID** and the tag's **type** (Custom HTML, Floodlight Counter, Google Ads Conversion Tracking…), for example `tag ID 37 (type: Custom HTML)`. The type is GTM's template, not the tag's name. To find the tag, open the container in GTM, go to **Tags**, and open the tag whose URL ends in `/tags/<ID>`.

Sometimes several tags contain the same URL or ID. For example, three Floodlight Counter tags that share one advertiser ID all load the same `gtag/js?id=DC-…` script, and whichever fires first loads it. The report then lists every candidate (`tag ID 14, 20 or 25 (type: Floodlight Counter)`), up to three, rather than guessing. When no tag matches, it says "tag not identified", which usually means the tag builds the URL at runtime. Getting tag names would need the GTM API and the client's Google credentials. That isn't built in.

Security-setup checks (headers, CSP, SRI, vulnerable libraries, exposed secrets, cookies, mixed content, the DOM-XSS canary), CSS attacks and malicious code in browser storage are covered in [Security checks](security-checks.md).

### Informational notes

These never count as findings (severity `info`). They explain what happened during the scan:

| Rule | Note |
|---|---|
| `no-baseline` | No baseline for this page yet, so change detection was skipped |
| `load-error` | The page failed to load (timeout, DNS, TLS…) |
| `http-status` | The page returned an HTTP error status (4xx/5xx) |
| `blocked-submit` | The submission guard blocked a form submission (see [Custom interactions](interactions.md#behavior)) |
| `interaction-failed` | A custom interaction step failed (selector not found, timeout) |

## 6. Baseline diff

Each run is compared with `baseline.json`. New domains, new scripts and scripts whose contents changed are flagged. Changed **first-party** files are flagged on purpose, because skimmers are often appended to a theme or plugin JS file on disk.

| Severity | Rule | Fires on |
|---|---|---|
| medium | `new-domain` / `new-script` | A third-party domain or script that wasn't in the baseline |
| medium | `changed-script` | A script whose contents changed, first-party included |
| low | `new-domain` / `new-script` | A new first-party domain or script, or a new one from a domain in `allowDomains` |
| low | `new-inline-script` | An inline script that wasn't in the baseline |

## How severity is assigned

Each rule has a fixed severity, chosen by one question: **how often does legitimate code do this?**

| Severity | Meaning | Standard |
|---|---|---|
| **high** | Investigate now | Rarely legitimate. Must produce **zero** hits on the false-positive corpus (below) |
| **medium** | Review | Suspicious, but some legitimate code does it |
| **low** | Note | Often harmless, but worth knowing |
| **info** | Context, not a finding | No baseline yet, load errors, blocked form submissions, failed custom steps |

Afterwards, only two things can lower a severity:

- **`allowDomains`:** a medium or low hit on a trusted vendor's script becomes low. **High is never downgraded**, so a compromised trusted vendor still shows up.
- **`volatileScripts`:** only suppresses "changed since baseline" for scripts that change on every load. Pattern rules still run on them.

Phase tags and *loaded by* trails never change severity.

**False-positive corpus.** Before any rule ships, it's run against about 1,150 clean files: the `dist` builds of about 35 popular libraries (jQuery, React, Vue, Bootstrap, GSAP, Swiper, Chart.js, Select2, jquery-validation, Three.js, Lodash, Axios, Alpine, card-validator, Cleave.js, IMask and more) and 16 third-party SDKs (Google gtag and GTM, Facebook pixel, Google Analytics, Stripe.js, PayPal, Braintree, Razorpay, LinkedIn, Clarity, reCAPTCHA, Datadog…).

The corpus also includes libraries chosen because they look most like the newer rules' targets: ethers.js and web3 (blockchain calls), rrweb, PostHog, Sentry, Mixpanel and Amplitude (session replay and analytics that read inputs), Socket.IO and SockJS (WebSockets), localForage, store2 and Garlic.js (form autosave), and Adyen, Braintree and PayPal SDKs.

Current result on about 3,200 files: **0 high, 0 medium**, 29 low (base64 blobs and minified identifiers).

**Skimmer samples.** `test/rules/positive/` holds inert re-creations of techniques from published incident write-ups: Sansec (Stripe-as-C2 2026, SVG onload 2026, fake payment pages 2020), cside (WebSocket loader 2024), Akamai (404-page loader 2023), Malwarebytes (whitespace-in-CSS 2023), Confiant and Trinity Cyber (EtherHiding 2026), plus generic patterns. Each file names the rule it must trigger. `test/rules/negative/` holds legitimate look-alikes that must not trigger anything above low: first-party checkout code, Stripe Elements, direct payment-processor calls, form autosave, a chat widget, a web3 gallery, session replay and the real GTM snippet.

## Reading the phase tags

The phase tags (built-in or custom) record **when something first appeared**, not what caused it:

- **First appearance only.** A script or domain already seen during page load isn't tagged again when a later click or hover uses it. In particular, requests to a host the page had already contacted don't show as, say, "contacted on custom: press pay". That includes data sent to a domain that also served a script at load time.
- **Hook code outside `step()`** is credited to the hook as a whole (`custom: script hook.mjs`). Wrap actions in `step()` for precise labels.
- **Delayed reactions** that land after a step finishes are credited to the next step, or to *after interaction* for the last one. Put a `{ "wait": 1500 }` after an important click so its effects stay with it.
- **Timing isn't proof of cause.** Something tagged *on scroll* appeared while the scanner was scrolling, but it might just be a slow timer. The idle wait reduces this but can't rule it out.
- **Only loads and requests are recorded.** A script that was already loaded and only attaches a key or click listener when you interact leaves no new load or request, so nothing gets a phase tag. Its code is still checked by the pattern rules.
- **Informational only.** Phase tags never change a finding's severity, because legitimate analytics and ad tags react to scrolling and typing all the time.
