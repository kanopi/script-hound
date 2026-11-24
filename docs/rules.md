# Rules

Every finding comes from a **rule** with an id (`skimmer-field-harvest`, `new-domain`, …). What each built-in rule detects is described in [How it works](how-it-works.md#3-pattern-rules). This page covers changing them.

To see every rule and its effective setting:

```bash
node scan.mjs --list-rules                       # built-in + config.json + --disable-rule
node scan.mjs --list-rules --site "Example Client" # …plus that site's settings
make rules                                        # same as the first line
```

## Where rules are configured

| Where | What it's for |
|---|---|
| **`config.json`** (global) | Turn rules off or change their severity for every site. Add custom rules and suppressions that apply everywhere. It can also hold default `options`, `allowDomains`, `blockDomains` and `volatileScripts` |
| **`sites.json`**, per site | `rules`, `customRules` and `suppress` for one site. A site can override the global settings, including turning a globally disabled rule back on |
| **Command line** | `--disable-rule <id>` (repeatable, or `SCAN_DISABLE_RULES=id1,id2`) turns a rule off for one run |

Precedence, last wins: **built-in → `config.json` → site → `--disable-rule`**.

`config.json` is read from the current folder by default. Use `--global-config <file>` (or `SCAN_GLOBAL_CONFIG`) to point elsewhere. It's optional, and there's a starting point in `config.example.json`. In `config.json` and `sites.json` together, `options` from `sites.json` win, and the domain lists are combined.

## Turning rules off or changing severity

```json
"rules": {
  "obfuscator-io": "off",
  "new-inline-script": "info",
  "form-harvest-generic": { "severity": "low", "reason": "Session-replay vendor, reviewed 2026-11" },
  "base64-blob": "on"
}
```

| Value | Effect |
|---|---|
| `"off"` | The rule never produces findings |
| `"high"` / `"medium"` / `"low"` / `"info"` | Change its severity |
| `"on"` | Back to the built-in setting. Use it in a site's `rules` to undo a global change |
| `{ "severity": …, "reason": "…" }` | Any of the above, with a reason that's shown in the report |

This works for every rule: pattern rules, page-level checks (`hidden-iframe`, `offsite-form`…), baseline checks (`new-domain`, `changed-script`…) and your own custom rules.

Unlike `allowDomains`, which never lowers a high finding, rule settings can turn off or lower anything, including high rules, because they're an explicit choice. To keep that honest, **every change is printed in the report** under "Rule changes in effect" with its reason and where it came from. Any finding whose severity was changed shows what it was ("was medium").

## Suppressing one false positive

To silence a rule on one script or page without turning it off everywhere, use `suppress`. A `reason` is required.

```json
"suppress": [
  { "rule": "base64-blob", "script": "/wp-content/plugins/fancy-fonts/", "reason": "Embedded font data, reviewed 2026-11" },
  { "rule": "hidden-iframe", "page": "/checkout", "script": "/regex/payments\\.example\\.com/", "reason": "Payment provider's 3-D Secure frame" }
]
```

- `script` matches the finding's script URL, or its host for domain findings. `page` matches the page URL. Each is a substring, or `"/regex/flags"`. At least one is required.
- Suppressed findings are left out of the counts but listed in the report ("Suppressed by config"), with the reason and how many findings each suppression hid. A suppression that hides nothing for a while is a sign it can be removed.

This is the preferred way to handle a false positive, because the rule keeps working everywhere else.

## Custom rules

```json
"customRules": [
  { "id": "retired-cdn", "severity": "medium", "target": "url", "pattern": "cdn\\.oldvendor\\.example", "description": "Request to a CDN we retired" },
  { "id": "old-theme-file", "severity": "medium", "target": "code", "pattern": "theme-v1-legacy", "description": "Reference to the pre-2025 theme bundle" },
  { "id": "tracking-pixel", "severity": "low", "target": "html", "pattern": "<img[^>]+tracking-pixel\\.example", "flags": "i", "description": "Hard-coded tracking pixel" }
]
```

| Field | Notes |
|---|---|
| `id` | Lowercase letters, digits and dashes. Must not reuse a built-in id or another custom rule's |
| `severity` | `high`, `medium`, `low` or `info` |
| `target` | `code` (default): every script body, external, inline and [dynamically created](how-it-works.md#code-that-arrives-at-runtime), plus every stored value (storage, cookies, caches…). `css`: every stylesheet and inline `<style>`, plus cached CSS. `url`: every script URL, request host, iframe `src`, form action and WebSocket URL. `html`: the page HTML exactly as the server sent it |
| `pattern` | A JavaScript regular expression, as a string. Escape backslashes for JSON (`\\.` for a literal dot) |
| `flags` | Optional regex flags, for example `"i"` |
| `description` | Shown as the finding's message |

Custom findings have the same detail as built-in ones: line and column for `code`, page-HTML line for `html`, and the *loaded by* trail and phase. They're marked **custom** in reports. Put them in `config.json` to check every site, or under a site in `sites.json` for that site only.

Keep patterns specific and bounded (`[^>]{0,200}`, not `.*`). A slow regex runs on every script of every page.

## Checks

Configuration is validated before anything is scanned. These stop the run with exit code 2 and a message naming the problem:

- An unknown rule id in `rules`, `suppress` or `--disable-rule`
- An invalid regex
- A custom rule that reuses an existing id
- A suppression without a `reason`, or without a `script` or `page` to scope it
