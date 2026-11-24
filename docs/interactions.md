# Custom interactions

The [built-in interactions](how-it-works.md#2-interaction) (mouse, scroll, typing into visible fields) don't open things like a "Pay by card" panel, a cart drawer or a multi-step donation form. Some skimmers only attach after one of those opens. You can script those interactions.

Custom interactions run after the built-in form input, on every URL that matches `match`. `match` can be a substring, `"/regex/flags"` or a list; leave it out to match all URLs. There are three ways to supply them:

- [Steps in `sites.json`](#steps-in-sitesjson), with no code
- [Script hooks](#script-hooks), using full Playwright
- [On the command line](#from-the-command-line)

## Steps in sites.json

```json
"interactions": [
  {
    "match": "/donate",
    "steps": [
      { "click": "text=Give by card", "label": "open card form" },
      { "type": "input[name=cardnumber]", "value": "4111111111111111", "frame": "iframe[title*=card i]" },
      { "wait": 1500 }
    ]
  }
]
```

Put `interactions` on a site, or under `options` to apply to every site that doesn't define its own.

| Action | Example | Notes |
|---|---|---|
| `click` | `{ "click": "#show-card" }` | |
| `fill` | `{ "fill": "#email", "value": "scripthound@example.invalid" }` | Sets the value in one go |
| `type` | `{ "type": "#cc", "value": "4111…", "delay": 20 }` | Key by key, so keyloggers fire |
| `hover` | `{ "hover": ".mini-cart" }` | |
| `press` | `{ "press": "Tab" }` or `{ "press": "Enter", "selector": "#q" }` | |
| `select` | `{ "select": "#country", "value": "US" }` | |
| `check` | `{ "check": "#terms" }` | |
| `scrollTo` | `{ "scrollTo": "#payment" }` | |
| `waitFor` | `{ "waitFor": ".card-iframe", "state": "visible" }` | |
| `wait` | `{ "wait": 2000 }` | Milliseconds |

Selectors are [Playwright selectors](https://playwright.dev/docs/locators): CSS, `text=…`, `role=button[name="Pay"]` and so on. The first match is used.

Optional on any step:
- `"frame"`: a selector for an iframe to act inside, for hosted card fields.
- `"label"`: the name shown in reports.
- `"timeout"`: in milliseconds (default 5000).

## Script hooks

For anything the steps can't express, point `script` at a JavaScript module. The path is relative to `sites.json`. See `interactions/example.mjs`.

```json
"interactions": [{ "match": "/checkout", "script": "interactions/example.mjs" }]
```

```js
export default async function ({ page, url, profile, step, log }) {
  await step('open payment section', () => page.getByRole('button', { name: /card/i }).click());
}
```

- `page` is the [Playwright page](https://playwright.dev/docs/api/class-page).
- Wrap each action in `step(label, fn)` so that whatever loads during it is tagged with that label.
- `log(message)` adds a note to the page's step log.
- Actions default to a 5-second timeout.

## From the command line

`--interactions` (repeatable; the environment equivalent is `SCAN_INTERACTIONS`) supplies interactions for a single run. They replace any in `sites.json` for that run. The value is read as:

| Value | Read as |
|---|---|
| Starts with `[` or `{` | Inline JSON: a list of steps, one block (`{"match": …, "steps": […]}`) or a list of blocks |
| Ends in `.json` | A JSON file in the same formats. `"script"` paths inside it are relative to the file |
| Ends in `.js` / `.mjs` | A script hook file |
| Anything else | Inline JavaScript, run as the body of a hook, with `page`, `step`, `log`, `url` and `profile` available |

```bash
node scan.mjs --urls https://shop.example.com/checkout \
  --interactions '[{"click":"text=Pay by card","label":"open card form"},{"wait":1500}]'

node scan.mjs --urls https://shop.example.com/checkout --interactions ./checkout-steps.json
node scan.mjs --urls https://shop.example.com/checkout --interactions ./interactions/example.mjs

node scan.mjs --urls https://shop.example.com/checkout \
  --interactions "await step('open card form', () => page.getByRole('button', { name: /card/i }).click())"
```

- A value ending in `.json`, `.js` or `.mjs` that doesn't exist stops the scan with "file not found" (exit 2) instead of being run as code.
- In Docker, file paths are relative to the mounted `/data` folder.
- Inline JavaScript runs with the scanner's full permissions, so only pass code you wrote. For CI, commit interactions in `sites.json` or as files in the repo, where they go through code review. Don't expose them as a pipeline parameter.

## Behavior

- **Each step is its own phase.** External scripts, inline scripts and domains that *first* appear during a step are tagged `custom: <label>`. The tag shows in the console tree (`ON CUSTOM: OPEN CARD FORM`), on findings ("first seen"), in the HTML report's *When* column, and in `report.json` (`phase`). See [Reading the phase tags](how-it-works.md#reading-the-phase-tags) for what this can and can't tell you.
- **Failures don't stop the scan.** A failed step (selector not found, timeout) is logged as an info note and the scan carries on. Each page's step log, with ✓ or ✗, is shown in the console and in the HTML report.
- **Forms are never submitted.** A guard answers any form-style navigation (a POST, for example) with `204 No Content`, so the browser stays on the page. Each attempt is recorded as "blocked form submission". A step can click "Pay" to trigger submit-time listeners without anything being sent.
- **Links still navigate.** If a step clicks a link, the browser leaves the page and the step log shows "navigated to …". Everything after that is inventoried from the new page.
- **Built-in interactions run first.** Set `"exerciseForms": false` if you want only your own steps to touch form fields.
