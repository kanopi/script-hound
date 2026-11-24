<!--
  Docker Hub overview for kanopi/script-hound.
  Paste everything below the line into Docker Hub → kanopi/script-hound → Overview (edit).
  Short description field (max 100 characters):
    ScriptHound sniffs out malicious front-end code: skimmers, injected scripts, XSS sinks, weak CSP
  Images and links use absolute GitHub URLs, so they only render once github.com/kanopi/script-hound
  is public and has the brand/ folder on main.
-->
---

<p align="center"><img src="https://raw.githubusercontent.com/kanopi/script-hound/main/brand/scripthound-logo.svg" alt="ScriptHound: sniffs out malicious front-end code" height="96"></p>

# ScriptHound

**ScriptHound sniffs out malicious front-end code.** It loads your pages in a real headless Chrome like a visitor would, interacts with them, and reports what's running in the browser that's malicious, unsafe or unexpectedly changed:

- **Compromise:** skimmers, injected and obfuscated scripts, malicious loaders, cryptominers, cloaked redirects, CSS keyloggers, payloads stashed in browser storage.
- **Weaknesses:** DOM-XSS sinks, vulnerable libraries, missing or weak CSP (with a suggested policy), missing security headers and SRI, exposed secrets, insecure cookies.
- **Change:** every script, stylesheet, domain, cookie and storage key, where it came from (down to the GTM tag), and what changed since the last scan.

It's passive: it never sends attack payloads or submits forms.

## Quick start

```bash
docker run --rm -t --ipc=host -v "$PWD":/data kanopi/script-hound --urls https://example.com/ --format console
```

Your current folder is mounted at `/data`: `sites.json`, `baseline.json` and `config.json` are read from it, and reports are written to `./reports/` (`report.html`, `report.md`, `report.json`).

```bash
# A whole site
docker run --rm --ipc=host -v "$PWD":/data kanopi/script-hound --urls https://shop.example.com/ --mode crawl --max-pages 50

# Your sites from sites.json, compared with a baseline, failing on high findings
docker run --rm --ipc=host -v "$PWD":/data kanopi/script-hound --fail-on high

# Every option
docker run --rm kanopi/script-hound --help
```

## Tags

| Tag | |
|---|---|
| `latest` | The most recent release |
| `1.0.0`, … | A specific version (recommended for CI) |

Every tag is built for `linux/amd64` and `linux/arm64`.

## Good to know

- **Add `-t`** for colored console output, and **`--ipc=host`** so Chromium has enough shared memory.
- **The container runs as non-root `pwuser`.** On Linux hosts, add `--user "$(id -u):$(id -g)"` so it can write to your folder.
- **Pass secrets as environment variables,** not on the command line: `-e SCAN_COOKIES="session=…"`, `-e SCAN_HEADERS="Authorization: …"`.
- **`jq` is included,** for turning `report.json` into spreadsheets: `docker run --rm -v "$PWD":/data --entrypoint jq kanopi/script-hound …`.

## Documentation

Full docs, configuration and source: **[github.com/kanopi/script-hound](https://github.com/kanopi/script-hound)**

- [Configuration and every option](https://github.com/kanopi/script-hound/blob/main/docs/configuration.md)
- [Security checks](https://github.com/kanopi/script-hound/blob/main/docs/security-checks.md)
- [Reports](https://github.com/kanopi/script-hound/blob/main/docs/reports.md) and [jq recipes](https://github.com/kanopi/script-hound/blob/main/docs/jq-recipes.md)
- [Docker details](https://github.com/kanopi/script-hound/blob/main/docs/docker.md)

## License

Apache License 2.0. Copyright 2026 Kanopi Studios. "ScriptHound" and its logo are trademarks of Kanopi Studios.
