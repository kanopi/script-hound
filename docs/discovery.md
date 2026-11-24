# Discovery modes

| Mode | What gets scanned |
|---|---|
| `url` (default) | Exactly the URLs in `sites.json` or `--urls` |
| `crawl` | The start URLs, then same-site links found on each scanned page, breadth-first, up to `--depth` (default 2) and `--max-pages` (default 25) |
| `sitemap` | The start URLs plus pages from the sitemap, capped at `--max-pages`. Sitemap indexes and `.gz` files are followed. When capped, pages are sampled across URL sections (`/products/`, `/blog/`…) so different page templates get covered |

```bash
node scan.mjs --urls https://shop.example.com/ --mode crawl --max-pages 50 --depth 3
node scan.mjs --sitemap https://shop.example.com/sitemap.xml --max-pages 40
node scan.mjs --sitemap ./sitemap.xml                       # local file; no sites.json needed
node scan.mjs --urls https://example.com/ --mode sitemap    # finds the sitemap via robots.txt
```

In `sites.json`, set `mode`, `maxPages`, `depth`, `sitemap`, `includeSubdomains` and `exclude` per site, or set defaults under `options`. See [Configuration](configuration.md).

## Staying on the site

Crawl and sitemap modes **never leave the site**:

- By default they stay on the start URL's host, with `www.` and the bare domain treated as the same site.
- `--include-subdomains` widens that to other subdomains of the same registrable domain (`shop.` → `blog.`).
- They skip files (PDF, images, archives), admin, login and logout paths, and add-to-cart URLs.
- Crawl mode drops query strings, so it doesn't loop through faceted-search variants.
- Add your own `exclude` regexes in `sites.json`.

Crawling only reads link `href`s. It never clicks anything or submits a form.

## Baselines

Each discovered page gets its own baseline entry. Pages first seen in a later run get a "no baseline" info note, not a finding. Sitemap sampling and crawling can pick different pages from run to run, so expect some of these notes.
