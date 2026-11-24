// Page discovery for crawl and sitemap modes. Never leaves the site's own host(s).
import fs from 'node:fs';
import zlib from 'node:zlib';
import { rootDomain } from './util.mjs';

// Links worth skipping: files, admin/login/logout and cart-mutating URLs.
const SKIP_EXT = /\.(pdf|jpe?g|png|gif|webp|avif|svg|ico|zip|gz|rar|7z|mp4|mov|webm|mp3|wav|docx?|xlsx?|pptx?|csv|xml|json|txt|md|ics|rss|atom|woff2?|ttf|eot|css|js)$/i;
const SKIP_PATH = /(\/wp-admin|\/wp-login|log-?out|sign-?out|\/user\/logout|\/admin(\/|$)|add-to-cart|\/cart\/add|\/cart\/clear|\/feed\/?$)/i;

const bareHost = (h) => (h || '').toLowerCase().replace(/^www\./, '');

/**
 * Scope test for one site. Strict (default): same host as a start URL, treating www and the
 * bare domain as one. includeSubdomains: any host under the same registrable domain.
 */
export function makeScope(startUrls, { includeSubdomains = false, exclude = [] } = {}) {
  const hosts = new Set(startUrls.map((u) => bareHost(new URL(u).hostname)));
  const roots = new Set(startUrls.map((u) => rootDomain(new URL(u).hostname)));
  const excludeRx = exclude.map((x) => new RegExp(x, 'i'));
  return (url) => {
    let u;
    try {
      u = new URL(url);
    } catch {
      return false;
    }
    if (!/^https?:$/.test(u.protocol)) return false;
    const inHost = includeSubdomains ? roots.has(rootDomain(u.hostname)) : hosts.has(bareHost(u.hostname));
    if (!inHost) return false;
    if (SKIP_EXT.test(u.pathname) || SKIP_PATH.test(u.pathname + u.search)) return false;
    return !excludeRx.some((rx) => rx.test(url));
  };
}

/** Canonical form for de-duplication. Crawl drops the query string to avoid facet/sort explosions. */
export function normalizeUrl(url, { keepQuery = false } = {}) {
  try {
    const u = new URL(url);
    u.hash = '';
    if (!keepQuery) u.search = '';
    return u.href;
  } catch {
    return null;
  }
}

/**
 * Pick up to n URLs, round-robin across first path segments, so a capped sample covers
 * many templates (products, collections, blog, pages…) instead of the first n of one kind.
 */
export function spreadPick(urls, n) {
  if (!n || urls.length <= n) return urls;
  const groups = new Map();
  for (const u of urls) {
    const seg = new URL(u).pathname.split('/').filter(Boolean)[0] || '';
    if (!groups.has(seg)) groups.set(seg, []);
    groups.get(seg).push(u);
  }
  const lists = [...groups.values()];
  const out = [];
  for (let i = 0; out.length < n; i++) {
    let added = false;
    for (const l of lists) {
      if (i < l.length && out.length < n) {
        out.push(l[i]);
        added = true;
      }
    }
    if (!added) break;
  }
  return out;
}

const decodeXml = (s) => s.replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&apos;/g, "'");

async function readSource(api, src) {
  let buf;
  if (/^https?:/i.test(src)) {
    const res = await api.get(src, { timeout: 30000 });
    if (!res.ok()) throw new Error(`HTTP ${res.status()} for ${src}`);
    buf = await res.body();
  } else {
    buf = fs.readFileSync(src);
  }
  if (buf[0] === 0x1f && buf[1] === 0x8b) buf = zlib.gunzipSync(buf);
  return buf.toString('utf8');
}

/**
 * Read a sitemap (URL or local file), following sitemap indexes. Returns page URLs in order.
 * `api` is a Playwright APIRequestContext (same UA/proxy/TLS settings as the scanner).
 */
export async function readSitemap(api, src, { maxSitemaps = 50, log = () => {} } = {}) {
  const pages = [];
  const queue = [src];
  const seen = new Set();
  while (queue.length && seen.size < maxSitemaps) {
    const s = queue.shift();
    if (seen.has(s)) continue;
    seen.add(s);
    let xml;
    try {
      xml = await readSource(api, s);
    } catch (e) {
      log(`  sitemap: could not read ${s}: ${e.message}`);
      continue;
    }
    const locs = [...xml.matchAll(/<loc>\s*([^<]{1,2048}?)\s*<\/loc>/gi)].map((m) => decodeXml(m[1]));
    if (/<sitemapindex[\s>]/i.test(xml)) queue.push(...locs);
    else pages.push(...locs);
  }
  return [...new Set(pages)];
}

/** Sitemap locations for a site: robots.txt "Sitemap:" lines, else /sitemap.xml. */
export async function findSitemaps(api, siteUrl) {
  const origin = new URL(siteUrl).origin;
  try {
    const res = await api.get(origin + '/robots.txt', { timeout: 15000 });
    if (res.ok()) {
      const found = [...(await res.text()).matchAll(/^\s*sitemap:\s*(\S+)/gim)].map((m) => m[1]);
      if (found.length) return found;
    }
  } catch {
    // fall through
  }
  return [origin + '/sitemap.xml'];
}
