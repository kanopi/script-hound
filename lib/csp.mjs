// Suggested Content-Security-Policy, built from what a site's pages actually loaded during the scan.
//
// It's a starting point, not a finished policy: one anonymous visit doesn't see every page, login
// state or checkout step. Deploy it as Content-Security-Policy-Report-Only first, collect violation
// reports, adjust, then enforce.
import { rootDomain } from './util.mjs';
import { parseCsp } from './posture.mjs';

// Playwright resource type → CSP directive.
const TYPE_DIRECTIVE = {
  script: 'script-src',
  stylesheet: 'style-src',
  image: 'img-src',
  font: 'font-src',
  media: 'media-src',
  xhr: 'connect-src',
  fetch: 'connect-src',
  eventsource: 'connect-src',
  websocket: 'connect-src',
  ping: 'connect-src',
  other: 'connect-src',
  manifest: 'manifest-src',
  texttrack: 'media-src',
};
const ORDER = ['default-src', 'script-src', 'style-src', 'img-src', 'font-src', 'connect-src', 'media-src', 'frame-src', 'worker-src', 'manifest-src', 'form-action', 'frame-ancestors', 'base-uri', 'object-src'];
const MAX_HASHES = 15;
const WILDCARD_AT = 4; // collapse 4+ hosts under one registrable domain to https://*.domain

// Inline scripts whose text carries long numbers/hex (timestamps, nonces, IDs) probably change per
// request, so a hash would stop matching on the next page load.
const looksDynamic = (code) => /\b\d{6,}\b|[0-9a-f]{12,}|[A-Za-z0-9_-]{32,}/i.test(code || '');

/**
 * pages: the site's pages from the report (any profiles). Returns { header, directives, notes } or null.
 *   header: 'Content-Security-Policy-Report-Only: …' (one line, ready to paste)
 *   directives: [[name, [sources]]], notes: [string]
 */
export function suggestCsp(pages) {
  const ok = pages.filter((p) => !p.error && p.finalUrl);
  if (!ok.length) return null;
  const selfOrigins = new Set(ok.map((p) => new URL(p.finalUrl || p.url).origin));
  const https = ok.every((p) => /^https:/.test(p.finalUrl || p.url));
  const d = new Map(ORDER.map((k) => [k, new Set()]));
  const add = (dir, src) => d.get(dir).add(src);
  add('default-src', "'self'");
  for (const dir of ['script-src', 'style-src', 'img-src', 'font-src', 'connect-src', 'media-src', 'frame-src', 'worker-src', 'manifest-src', 'form-action']) add(dir, "'self'");
  add('frame-ancestors', "'self'");
  add('base-uri', "'self'");
  add('object-src', "'none'");
  // Data/blob URLs commonly used for images and fonts; harmless there.
  add('img-src', 'data:');
  add('font-src', 'data:');

  const notes = [];
  for (const p of ok) {
    // Hosts by request type (the top-level document itself is covered by 'self').
    for (const dom of p.domains || []) {
      for (const [type, origins] of Object.entries(dom.sources || {})) {
        for (const o of origins) {
          if (type === 'document') {
            if (!selfOrigins.has(o)) add('frame-src', o);
            continue;
          }
          const dir = TYPE_DIRECTIVE[type];
          if (!dir || selfOrigins.has(o)) continue;
          add(dir, type === 'websocket' ? o.replace(/^http/, 'ws') : o);
        }
      }
    }
    for (const w of p.websockets || []) {
      try {
        const o = new URL(w.url).origin;
        if (!selfOrigins.has(o.replace(/^ws/, 'http'))) add('connect-src', o.startsWith('ws') ? o : w.url.split('/').slice(0, 3).join('/'));
      } catch {
        // ignore
      }
    }
    for (const w of p.workers || []) {
      if (/^blob:/.test(w.url)) add('worker-src', 'blob:');
      else
        try {
          const o = new URL(w.url).origin;
          if (!selfOrigins.has(o)) add('worker-src', o);
        } catch {
          // ignore
        }
    }
    for (const f of p.forms || []) {
      try {
        const o = new URL(f.action).origin;
        if (!selfOrigins.has(o)) add('form-action', o);
      } catch {
        // relative or empty action: 'self'
      }
    }
  }

  // Inline scripts in the server HTML: hashes (CSP needs base64 of the SHA-256 of the exact text).
  const inline = new Map();
  for (const p of ok) for (const s of p.scripts || []) if (s.inline && !s.dynamic && s.origin?.delivered === 'html' && s.sha256) inline.set(s.sha256, s);
  const dynamicLooking = [...inline.values()].filter((s) => looksDynamic(s.preview));
  if (inline.size && inline.size <= MAX_HASHES && !dynamicLooking.length) {
    for (const h of inline.keys()) add('script-src', `'sha256-${Buffer.from(h, 'hex').toString('base64')}'`);
    notes.push(`${inline.size} inline script(s) in the HTML are allowed by hash. If you edit one, its hash changes and the policy must be updated.`);
  } else if (inline.size) {
    add('script-src', "'nonce-{SERVER-GENERATED}'");
    notes.push(
      `${inline.size} inline script(s) in the HTML${dynamicLooking.length ? `, ${dynamicLooking.length} of which look different on every request (IDs, timestamps)` : ''}: hashes won't hold up, so use a nonce. Generate a random value per response, put it in the header and add nonce="…" to each inline <script>.`
    );
  }
  const injected = ok.flatMap((p) => p.scripts || []).filter((s) => s.inline && s.origin?.delivered === 'injected').length;
  if (injected) notes.push(`${injected} inline script(s) were added at runtime (often by a tag manager). They need the same nonce passed along (GTM supports this), or 'unsafe-inline', which largely defeats the policy.`);
  const evals = ok.reduce((n, p) => n + (p.evalCount || 0), 0);
  if (evals) {
    add('script-src', "'unsafe-eval'");
    notes.push(`Code ran via eval/new Function ${evals} time(s) (often tag-manager custom templates or older libraries), so 'unsafe-eval' is included. Find and remove that use if you can, then drop 'unsafe-eval'.`);
  }
  if (ok.some((p) => (p.stylesheets || []).some((s) => s.inline))) {
    add('style-src', "'unsafe-inline'");
    notes.push("Inline <style> blocks are used, so style-src includes 'unsafe-inline' (low risk compared with scripts; switch to hashes or a nonce for a stricter policy).");
  }
  if (https) d.set('upgrade-insecure-requests', new Set());

  // Never loosen what the site already has: keep its frame-ancestors (e.g. 'none' is stricter than our
  // 'self'), its reporting endpoints, and any directive we don't generate (block-all-mixed-content,
  // require-trusted-types-for, sandbox…).
  const current = ok.map((p) => p.docHeaders?.['content-security-policy'] || p.docHeaders?.['content-security-policy-report-only'] || p.metaCsp).find(Boolean);
  if (current) {
    const cur = parseCsp(current);
    const kept = [];
    for (const [name, vals] of Object.entries(cur)) {
      if (name === 'frame-ancestors' || !d.has(name)) {
        d.set(name, new Set(vals));
        kept.push(name);
      }
    }
    if (kept.length) notes.unshift(`Kept from the site's current policy: ${kept.join(', ')}.`);
  }

  // Collapse many subdomains of one registrable domain into a wildcard, to keep the header readable.
  for (const [dir, set] of d) {
    const byRoot = new Map();
    for (const src of set) {
      const m = /^https:\/\/([^/:]+)$/.exec(src);
      if (!m) continue;
      const root = rootDomain(m[1]);
      if (!byRoot.has(root)) byRoot.set(root, []);
      byRoot.get(root).push(src);
    }
    for (const [root, list] of byRoot) {
      if (list.length < WILDCARD_AT) continue;
      for (const src of list) set.delete(src);
      set.add(`https://*.${root}`);
      if (list.includes(`https://${root}`)) set.add(`https://${root}`);
    }
  }

  // Drop directives that add nothing beyond default-src 'self'.
  const directives = [];
  for (const [name, set] of d) {
    const sources = [...set].sort((a, b) => Number(b.startsWith("'")) - Number(a.startsWith("'")) || a.localeCompare(b));
    if (name !== 'default-src' && sources.length === 1 && sources[0] === "'self'" && !['frame-ancestors', 'base-uri', 'form-action'].includes(name)) continue;
    directives.push([name, sources]);
  }
  notes.push('Built from the pages scanned in this run. Pages, logins and checkout steps that weren\'t visited may load more, so start with Report-Only (add report-to/report-uri to collect violations) and enforce once reports are quiet.');
  const policy = directives.map(([n, s]) => (s.length ? `${n} ${s.join(' ')}` : n)).join('; ');
  return { header: `Content-Security-Policy-Report-Only: ${policy}`, policy, directives, notes, pages: ok.length };
}
