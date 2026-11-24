import crypto from 'node:crypto';
import { getDomain } from 'tldts';

export const sha256 = (s) => crypto.createHash('sha256').update(s).digest('hex');

export function hostOf(url) {
  try {
    return new URL(url).hostname.toLowerCase();
  } catch {
    return null;
  }
}

// Registrable domain ("www.shop.example.co.uk" -> "example.co.uk").
export function rootDomain(host) {
  if (!host) return null;
  return getDomain(host, { allowPrivateDomains: true }) || host;
}

// Matches "example.com" against host and any subdomain of it.
export function hostMatches(host, patterns = []) {
  if (!host) return false;
  return patterns.some((p) => {
    p = p.toLowerCase().replace(/^\*\./, '');
    return host === p || host.endsWith('.' + p);
  });
}

// Stable key for an external script: origin + path, query string dropped (cache-busters).
export function scriptKey(url) {
  try {
    const u = new URL(url);
    return u.origin + u.pathname;
  } catch {
    return url;
  }
}

// Inline scripts often embed nonces, timestamps and IDs that change on every request.
// Strip those before hashing so the baseline isn't noisy.
export function normalizeInline(code) {
  return code
    .replace(/[a-f0-9]{8,}/gi, 'H')
    .replace(/[A-Za-z0-9_-]{24,}/g, 'T')
    .replace(/\d+/g, '0')
    .replace(/\s+/g, ' ')
    .trim();
}

// Phases of a page visit, in order. "load" = navigation until network idle; "idle" = a quiet wait
// before interacting; "after-interaction" = the final wait (delayed reactions to the interactions).
export const PHASES = {
  load: 'page load',
  idle: 'idle wait (timers)',
  mouse: 'mouse movement',
  scroll: 'scroll',
  'form-input': 'form input',
  'after-interaction': 'after interaction',
  inventory: 'end of visit',
};
const BUILTIN_INTERACTION_PHASES = new Set(['mouse', 'scroll', 'form-input', 'after-interaction']);
// Custom steps from sites.json run as "custom:<label>".
export const isInteractionPhase = (ph) => !!ph && (BUILTIN_INTERACTION_PHASES.has(ph) || ph.startsWith('custom:'));
export const phaseName = (ph) => (ph?.startsWith('custom:') ? `custom: ${ph.slice(7)}` : PHASES[ph] || ph || '');

export const SEVERITY_ORDER = { high: 3, medium: 2, low: 1, info: 0 };

export function escapeHtml(s) {
  return String(s ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

export async function mapLimit(items, limit, fn) {
  const results = new Array(items.length);
  let i = 0;
  const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (i < items.length) {
      const idx = i++;
      results[idx] = await fn(items[idx], idx);
    }
  });
  await Promise.all(workers);
  return results;
}

// Like mapLimit, but each task may return more jobs: fn(job) -> { result, more?: job[] }.
// Used by crawl mode, where scanning one page discovers the next ones.
export function runQueue(initial, limit, fn) {
  const queue = [...initial];
  const results = [];
  let active = 0;
  return new Promise((resolve, reject) => {
    const pump = () => {
      if (!queue.length && !active) return resolve(results);
      while (active < limit && queue.length) {
        const job = queue.shift();
        active++;
        Promise.resolve()
          .then(() => fn(job))
          .then(({ result, more = [] }) => {
            results.push(result);
            queue.push(...more);
          })
          .then(() => {
            active--;
            pump();
          }, reject);
      }
    };
    pump();
  });
}
