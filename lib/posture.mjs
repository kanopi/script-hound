// Passive security-posture checks (OWASP Client-Side Top 10 / PCI DSS 6.4.3): response headers, CSP,
// Subresource Integrity, mixed content, cookie flags, tokens in browser storage, and the opt-in DOM-XSS
// canary result. Nothing here sends anything to the site beyond the normal page visit.
//
// Each check returns issues as [severity, type, message, detail]. Severities are deliberately low:
// these are weak settings, not signs of compromise, and must not drown out real findings.
import { hostOf, hostMatches } from './util.mjs';

// Headers that matter here (lower-case, as Playwright returns them).
export const POSTURE_HEADERS = [
  'content-security-policy',
  'content-security-policy-report-only',
  'strict-transport-security',
  'x-content-type-options',
  'x-frame-options',
  'referrer-policy',
];

// Parse a CSP string into { directive: [sources] }. Multiple policies: first definition wins per directive.
export function parseCsp(csp) {
  const out = {};
  for (const part of String(csp || '').split(/[;,]/)) {
    const [name, ...vals] = part.trim().split(/\s+/);
    if (name && !(name.toLowerCase() in out)) out[name.toLowerCase()] = vals;
  }
  return out;
}

// What's weak about the policy for scripts. 'unsafe-inline' is ignored by browsers when a nonce,
// hash or 'strict-dynamic' is present, so it only counts without them.
export function cspScriptWeaknesses(csp) {
  const d = parseCsp(csp);
  const src = d['script-src'] || d['default-src'];
  if (!src) return null; // policy exists but doesn't cover scripts
  const lower = src.map((s) => s.toLowerCase());
  const weak = [];
  const neutralised = lower.some((s) => s.startsWith("'nonce-") || s.startsWith("'sha") || s === "'strict-dynamic'");
  if (lower.includes("'unsafe-inline'") && !neutralised) weak.push("'unsafe-inline' (inline scripts allowed)");
  if (lower.includes("'unsafe-eval'")) weak.push("'unsafe-eval' (eval allowed)");
  if (lower.some((s) => s === '*' || s === 'https:' || s === 'http:')) weak.push(`a wildcard source (${src.find((s) => ['*', 'https:', 'http:'].includes(s.toLowerCase()))})`);
  if (lower.includes('data:')) weak.push('data: URLs');
  return weak;
}

export function headerChecks({ headers = {}, metaCsp = null, url }) {
  const out = [];
  const https = /^https:/i.test(url || '');
  const csp = headers['content-security-policy'] || metaCsp;
  if (!csp) {
    if (headers['content-security-policy-report-only']) {
      out.push(['info', 'csp-report-only', 'Content-Security-Policy is report-only, so it reports violations but blocks nothing']);
    } else {
      out.push(['low', 'csp-missing', 'No Content-Security-Policy: nothing limits which scripts can run or where data can be sent']);
    }
  } else {
    const weak = cspScriptWeaknesses(csp);
    if (weak === null) out.push(['low', 'csp-weak', "Content-Security-Policy doesn't restrict scripts (no script-src or default-src)", { match: csp.slice(0, 300) }]);
    else if (weak.length) out.push(['low', 'csp-weak', `Content-Security-Policy allows ${weak.join(', ')}`, { match: csp.slice(0, 300) }]);
  }
  if (https) {
    const hsts = headers['strict-transport-security'];
    const age = Number((/max-age=(\d+)/i.exec(hsts || '') || [])[1] || 0);
    if (!hsts) out.push(['low', 'hsts-missing', 'No Strict-Transport-Security header: browsers may still try plain HTTP first']);
    else if (age < 15552000) out.push(['info', 'hsts-missing', `Strict-Transport-Security max-age is short (${age}s; 180 days or more is recommended)`, { match: hsts }]);
  }
  if ((headers['x-content-type-options'] || '').toLowerCase() !== 'nosniff') {
    out.push(['info', 'nosniff-missing', 'No X-Content-Type-Options: nosniff header']);
  }
  const frameAncestors = parseCsp(csp)['frame-ancestors'];
  if (!headers['x-frame-options'] && !frameAncestors) {
    out.push(['low', 'clickjacking-unprotected', 'Page can be framed by any site (no X-Frame-Options or CSP frame-ancestors), so clickjacking is possible']);
  }
  const rp = (headers['referrer-policy'] || '').toLowerCase();
  if (!rp) out.push(['info', 'referrer-policy-missing', 'No Referrer-Policy header (browsers default to strict-origin-when-cross-origin)']);
  else if (/unsafe-url|no-referrer-when-downgrade/.test(rp)) out.push(['info', 'referrer-policy-missing', `Referrer-Policy "${rp}" sends full URLs to other sites`]);
  return out;
}

// Third-party <script src> tags without integrity=. Volatile scripts (GTM etc.) can't use SRI, so
// they're left out. Info normally; low on payment pages (PCI DSS 6.4.3 expects script integrity there).
export function sriCheck({ scriptTags = [], isFirst, paymentPage, volatile = [] }) {
  const missing = scriptTags.filter((t) => {
    const h = hostOf(t.src);
    return h && !isFirst(h) && !t.integrity && !volatile.some((v) => t.src.includes(v) || hostMatches(h, [v]));
  });
  if (!missing.length) return [];
  const hosts = [...new Set(missing.map((t) => hostOf(t.src)))];
  return [[
    paymentPage ? 'low' : 'info',
    'sri-missing',
    `${missing.length} third-party script tag(s) without Subresource Integrity${paymentPage ? ' on a payment page' : ''}: ${hosts.slice(0, 6).join(', ')}${hosts.length > 6 ? '…' : ''}`,
    { match: missing.slice(0, 10).map((t) => t.src).join('\n') },
  ]];
}

// Mixed content on HTTPS pages. Active content (scripts, styles, frames, XHR/fetch, WebSockets) is
// blocked by browsers today, but its presence means something is referencing plain-HTTP resources.
const ACTIVE = new Set(['script', 'stylesheet', 'document', 'xhr', 'fetch', 'websocket', 'eventsource']);
export function mixedContentCheck({ mixed = [] }) {
  if (!mixed.length) return [];
  const active = mixed.filter((m) => ACTIVE.has(m.type));
  const passive = mixed.filter((m) => !ACTIVE.has(m.type));
  const out = [];
  if (active.length) out.push(['medium', 'mixed-content', `HTTPS page requests ${active.length} active resource(s) over plain HTTP (${[...new Set(active.map((m) => m.type))].join(', ')})`, { match: active.slice(0, 10).map((m) => m.url).join('\n'), host: hostOf(active[0].url) }]);
  if (passive.length) out.push(['low', 'mixed-content', `HTTPS page requests ${passive.length} image/media resource(s) over plain HTTP`, { match: passive.slice(0, 10).map((m) => m.url).join('\n') }]);
  return out;
}

// Cookies that look like session/auth cookies but can be read by JavaScript (no HttpOnly), or go
// over plain HTTP (no Secure). A skimmer or XSS that can read them can hijack the session.
// Real session/auth cookie names from common platforms (PHP, Java, .NET, Node, Laravel, CodeIgniter,
// Rails "_<app>_session", Magento "frontend", WordPress/WooCommerce, Drupal SESS/SSESS<hash>), plus a
// few generic auth names. Analytics "session" cookies (_hjSession, __attentive_session_id…) don't count.
const SESSIONISH =
  /^(phpsessid|jsessionid|asp\.net_sessionid|aspsessionid\w*|connect\.sid|laravel_session|ci_session|_[a-z0-9]+_session|session|sessionid|session_id|sid|frontend|wordpress_logged_in_\w+|wordpress_sec_\w+|wp_woocommerce_session_\w+|s?sess[0-9a-f]{20,}|auth|auth_token|access_token|id_token|jwt|token)$/i;
export function cookieCheck({ cookies = [], url }) {
  const https = /^https:/i.test(url || '');
  const bad = [];
  for (const c of cookies) {
    if (c.thirdParty || !SESSIONISH.test(c.name)) continue;
    const missing = [];
    if (!c.httpOnly) missing.push('HttpOnly');
    if (https && !c.secure) missing.push('Secure');
    if (c.sameSite === 'None' && !c.secure) missing.push('Secure (required with SameSite=None)');
    if (missing.length) bad.push(`${c.name} (missing ${missing.join(', ')})`);
  }
  return bad.length ? [['low', 'session-cookie-insecure', `Session-like cookie(s) readable by scripts or sent without Secure: ${bad.slice(0, 6).join('; ')}`]] : [];
}

// JWT-shaped values in localStorage/sessionStorage. Any script on the page (including a skimmer) can
// read them. Values are never put in the report.
export function storageCheck({ storageTokens = [] }) {
  if (!storageTokens.length) return [];
  return [['low', 'token-in-storage', `Token-like value(s) in browser storage, readable by any script on the page: ${storageTokens.map((t) => `${t.store}.${t.key}`).slice(0, 6).join(', ')}`]];
}

export function canaryCheck({ canary }) {
  if (!canary?.reflected) return [];
  return [['medium', 'dom-xss-canary', `Text from the URL fragment (#…) was inserted into the page as HTML: a DOM-based XSS sink. Check scripts that read location.hash`, { match: canary.where || '' }]];
}
