// Rule configuration: turning rules off, changing severities, custom patterns and suppressions.
//
// Precedence (later wins): built-in default → config.json "rules" → site "rules" → --disable-rule.
//
// A rule setting is one of:
//   "off"                                   disable
//   "on"                                    back to the built-in severity (e.g. re-enable per site)
//   "high" | "medium" | "low" | "info"      change severity
//   { "severity": <any of the above>, "reason": "why" }
import { RULES } from './heuristics.mjs';
import { CSS_RULES } from './css.mjs';

// Page-level, baseline and informational checks from lib/evaluate.mjs (pattern rules come from RULES).
export const PAGE_RULES = [
  { id: 'offsite-redirect', severity: 'high', description: 'The page redirected to another site' },
  { id: 'blocklisted-domain', severity: 'high', description: 'A request went to a domain in blockDomains' },
  { id: 'handler-runs-decoded-code', severity: 'high', description: 'An inline on* attribute runs decoded (base64) code' },
  { id: 'meta-refresh', severity: 'medium', description: 'Meta refresh to a third-party URL' },
  { id: 'hidden-iframe', severity: 'medium', description: 'Hidden third-party iframe' },
  { id: 'offsite-form', severity: 'medium', description: 'Form posts to a third-party host' },
  { id: 'websocket', severity: 'medium', description: 'WebSocket to a third-party host' },
  { id: 'obfuscated-handler', severity: 'medium', description: 'Obfuscated inline on* attribute' },
  { id: 'handler-loads-script', severity: 'low', description: 'Inline on* attribute loads a script (often a CDN fallback)' },
  { id: 'new-domain', severity: 'medium', description: 'Domain not in the baseline (low for first-party / allowDomains)' },
  { id: 'new-script', severity: 'medium', description: 'Script not in the baseline (low for first-party / allowDomains)' },
  { id: 'changed-script', severity: 'medium', description: 'Script contents changed since the baseline (low for allowDomains)' },
  { id: 'new-inline-script', severity: 'low', description: 'Inline script not in the baseline' },
  { id: 'new-cookie', severity: 'info', description: 'Cookie not in the baseline (low for third-party cookies set by JavaScript)' },
  { id: 'no-baseline', severity: 'info', description: 'No baseline for this page yet' },
  { id: 'load-error', severity: 'info', description: 'Page failed to load' },
  { id: 'http-status', severity: 'info', description: 'Page returned an HTTP error status' },
  { id: 'blocked-submit', severity: 'info', description: 'A form submission was blocked by the guard' },
  // Security posture (lib/posture.mjs, lib/vulndb.mjs)
  { id: 'card-data-in-storage', severity: 'high', description: 'The dummy card number the scanner typed turned up in browser storage or a cookie (raw or encoded): a script is stashing what visitors type' },
  { id: 'new-stylesheet', severity: 'low', description: 'Stylesheet not in the baseline (low for third-party, info for first-party)' },
  { id: 'changed-stylesheet', severity: 'info', description: 'Stylesheet contents changed since the baseline (CSS rules still run on every scan)' },
  { id: 'code-in-storage', severity: 'low', description: 'JavaScript code stored in localStorage/sessionStorage/IndexedDB (also checked after base64-decoding); a known way to persist a payload' },
  { id: 'new-storage-key', severity: 'info', description: 'localStorage/sessionStorage key not in the baseline' },
  { id: 'new-service-worker', severity: 'low', description: 'Service worker not in the baseline (service workers persist across visits)' },
  { id: 'vulnerable-library', severity: 'medium', description: 'Library version with known vulnerabilities (Retire.js database; critical/high → medium, medium → low, low → info)' },
  { id: 'mixed-content', severity: 'medium', description: 'HTTPS page requests resources over plain HTTP (medium for scripts/frames/XHR, low for images)' },
  { id: 'dom-xss-canary', severity: 'medium', description: 'Opt-in probe: text from the URL fragment was written into the page as HTML (DOM XSS sink)' },
  { id: 'csp-missing', severity: 'low', description: 'No Content-Security-Policy' },
  { id: 'csp-weak', severity: 'low', description: "CSP allows 'unsafe-inline' (without nonce/hash), 'unsafe-eval', wildcards or data: for scripts" },
  { id: 'hsts-missing', severity: 'low', description: 'No Strict-Transport-Security on an HTTPS page (info if max-age is short)' },
  { id: 'clickjacking-unprotected', severity: 'low', description: 'No X-Frame-Options or CSP frame-ancestors' },
  { id: 'sri-missing', severity: 'info', description: 'Third-party script tags without Subresource Integrity (low on payment pages)' },
  { id: 'session-cookie-insecure', severity: 'low', description: 'Session-like cookie without HttpOnly or Secure' },
  { id: 'token-in-storage', severity: 'low', description: 'Token-like value in localStorage/sessionStorage' },
  { id: 'csp-report-only', severity: 'info', description: 'CSP is report-only (blocks nothing)' },
  { id: 'nosniff-missing', severity: 'info', description: 'No X-Content-Type-Options: nosniff' },
  { id: 'referrer-policy-missing', severity: 'info', description: 'No Referrer-Policy, or one that leaks full URLs' },
  { id: 'interaction-failed', severity: 'info', description: 'A custom interaction step failed' },
];

export const BUILTIN_RULES = [
  ...RULES.map(({ id, severity, description }) => ({ id, severity, description, kind: 'code' })),
  ...CSS_RULES.map(({ id, severity, description }) => ({ id, severity, description, kind: 'css' })),
  ...PAGE_RULES.map((r) => ({ ...r, kind: 'page' })),
];

const SEVERITIES = ['high', 'medium', 'low', 'info'];
const CUSTOM_TARGETS = ['code', 'url', 'html', 'css'];

/** Normalise one setting to { severity: 'off'|'on'|<sev>, reason }. Throws on bad input. */
function normalise(id, v, where) {
  const val = typeof v === 'string' ? { severity: v } : v && typeof v === 'object' ? v : null;
  if (!val || !['off', 'on', ...SEVERITIES].includes(val.severity)) {
    throw new Error(`${where}: rule "${id}" must be "off", "on", one of ${SEVERITIES.join('/')}, or { "severity": …, "reason": … }`);
  }
  return { severity: val.severity, reason: val.reason || '' };
}

/** Compile and validate custom rules. Returns [{ id, severity, description, target, rx, test }]. */
export function compileCustomRules(list = [], where, builtinIds) {
  const out = [];
  list.forEach((r, i) => {
    const at = `${where}.customRules[${i}]`;
    if (!r || typeof r !== 'object') throw new Error(`${at}: must be an object`);
    if (!/^[a-z0-9][a-z0-9-]{1,60}$/.test(r.id || '')) throw new Error(`${at}: "id" is required (lowercase letters, digits, dashes)`);
    if (builtinIds.has(r.id)) throw new Error(`${at}: "${r.id}" is a built-in rule id; pick another`);
    if (!SEVERITIES.includes(r.severity)) throw new Error(`${at} (${r.id}): "severity" must be one of ${SEVERITIES.join('/')}`);
    const target = r.target || 'code';
    if (!CUSTOM_TARGETS.includes(target)) throw new Error(`${at} (${r.id}): "target" must be one of ${CUSTOM_TARGETS.join('/')}`);
    if (typeof r.pattern !== 'string' || !r.pattern) throw new Error(`${at} (${r.id}): "pattern" (a regular expression string) is required`);
    let rx;
    try {
      rx = new RegExp(r.pattern, (r.flags || '').replace(/g/g, ''));
    } catch (e) {
      throw new Error(`${at} (${r.id}): invalid pattern: ${e.message}`);
    }
    out.push({
      id: r.id,
      severity: r.severity,
      description: r.description || `Custom rule ${r.id}`,
      target,
      pattern: r.pattern,
      custom: true,
      // Same contract as built-in pattern rules: { match, index } or null.
      test: (text) => {
        const m = rx.exec(text);
        return m ? { match: m[0].slice(0, 160), index: m.index } : null;
      },
    });
  });
  return out;
}

/** Validate suppressions: [{ rule, script?, page?, reason }]. script/page: substring or "/regex/flags". */
export function compileSuppressions(list = [], where, knownIds) {
  return list.map((s, i) => {
    const at = `${where}.suppress[${i}]`;
    if (!s || typeof s !== 'object') throw new Error(`${at}: must be an object`);
    if (!knownIds.has(s.rule)) throw new Error(`${at}: unknown rule "${s.rule}" (run --list-rules)`);
    if (!s.reason) throw new Error(`${at}: "reason" is required, so the report can say why it was suppressed`);
    if (!s.script && !s.page) throw new Error(`${at}: give "script" and/or "page" (substring or "/regex/") to scope it; to turn a rule off everywhere use "rules"`);
    return { rule: s.rule, script: s.script, page: s.page, reason: s.reason, where, hits: 0 };
  });
}

const matches = (pattern, text) => {
  if (!pattern) return true;
  if (text == null) return false;
  const rx = /^\/(.+)\/([a-z]*)$/.exec(pattern);
  return rx ? new RegExp(rx[1], rx[2]).test(text) : String(text).includes(pattern);
};

/**
 * Build the effective rule set for one site.
 *   layers: [{ rules, where }] in precedence order (config.json, then site)
 *   disabled: rule ids from --disable-rule
 * Returns { settings: Map(id → { severity, reason, source }), changes: [...] } and throws on unknown ids.
 */
export function effectiveRules(layers, disabled, knownIds) {
  const settings = new Map();
  for (const { rules, where } of layers) {
    for (const [id, v] of Object.entries(rules || {})) {
      if (!knownIds.has(id)) throw new Error(`${where}: unknown rule "${id}" (run --list-rules to see them all)`);
      const n = normalise(id, v, where);
      if (n.severity === 'on') settings.delete(id);
      else settings.set(id, { ...n, source: where });
    }
  }
  for (const id of disabled) {
    if (!knownIds.has(id)) throw new Error(`--disable-rule: unknown rule "${id}" (run --list-rules to see them all)`);
    settings.set(id, { severity: 'off', reason: 'disabled on the command line', source: 'command line' });
  }
  return settings;
}

/**
 * Apply rule settings and suppressions to a page's issues. Returns the kept issues; suppressed ones
 * are returned separately (with the suppression's reason) so reports can still show them.
 */
export function applyRuleSettings(issues, { settings, suppress = [], pageUrl }) {
  const kept = [];
  const suppressed = [];
  for (const i of issues) {
    const id = i.rule || i.type;
    const set = settings.get(id);
    if (set?.severity === 'off') continue;
    if (set && set.severity !== i.severity) {
      i.originalSeverity = i.severity;
      i.severity = set.severity;
    }
    const sup = suppress.find((s) => s.rule === id && matches(s.page, pageUrl) && matches(s.script, i.script || i.host));
    if (sup) {
      sup.hits++;
      suppressed.push({ ...i, suppressedBy: sup.reason });
      continue;
    }
    kept.push(i);
  }
  return { kept, suppressed };
}
