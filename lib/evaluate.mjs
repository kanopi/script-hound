import { hostOf, rootDomain, hostMatches, SEVERITY_ORDER } from './util.mjs';
import { applyRuleSettings } from './rules.mjs';
import { headerChecks, sriCheck, mixedContentCheck, cookieCheck, storageCheck, canaryCheck } from './posture.mjs';

// Retire.js severities → ours. A vulnerable library is a weakness, not a compromise.
const LIB_SEVERITY = { critical: 'medium', high: 'medium', medium: 'low', low: 'info' };

// Authenticated scans get their own baseline entries: a logged-in page loads different things.
// Shared-session pages too: cookies carried from earlier pages change what loads.
export const pageId = (p) => `${p.url}|${p.profile}${p.authenticated ? '|auth' : ''}${p.sharedSession ? '|site-session' : ''}`;

// Storage keys and service workers, with ID-like parts collapsed like cookie names.
const storageKey = (s) => `${s.origin}|${s.type}|${s.key.replace(/[0-9a-f]{6,}|\d+/gi, '*')}`;
const swKey = (w) => (w.scriptURL || w.scope).split('?')[0];

// Cookies you supplied aren't part of what the site did, so they're left out of baselines.
const PRESET = new Set(['you (auth)', 'cookie jar']);

// Cookie names often carry IDs (_ga_ABC123, _hjSession_4567); collapse those so the baseline is stable.
const cookieKey = (c) => `${c.domain.replace(/^\./, '')}|${c.name.replace(/[0-9a-f]{6,}|\d+/gi, '*')}`;

// What we keep between runs, per page + browser profile.
export function baselineEntry(page) {
  const scripts = {};
  // Dynamic code (eval output, self-removing scripts) is only pattern-checked, never baselined.
  for (const s of page.scripts) if (s.sha256 && !s.dynamic) scripts[s.key] = s.inline ? 'inline' : s.sha256;
  return {
    domains: page.domains.map((d) => d.host).sort(),
    scripts,
    storage: [...new Set((page.storage || []).map(storageKey))].sort(),
    stylesheets: Object.fromEntries((page.stylesheets || []).filter((st) => !st.inline && st.sha256).map((st) => [st.key, st.sha256])),
    serviceWorkers: [...new Set((page.serviceWorkers || []).map(swKey))].sort(),
    cookies: [...new Set((page.cookies || []).filter((c) => !PRESET.has(c.setBy)).map(cookieKey))].sort(),
  };
}

/**
 * Turn a raw page inventory into a list of issues, comparing against the baseline if there is one.
 */
/**
 * rules (optional): { settings, suppress, urlRules } from lib/rules.mjs for this site. Settings and
 * suppressions are applied last, after allowDomains, so an explicit config choice always wins.
 */
export function evaluatePage(page, { baseline, config, firstParty, rules = null }) {
  const issues = [];
  const add = (severity, type, message, detail = {}) => issues.push({ severity, type, message, ...detail });
  const allow = config.allowDomains || [];
  const block = config.blockDomains || [];
  const volatile = config.volatileScripts || [];
  const isVolatile = (s) => volatile.some((v) => s.url.includes(v) || hostMatches(s.host, [v]));
  // Best-effort provenance (what loaded it / where to look), attached to findings when known.
  // ...and the visit phase it first appeared in (page load, scroll, form input…).
  const domainBy = Object.fromEntries(page.domains.map((d) => [d.host, d]));
  const hostOrigin = (host) => ({ ...(domainBy[host]?.origin ? { origin: domainBy[host].origin } : {}), ...(domainBy[host]?.phase ? { phase: domainBy[host].phase } : {}) });
  const scriptOrigin = (s) => ({ ...(s.origin ? { origin: s.origin } : {}), ...(s.phase ? { phase: s.phase } : {}) });

  if (page.error) add('info', 'load-error', `Page failed to load: ${page.error}`);
  if (page.status && page.status >= 400) add('info', 'http-status', `Page returned HTTP ${page.status}`);
  for (const b of page.blockedSubmissions || []) add('info', 'blocked-submit', `Blocked a form submission (${b.method} ${b.url}); the scanner never submits forms`, { phase: b.phase });
  for (const it of page.interactions || []) if (it.ok === false) add('info', 'interaction-failed', `Custom interaction step failed: ${it.label} — ${it.error}`);

  // Off-site redirect of the main document
  const startHost = hostOf(page.url);
  const endHost = hostOf(page.finalUrl);
  if (endHost && startHost && rootDomain(endHost) !== rootDomain(startHost) && !hostMatches(endHost, firstParty)) {
    add('high', 'offsite-redirect', `Page redirected off-site to ${page.finalUrl}`);
  }
  if (page.metaRefresh && /url=/i.test(page.metaRefresh)) {
    const target = page.metaRefresh.split(/url=/i)[1]?.replace(/['"]/g, '').trim();
    const th = hostOf(target);
    if (th && !hostMatches(th, firstParty)) add('medium', 'meta-refresh', `Meta refresh to third-party URL ${target}`);
  }

  // Known-bad domains
  for (const d of page.domains) {
    if (hostMatches(d.host, block)) add('high', 'blocklisted-domain', `Request to blocklisted domain ${d.host}`, { host: d.host, ...hostOrigin(d.host) });
  }

  // Heuristic hits in script bodies
  for (const s of page.scripts) {
    for (const f of s.flags || []) {
      let sev = f.severity;
      // Downgrade low-confidence hits on scripts from domains you've marked as trusted
      if (!s.inline && hostMatches(s.host, allow) && sev !== 'high') sev = 'low';
      add(sev, 'suspicious-code', `${f.description}`, {
        rule: f.rule,
        ...(f.custom ? { custom: true } : {}),
        script: s.dynamic ? `${s.removed ? 'inline script removed after running' : 'dynamically created code'} ${s.key}` : s.inline ? `inline ${s.key}` : s.url,
        match: f.match,
        // Where in the script: line/column (1-based) and the surrounding code. For server-sent inline
        // scripts, htmlLine is the same spot as a line number in the page's HTML source.
        ...(f.line ? { line: f.line, column: f.column, context: f.context } : {}),
        ...(f.line && s.htmlLine ? { htmlLine: s.htmlLine + f.line - 1 } : {}),
        ...scriptOrigin(s),
      });
    }
  }

  // Inline event handlers with obfuscation
  for (const h of page.inlineHandlers || []) {
    // Real obfuscation in an on* attribute is medium. A handler that only creates a <script> is often a
    // CDN fallback (onerror → load backup copy), but also a known injection trick, so it's low + the URL.
    // Executing decoded code from an attribute (Sansec 2026 <svg onload="setTimeout(atob(…))">, Akamai 2023
    // <img src onerror="…atob…">) is high: legitimate markup has no reason to hide code in a handler.
    if (/(?:eval|setTimeout|setInterval|Function)\s*\(\s*(?:window\.)?atob\s*\(|(?:eval|Function)\s*\([\s\S]{0,80}atob\s*\(/i.test(h.value)) {
      add('high', 'handler-runs-decoded-code', `Inline ${h.attr} on <${h.tag}> runs decoded (base64) code`, { match: h.value });
    } else if (/(atob|eval|fromCharCode|\\x[0-9a-f]{2})/i.test(h.value)) {
      add('medium', 'obfuscated-handler', `Obfuscated inline ${h.attr} on <${h.tag}>`, { match: h.value });
    } else {
      const src = (h.value.match(/['"`]((?:https?:)?\/\/[^'"`\s]+)['"`]/) || [])[1];
      add('low', 'handler-loads-script', `Inline ${h.attr} on <${h.tag}> loads a script${src ? ` from ${src}` : ''} (often a CDN fallback)`, { match: h.value, ...(src ? { host: hostOf(src.startsWith('//') ? 'https:' + src : src) } : {}) });
    }
  }

  // Hidden third-party iframes, third-party form posts, third-party websockets
  for (const f of page.iframes) {
    if (f.hidden && f.thirdParty && !hostMatches(f.host, allow)) add('medium', 'hidden-iframe', `Hidden third-party iframe: ${f.src}`, { host: f.host, ...hostOrigin(f.host) });
  }
  for (const f of page.forms) {
    if (f.thirdParty && !hostMatches(f.host, allow)) add('medium', 'offsite-form', `Form submits to third-party host ${f.host} (${f.action})`, { host: f.host, ...hostOrigin(f.host) });
  }
  for (const w of page.websockets) {
    if (w.thirdParty && !hostMatches(w.host, allow)) add('medium', 'websocket', `WebSocket to third-party host ${w.url}`, { host: w.host, ...hostOrigin(w.host) });
  }

  // Baseline comparison
  const base = baseline?.pages?.[pageId(page)];
  if (!base) {
    add('info', 'no-baseline', 'No baseline for this page yet; change detection skipped.');
  } else if (!page.error) {
    const oldDomains = new Set(base.domains);
    for (const d of page.domains) {
      if (oldDomains.has(d.host)) continue;
      const sev = !d.thirdParty || hostMatches(d.host, allow) ? 'low' : 'medium';
      add(sev, 'new-domain', `New domain since baseline: ${d.host} (${d.types.join(', ')})`, { host: d.host, ...hostOrigin(d.host) });
    }
    // New cookies (only when the baseline recorded cookies). Third-party cookies set by JavaScript
    // are the interesting ones: that's how trackers, and some skimmers, stash data.
    if (base.stylesheets) {
      for (const st of page.stylesheets || []) {
        if (!st.sha256 || st.inline) continue;
        const prev = base.stylesheets[st.key];
        if (prev === undefined) add(st.thirdParty && !hostMatches(st.host, allow) ? 'low' : 'info', 'new-stylesheet', `New stylesheet since baseline: ${st.url}`, { script: st.url, host: st.host });
        else if (prev !== st.sha256 && !isVolatile(st)) add('info', 'changed-stylesheet', `Stylesheet contents changed since baseline: ${st.url}`, { script: st.url, host: st.host });
      }
    }
    if (base.storage) {
      const known = new Set(base.storage);
      for (const s of page.storage || []) {
        if (known.has(storageKey(s))) continue;
        known.add(storageKey(s));
        add('info', 'new-storage-key', `New ${s.type} key since baseline: ${s.key} (${s.origin}${s.firstWritten ? ', written during ' + s.firstWritten : ''})`, { host: hostOf(s.origin) });
      }
    }
    if (base.serviceWorkers) {
      const known = new Set(base.serviceWorkers);
      for (const w of page.serviceWorkers || []) if (!known.has(swKey(w))) add('low', 'new-service-worker', `New service worker since baseline: ${w.scriptURL || w.scope}`, { host: hostOf(w.scriptURL || w.scope) });
    }
    if (base.cookies) {
      const known = new Set(base.cookies);
      for (const c of page.cookies || []) {
        if (PRESET.has(c.setBy) || known.has(cookieKey(c))) continue;
        known.add(cookieKey(c));
        add(c.thirdParty && c.setBy === 'javascript' ? 'low' : 'info', 'new-cookie', `New cookie since baseline: ${c.name} on ${c.domain} (${c.thirdParty ? 'third-party' : 'first-party'}, set by ${c.setBy})`, { host: c.domain.replace(/^\./, '') });
      }
    }
    for (const s of page.scripts) {
      if (!s.sha256) continue;
      const prev = base.scripts[s.key];
      if (s.dynamic) continue;
      if (s.inline) {
        if (prev === undefined) add('low', 'new-inline-script', `New inline script ${s.key}`, { preview: s.preview, ...scriptOrigin(s) });
        continue;
      }
      if (prev === undefined) {
        const sev = s.thirdParty && !hostMatches(s.host, allow) ? 'medium' : 'low';
        add(sev, 'new-script', `New script since baseline: ${s.url}`, { script: s.url, ...scriptOrigin(s) });
      } else if (prev !== s.sha256 && !isVolatile(s)) {
        // Changed first-party files matter as much as third-party: skimmers are often
        // appended to a theme/plugin JS file on disk.
        const sev = hostMatches(s.host, allow) ? 'low' : 'medium';
        add(sev, 'changed-script', `Script contents changed since baseline: ${s.url}`, { script: s.url, ...scriptOrigin(s) });
      }
    }
  }

  // Card-data honeytoken: the dummy card number we typed, found in storage or a cookie.
  for (const f of page.cardDataFound || []) {
    add('high', 'card-data-in-storage', `The dummy card number the scanner typed was stored ${f.encoding} in ${f.where} "${f.key}" (${f.origin}): a script is stashing what visitors type`, {
      host: hostOf(f.origin) || f.origin.replace(/^\./, ''),
      match: `${f.where} ${f.key}`,
    });
  }

  // CSS rules (keyloggers, hidden payloads, script URLs) on every stylesheet.
  for (const st of page.stylesheets || []) {
    for (const fl of st.flags || []) {
      add(fl.severity, 'suspicious-css', fl.description, {
        rule: fl.rule,
        script: st.inline ? `inline ${st.key}` : st.url,
        match: fl.match,
        ...(fl.line ? { line: fl.line, column: fl.column, context: fl.context } : {}),
        ...(fl.custom ? { custom: true } : {}),
        ...(st.inline ? {} : { host: st.host }),
      });
    }
  }

  // Pattern-rule hits and code found inside storage values and IndexedDB records.
  const seenCode = new Set();
  for (const f of page.storageFindings || []) {
    const label = `${f.where} "${f.key}" (${f.origin})${f.decoded ? ', after base64-decoding' : ''}`;
    if (f.code) {
      if (seenCode.has(label)) continue;
      seenCode.add(label);
      add('low', 'code-in-storage', `JavaScript code stored in ${label}: storage is a known place to keep a payload between visits`, { script: label, match: f.preview, host: hostOf(f.origin) || f.origin });
      continue;
    }
    for (const fl of f.flags) {
      add(fl.severity, 'suspicious-code', fl.description, { rule: fl.rule, script: label, match: fl.match, host: hostOf(f.origin) || f.origin, storage: true, ...(fl.custom ? { custom: true } : {}) });
    }
  }

  // Known-vulnerable libraries (one finding per library per script).
  for (const s of page.scripts) {
    for (const lib of s.libs || []) {
      const cves = [...new Set(lib.vulnerabilities.flatMap((v) => v.cves))];
      const summaries = [...new Set(lib.vulnerabilities.map((v) => v.summary).filter(Boolean))];
      add(LIB_SEVERITY[lib.severity] || 'low', 'vulnerable-library', `${lib.library} ${lib.version} has ${lib.vulnerabilities.length} known vulnerabilit${lib.vulnerabilities.length === 1 ? 'y' : 'ies'}${cves.length ? ` (${cves.slice(0, 5).join(', ')}${cves.length > 5 ? '…' : ''})` : ''}`, {
        script: s.inline ? `inline ${s.key}` : s.url,
        match: summaries.slice(0, 3).join(' | ').slice(0, 300),
        library: { name: lib.library, version: lib.version, detectedBy: lib.detectedBy, advisories: lib.vulnerabilities.flatMap((v) => v.info).slice(0, 4) },
        ...scriptOrigin(s),
      });
    }
  }

  // Security posture: headers, SRI, mixed content, cookies, storage, opt-in DOM-XSS canary.
  if (!page.error) {
    const isFirst = (h) => hostMatches(h, firstParty);
    for (const [sev, type, message, detail] of [
      ...headerChecks({ headers: page.docHeaders, metaCsp: page.metaCsp, url: page.finalUrl || page.url }),
      ...sriCheck({ scriptTags: page.scriptTags, isFirst, paymentPage: page.paymentPage, volatile }),
      ...mixedContentCheck({ mixed: page.mixed }),
      ...cookieCheck({ cookies: page.cookies, url: page.finalUrl || page.url }),
      ...storageCheck({ storageTokens: page.storageTokens }),
      ...canaryCheck({ canary: page.canary }),
    ]) {
      add(sev, type, message, detail || {});
    }
  }

  // Custom rules: "html" hits were found during the scan; "url" rules run here over every URL we saw.
  for (const h of page.htmlHits || []) {
    add(h.severity, 'custom-html', h.description, { rule: h.rule, match: h.match, htmlLine: h.line, custom: true });
  }
  for (const r of rules?.urlRules || []) {
    const urls = new Set([
      ...page.scripts.filter((s) => !s.inline).map((s) => s.url),
      ...page.domains.map((d) => d.host),
      ...page.iframes.map((f) => f.src),
      ...page.forms.map((f) => f.action).filter(Boolean),
      ...page.websockets.map((w) => w.url),
    ]);
    for (const u of urls) {
      const hit = r.test(u);
      if (hit) add(r.severity, 'custom-url', `${r.description}: ${u}`, { rule: r.id, match: hit.match, script: u, host: hostOf(u) || u, custom: true, ...hostOrigin(hostOf(u) || u) });
    }
  }

  let out = issues;
  if (rules) {
    const { kept, suppressed } = applyRuleSettings(issues, { settings: rules.settings, suppress: rules.suppress, pageUrl: page.url });
    out = kept;
    page.suppressed = suppressed;
  }
  out.sort((a, b) => SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity]);
  return out;
}

export function summarize(pages) {
  const counts = { high: 0, medium: 0, low: 0, info: 0 };
  for (const p of pages) for (const i of p.issues) counts[i.severity]++;
  return counts;
}
