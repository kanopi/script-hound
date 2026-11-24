import { escapeHtml as e, phaseName, isInteractionPhase } from './util.mjs';
import { NAME, TAGLINE, COLORS, VERSION, brandSvg, svgDataUri, consoleName } from './brand.mjs';

// Short tag for things that only showed up once we interacted with the page.
const phaseTag = (ph) => (isInteractionPhase(ph) ? `on ${phaseName(ph)}` : ph === 'idle' ? 'after idle wait' : '');

const SEV_COLORS = { high: '#b42318', medium: '#b54708', low: '#175cd3', info: '#475467' };
const DELIVERED = { html: 'In the page HTML', injected: 'Added at runtime', unknown: 'Origin not traced' };

// "line 1, col 48213" (+ "page HTML line 214" for server-sent inline scripts)
const locText = (i) => (i.line ? `line ${i.line}, col ${i.column}${i.htmlLine ? ` (page HTML line ${i.htmlLine})` : ''}` : '');
// Rule id for code findings; the finding type is the "rule" for page-level and baseline findings.
const ruleOf = (i) => i.rule || i.type;
const wasText = (i) => (i.originalSeverity ? ` (was ${i.originalSeverity})` : '');

// Plain-text lines describing rule changes for a site (disabled, re-levelled, custom, suppressed).
// "Logged-in scan: headers Authorization; cookies session_id; storage state auth.json" (names only).
const authText = (a) =>
  a ? `Logged-in scan: ${[a.headers.length && 'headers ' + a.headers.join(', '), a.cookies.length && 'cookies ' + a.cookies.join(', '), a.storageState && 'storage state ' + a.storageState].filter(Boolean).join('; ')}` : '';

const cookieFlags = (c) => [c.httpOnly ? 'HttpOnly' : '', c.secure ? 'Secure' : '', c.sameSite ? `SameSite=${c.sameSite}` : ''].filter(Boolean).join(' ');
const cookieLife = (c) => (c.session ? 'session' : c.expiresDays != null ? (c.expiresDays < 1 ? '<1d' : `${c.expiresDays}d`) : '');

function ruleChangeLines(r) {
  if (!r) return [];
  const out = [];
  for (const c of r.changed) out.push(c.severity === 'off' ? `${c.id} turned OFF — ${c.reason || 'no reason given'} (${c.source})` : `${c.id} set to ${c.severity} (default ${c.default}) — ${c.reason || 'no reason given'} (${c.source})`);
  for (const c of r.custom) out.push(`custom rule ${c.id} (${c.severity}, ${c.target}): /${c.pattern}/ (${c.source})`);
  for (const s of r.suppress) out.push(`suppressed ${s.rule} on ${[s.page && 'page ' + s.page, s.script && 'script ' + s.script].filter(Boolean).join(', ')} — ${s.reason}; hid ${s.hits} finding(s) (${s.source})`);
  return out;
}

// One-line trail for Markdown / table cells: "A ← B ← page HTML"
const trailText = (o) => (o?.trail?.length ? o.trail.join(' ← ') : '');

function originMd(o) {
  if (!o) return '';
  const parts = [`${DELIVERED[o.delivered] || o.delivered}${o.via ? ` (${o.via})` : ''}`];
  if (o.request) parts.push(`first request ${o.request}`);
  if (o.trail.length) parts.push(`loaded by: ${trailText(o)}`);
  if (o.hint) parts.push(`where to look: ${o.hint}`);
  return parts.join('; ');
}

function originHtml(o) {
  if (!o) return '';
  return `<div class="origin"><b>${e(DELIVERED[o.delivered] || o.delivered)}</b>${o.via ? ` <span class="sub">— ${e(o.via)}</span>` : ''}${o.request ? ` <span class="sub">(first request: ${e(o.request)})</span>` : ''}${
    o.trail.length ? `<ol class="trail">${o.trail.map((t) => `<li>${e(t)}</li>`).join('')}</ol>` : ''
  }${o.hint ? `<div class="hint">Where to look: ${e(o.hint)}</div>` : ''}</div>`;
}

// views: { scripts, cookies, storage, headers, html } — the --show-* views to include (as code blocks).
export function renderMarkdown(report, { views = {}, htmlExcerpts = new Map(), outDir = 'reports' } = {}) {
  const { summary: c, meta } = report;
  const out = [];
  out.push(`# ${NAME} report`);
  out.push('');
  out.push(`_${TAGLINE}_${VERSION ? ` · v${VERSION}` : ''}`);
  out.push('');
  if (meta.containsValues) out.push(`> **⚠ ${VALUE_BANNER}**`, '');
  out.push(`Run: ${meta.startedAt} · ${meta.pageCount} page loads · ${meta.durationSec}s · mode: ${meta.modes || 'url'} · baseline: ${meta.baselineUsed ? 'yes' : 'none'}`);
  out.push('');
  out.push(`**High:** ${c.high} · **Medium:** ${c.medium} · **Low:** ${c.low} · Info: ${c.info}`);
  out.push('');
  for (const site of report.sites) {
    out.push(`## ${site.name}`);
    const rc = ruleChangeLines(site.rules);
    if (site.auth) out.push('', `_${authText(site.auth)}_`);
    if (rc.length) {
      out.push('', '**Rule changes in effect:**', '', ...rc.map((l) => `- ${l}`));
    }
    if (site.cspSuggestion) {
      out.push('', `**Suggested Content-Security-Policy** (from what ${site.cspSuggestion.pages} scanned page(s) loaded; deploy as Report-Only first):`, '', '```', site.cspSuggestion.header, '```', '', ...site.cspSuggestion.notes.map((n) => `- ${n}`));
    }
    for (const p of site.pages) {
      const n = p.issues.filter((i) => i.severity !== 'info').length;
      out.push('');
      out.push(`### ${p.url} (${p.profile}) — ${n ? n + ' finding(s)' : 'clean'}`);
      out.push(`${p.scripts.length} scripts · ${p.domains.length} domains (${p.domains.filter((d) => d.thirdParty).length} third-party)`);
      if (p.issues.length) {
        out.push('');
        out.push('| Severity | Rule | Detail |');
        out.push('|---|---|---|');
        for (const i of p.issues) {
          const detail = [
            i.message + (i.alsoOn ? ` (also on ${i.alsoOn} other page(s))` : ''),
            i.script && i.type === 'suspicious-code' ? `in ${i.script}${i.line ? ` at ${locText(i)}` : ''}` : '',
            i.match ? '`' + String(i.match).replace(/[|`\n]/g, ' ').slice(0, 120) + '`' : '',
            i.context ? 'code: `' + String(i.context).replace(/[|`\n]/g, ' ').slice(0, 160) + '`' : '',
            i.phase && i.phase !== 'load' ? `first seen: ${phaseName(i.phase)}` : '',
            originMd(i.origin).replace(/\n/g, ' '),
          ]
            .filter(Boolean)
            .join(' — ');
          out.push(`| ${i.severity}${wasText(i)} | ${ruleOf(i)}${i.custom ? ' (custom)' : ''} | ${detail.replace(/\|/g, '\\|')} |`);
        }
      }
      if (p.suppressed?.length) {
        out.push('', `Suppressed by config: ${p.suppressed.map((i) => `${ruleOf(i)} (${i.suppressedBy})`).join('; ')}`);
      }
      for (const [title, lines] of viewSections(p, views, makeColors(false), { htmlExcerpts, outDir, excerpt: false })) {
        out.push('', `**${title}**`, '', '```', ...lines.map((l) => l.replace(/^ {4}/, '')).filter((l, i) => i > 0 || l.trim()), '```');
      }
    }
    out.push('');
  }
  return out.join('\n');
}

// The --show-* views as plain-text sections, shared by Markdown and HTML (the console uses the same
// line renderers with colors). excerpt: include the server-HTML excerpt in the HTML view.
function viewSections(p, views, c, { htmlExcerpts, outDir, excerpt = true }) {
  const out = [];
  if (views.scripts) out.push(['Third-party script tree', scriptTreeLines(p, c)]);
  if (views.cookies) out.push(['Cookies', cookieLines(p, c)]);
  if (views.storage) out.push(['Browser storage', storageLines(p, c)]);
  if (views.headers) out.push(['Headers', headerLines(p, c)]);
  if (views.html) out.push(['HTML', htmlLines(p, c, excerpt ? htmlExcerpts.get(p) : null, outDir)]);
  return out;
}

// The HTML report always includes every view (collapsed), so nothing depends on which --show-* flags ran.
export function renderHtml(report, { htmlExcerpts = new Map(), outDir = 'reports' } = {}) {
  const { summary: c, meta } = report;
  const badge = (s) => `<span class="b" style="background:${SEV_COLORS[s]}">${s}</span>`;

  const pageBlock = (p) => {
    const real = p.issues.filter((i) => i.severity !== 'info');
    const worst = real[0]?.severity;
    const rows = p.issues
      .map(
        (i) => `<tr><td>${badge(i.severity)}${i.originalSeverity ? `<div class="sub">was ${e(i.originalSeverity)}</div>` : ''}</td><td><code>${e(ruleOf(i))}</code>${i.custom ? '<div class="sub">custom</div>' : ''}</td><td>${e(i.message)}${i.alsoOn ? ` <span class="sub">(also on ${i.alsoOn} other page(s))</span>` : ''}${
          i.script && i.type === 'suspicious-code' ? `<div class="sub">in ${e(i.script)}${i.line ? ` at <b>${e(locText(i))}</b>` : ''}</div>` : ''
        }${i.match ? `<pre>${e(i.match)}</pre>` : ''}${i.context ? `<pre class="ctx">${e(i.context)}</pre>` : ''}${i.preview ? `<pre>${e(i.preview)}</pre>` : ''}${
          i.phase && i.phase !== 'load' ? `<div class="sub">First seen during: <b>${e(phaseName(i.phase))}</b></div>` : ''
        }${originHtml(i.origin)}</td></tr>`
      )
      .join('');
    const scripts = p.scripts
      .slice()
      .sort((a, b) => Number(b.thirdParty) - Number(a.thirdParty) || a.key.localeCompare(b.key))
      .map(
        (s) => `<tr><td>${s.inline ? 'inline' : s.thirdParty ? '3rd-party' : '1st-party'}</td><td class="u">${e(s.inline ? s.key : s.url)}${
          s.inline ? `<pre>${e(s.preview)}</pre>` : ''
        }</td><td>${s.origin ? `${e(DELIVERED[s.origin.delivered])}${s.origin.via ? `<div>${e(s.origin.via)}</div>` : ''}${s.origin.trail.length ? `<div class="sub">${e(trailText(s.origin))}</div>` : ''}` : '–'}</td><td>${s.phase ? (isInteractionPhase(s.phase) ? `<b>${e(phaseName(s.phase))}</b>` : e(phaseName(s.phase))) : '–'}</td><td>${s.size ?? '–'}</td><td><code>${e((s.sha256 || s.error || '').slice(0, 12))}</code></td><td>${(s.flags || []).map((f) => `${badge(f.severity)} <code>${e(f.rule)}</code>${f.line ? ` <span class="sub">${f.line}:${f.column}</span>` : ''}`).join('<br>')}</td></tr>`
      )
      .join('');
    const domains = p.domains
      .slice()
      .sort((a, b) => Number(b.thirdParty) - Number(a.thirdParty) || a.host.localeCompare(b.host))
      .map((d) => `<tr><td>${d.thirdParty ? '3rd-party' : '1st-party'}</td><td>${e(d.host)}</td><td>${e(d.types.join(', '))}</td><td>${d.count}</td><td class="u">${d.origin ? e(trailText(d.origin) || DELIVERED[d.origin.delivered]) : '–'}</td><td>${d.phase ? (isInteractionPhase(d.phase) ? `<b>${e(phaseName(d.phase))}</b>` : e(phaseName(d.phase))) : '–'}</td></tr>`)
      .join('');
    return `<section class="page ${worst || 'clean'}">
      <h3>${worst ? badge(worst) : '<span class="b ok">clean</span>'} <a href="${e(p.url)}">${e(p.url)}</a> <span class="sub">${e(p.profile)}</span></h3>
      <p class="sub">${p.scripts.length} scripts · ${p.domains.length} domains (${p.domains.filter((d) => d.thirdParty).length} third-party)${
        p.finalUrl && p.finalUrl !== p.url ? ` · final URL ${e(p.finalUrl)}` : ''
      }</p>
      ${(p.interactions || []).length ? `<details><summary>Custom interactions (${p.interactions.filter((i) => !i.note).length} steps, ${p.interactions.filter((i) => i.ok === false).length} failed)</summary><ul>${p.interactions
        .map((it) => `<li>${it.note ? e(it.label) : `${it.ok ? '✓' : '✗'} ${e(it.label)}${it.ok ? '' : ` — <b>${e(it.error)}</b>`}${it.navigatedTo ? ` → navigated to ${e(it.navigatedTo)}` : ''} <span class="sub">${it.ms}ms</span>`}</li>`)
        .join('')}</ul></details>` : ''}
      ${rows ? `<table><thead><tr><th>Severity</th><th>Rule</th><th>Detail</th></tr></thead><tbody>${rows}</tbody></table>` : ''}
      ${p.suppressed?.length ? `<details><summary>Suppressed by config (${p.suppressed.length})</summary><ul>${p.suppressed.map((i) => `<li>${badge(i.severity)} <code>${e(ruleOf(i))}</code> ${e(i.message)} — <i>${e(i.suppressedBy)}</i></li>`).join('')}</ul></details>` : ''}
      <details><summary>Script inventory (${p.scripts.length})</summary><table><thead><tr><th>Origin</th><th>Script</th><th>Loaded by</th><th>When</th><th>Bytes</th><th>SHA-256</th><th>Flags</th></tr></thead><tbody>${scripts}</tbody></table></details>
      ${(p.cookies || []).length ? `<details><summary>Cookies (${p.cookies.length}: ${p.cookies.filter((c) => c.thirdParty).length} third-party, ${p.cookies.filter((c) => c.setBy === 'javascript').length} set by JavaScript)</summary><table><thead><tr><th>Origin</th><th>Name</th><th>Domain</th><th>Set by</th><th>Flags</th><th>Expires</th>${p.cookies.some((c) => c.value !== undefined) ? '<th>Value</th>' : ''}</tr></thead><tbody>${p.cookies
        .slice()
        .sort((a, b) => Number(b.thirdParty) - Number(a.thirdParty) || a.domain.localeCompare(b.domain) || a.name.localeCompare(b.name))
        .map((c) => `<tr><td>${c.thirdParty ? '3rd-party' : '1st-party'}</td><td><code>${e(c.name)}</code></td><td>${e(c.domain)}</td><td>${e(c.setBy)}</td><td>${e(cookieFlags(c))}</td><td>${e(cookieLife(c))}</td>${c.value !== undefined ? `<td class="u"><code>${e(c.value)}</code></td>` : ''}</tr>`)
        .join('')}</tbody></table></details>` : ''}
      ${storageCount(p) ? `<details><summary>Browser storage (${storageSummary(p)})</summary>${
        (p.storage || []).length ? `<table><thead><tr><th>Origin</th><th>Type</th><th>Key</th><th>Kind</th><th>Size</th><th>First written</th><th>${(p.storage || []).some((x) => x.value !== undefined) ? 'Value' : 'Preview'}</th></tr></thead><tbody>${p.storage
          .slice()
          .sort((a, b) => Number(b.thirdParty) - Number(a.thirdParty) || a.origin.localeCompare(b.origin) || a.type.localeCompare(b.type) || a.key.localeCompare(b.key))
          .map((x) => `<tr><td class="u">${e(x.origin)}${x.thirdParty ? ' <span class="sub">3rd-party</span>' : ''}</td><td>${e(x.type)}</td><td><code>${e(x.key)}</code></td><td>${e(x.kind)}</td><td>${x.size}</td><td>${x.firstWritten ? (isInteractionPhase(x.firstWritten) ? `<b>${e(phaseName(x.firstWritten))}</b>` : e(phaseName(x.firstWritten))) : '–'}</td><td>${x.value !== undefined ? `<pre>${e(x.value)}</pre>` : `<code>${e(x.preview)}</code>`}</td></tr>`)
          .join('')}</tbody></table>` : ''
      }${(p.indexedDB || []).length ? `<p><b>IndexedDB</b></p><ul>${p.indexedDB.map((d) => `<li>${e(d.origin)} <code>${e(d.name)}</code> v${e(d.version)}: ${d.stores.map((s) => `${e(s.name)} (${s.count ?? '?'})${(s.samples || []).length ? `<pre>${s.samples.map((v) => e(v)).join('\n')}</pre>` : ''}`).join(', ') || 'no stores'}</li>`).join('')}</ul>` : ''}${
        (p.opfs || []).some((f) => f.size != null) ? `<p><b>Origin Private File System</b></p><ul>${p.opfs.filter((f) => f.size != null).map((f) => `<li>${e(f.origin)} <code>${e(f.path)}</code> ${kb(f.size)}${f.sqlite ? ' <b>SQLite database</b>' : ''}</li>`).join('')}</ul>` : ''
      }${p.windowName ? `<p><b>window.name</b> (${p.windowName.size} chars): <code>${e(p.windowName.value ?? p.windowName.preview)}</code></p>` : ''}${
        p.historyState ? `<p><b>history.state</b> (${p.historyState.size} chars): <code>${e(p.historyState.value ?? p.historyState.preview)}</code></p>` : ''
      }${(p.storageUsage || []).some((u) => u.usage) ? `<p class="sub">Storage used: ${p.storageUsage.filter((u) => u.usage).map((u) => `${e(u.origin)} ${kb(u.usage)}`).join(', ')}</p>` : ''}${
        (p.cacheStorage || []).length ? `<p><b>Cache Storage</b></p><ul>${p.cacheStorage.map((c) => `<li>${e(c.origin)} <code>${e(c.name)}</code>: ${c.entries} entries</li>`).join('')}</ul>` : ''
      }${(p.serviceWorkers || []).length ? `<p><b>Service workers</b></p><ul>${p.serviceWorkers.map((w) => `<li><code>${e(w.scriptURL)}</code> scope ${e(w.scope)} (${e(w.state)})</li>`).join('')}</ul>` : ''}</details>` : ''}
      ${(p.stylesheets || []).length ? `<details><summary>Stylesheets (${p.stylesheets.length})</summary><table><thead><tr><th>Origin</th><th>Stylesheet</th><th>Bytes</th><th>SHA-256</th><th>Flags</th></tr></thead><tbody>${p.stylesheets
        .slice()
        .sort((a, b) => Number(b.thirdParty) - Number(a.thirdParty) || a.key.localeCompare(b.key))
        .map((st) => `<tr><td>${st.inline ? 'inline' : st.thirdParty ? '3rd-party' : '1st-party'}</td><td class="u">${e(st.inline ? st.key : st.url)}${st.inline ? `<pre>${e(st.preview)}</pre>` : ''}</td><td>${st.size}</td><td><code>${e(st.sha256.slice(0, 12))}</code></td><td>${(st.flags || []).map((f) => `${badge(f.severity)} <code>${e(f.rule)}</code>${f.line ? ` <span class="sub">${f.line}:${f.column}</span>` : ''}`).join('<br>')}</td></tr>`)
        .join('')}</tbody></table></details>` : ''}
      ${(p.responseHeaders || []).length ? `<details><summary>Headers (HTTP ${p.responseStatus ?? '?'}, ${p.responseHeaders.length} response / ${(p.requestHeaders || []).length} request)</summary><table><thead><tr><th>Response header</th><th>Value</th></tr></thead><tbody>${p.responseHeaders
        .map((h) => `<tr><td><code>${e(h.name)}</code></td><td class="u">${e(h.value)}</td></tr>`)
        .join('')}</tbody></table>${(p.requestHeaders || []).length ? `<table><thead><tr><th>Request header sent</th><th>Value</th></tr></thead><tbody>${p.requestHeaders.map((h) => `<tr><td><code>${e(h.name)}</code></td><td class="u">${e(h.value)}</td></tr>`).join('')}</tbody></table>` : ''}</details>` : ''}
      ${(p.scripts || []).some((s) => !s.inline && s.thirdParty) ? `<details><summary>Third-party script tree</summary><pre class="tree">${e(scriptTreeLines(p, makeColors(false)).slice(2).map((l) => l.replace(/^ {4}/, '')).join('\n'))}</pre></details>` : ''}
      ${p.html ? `<details><summary>HTML: as sent vs rendered${changedByScripts(p) ? ` (${e(changedByScripts(p))})` : ''}</summary><p>${p.html.server ? `<a href="${e(p.html.server.file)}">As sent by the server</a> (${kb(p.html.server.size)}, ${p.html.server.lines} lines)` : ''}${p.html.rendered ? ` · <a href="${e(p.html.rendered.file)}">Rendered after scripts</a> (${kb(p.html.rendered.size)}, ${p.html.rendered.lines} lines)` : ''}</p>${
        htmlExcerpts.get(p) != null ? `<p class="sub">Server HTML, first ${Math.min(200, htmlExcerpts.get(p).split('\n').length)} lines:</p><pre class="tree">${e(htmlExcerpts.get(p).split('\n').slice(0, 200).join('\n'))}</pre>` : ''
      }</details>` : ''}
      <details><summary>Domains contacted (${p.domains.length})</summary><table><thead><tr><th>Origin</th><th>Host</th><th>Request types</th><th>Requests</th><th>First requested by</th><th>When</th></tr></thead><tbody>${domains}</tbody></table></details>
    </section>`;
  };

  return `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${NAME} report — ${e(meta.startedAt)}</title>
${brandSvg('scripthound-mark-simple') ? `<link rel="icon" href="${svgDataUri(brandSvg('scripthound-mark-simple'))}">` : ''}
<style>
  body{font:14px/1.5 system-ui,-apple-system,Segoe UI,sans-serif;margin:0;color:#101828;background:#f9fafb}
  main{max-width:1200px;margin:0 auto;padding:24px}
  h1{margin:0 0 4px} h2{margin-top:32px;border-bottom:1px solid #d0d5dd;padding-bottom:4px}
  .sub{color:#475467;font-size:12px;font-weight:normal}
  .cards{display:flex;gap:12px;margin:16px 0}
  .card{background:#fff;border:1px solid #eaecf0;border-radius:8px;padding:12px 18px;min-width:90px}
  .card b{display:block;font-size:24px}
  .page{background:#fff;border:1px solid #eaecf0;border-left:4px solid #12b76a;border-radius:6px;padding:8px 16px;margin:12px 0}
  .page.high{border-left-color:${SEV_COLORS.high}} .page.medium{border-left-color:${SEV_COLORS.medium}} .page.low{border-left-color:${SEV_COLORS.low}}
  h3{font-size:15px;margin:8px 0;word-break:break-all}
  table{border-collapse:collapse;width:100%;margin:8px 0;font-size:13px}
  th,td{text-align:left;border-bottom:1px solid #eaecf0;padding:6px;vertical-align:top}
  td.u{word-break:break-all}
  pre{white-space:pre-wrap;word-break:break-all;background:#f2f4f7;padding:6px;border-radius:4px;margin:4px 0 0;font-size:12px;max-height:160px;overflow:auto}
  .b{color:#fff;border-radius:10px;padding:1px 8px;font-size:11px;font-weight:600;text-transform:uppercase}
  .b.ok{background:#12b76a}
  details{margin:6px 0} summary{cursor:pointer;color:#344054}
  .origin{margin-top:6px;font-size:12px;color:#344054;border-left:2px solid #d0d5dd;padding-left:8px}
  .trail{margin:2px 0;padding-left:18px;word-break:break-all} .trail li::marker{content:'← '}
  .hint{color:#475467;font-style:italic}
  pre.ctx{background:#fef3f2;border-left:3px solid #b42318}
  pre.tree{max-height:600px;font-size:12px;line-height:1.35;word-break:normal;white-space:pre;overflow:auto}
  .note{background:#fffaeb;border:1px solid #fedf89;border-radius:6px;padding:8px 12px;font-size:13px}
  /* ScriptHound brand (brand/README.md): navy header, amber accents */
  header.brand{background:${COLORS.navy};color:${COLORS.cream}}
  header.brand .in{max-width:1200px;margin:0 auto;padding:16px 24px;display:flex;align-items:center;gap:16px;flex-wrap:wrap}
  header.brand .logo svg{height:44px;width:auto;display:block}
  header.brand .t{font-size:13px;color:#c9cfdb}
  header.brand .t b{color:${COLORS.cream};font-weight:600}
  header.brand .fallback{font:800 26px system-ui,sans-serif;color:${COLORS.cream}} header.brand .fallback span{color:${COLORS.amber}}
  a{color:#175cd3} h2{border-bottom-color:${COLORS.amber}}
  footer{color:#667085;font-size:12px;text-align:center;padding:24px}
</style></head><body>
<header class="brand"><div class="in"><div class="logo">${brandSvg('scripthound-logo-simple-dark') || `<span class="fallback">Script<span>Hound</span></span>`}</div><div class="t"><b>${e(TAGLINE)}</b><br>Report${VERSION ? ` · v${e(VERSION)}` : ''}</div></div></header>
<main>
<h1>Scan report</h1>
<div class="sub">${e(meta.startedAt)} · ${meta.pageCount} page loads · ${meta.durationSec}s · mode: ${e(meta.modes || 'url')} · baseline: ${meta.baselineUsed ? 'compared' : 'none (first run)'}</div>
<div class="cards">
  <div class="card"><b style="color:${SEV_COLORS.high}">${c.high}</b>High</div>
  <div class="card"><b style="color:${SEV_COLORS.medium}">${c.medium}</b>Medium</div>
  <div class="card"><b style="color:${SEV_COLORS.low}">${c.low}</b>Low</div>
  <div class="card"><b style="color:${SEV_COLORS.info}">${c.info}</b>Info</div>
</div>
${meta.containsValues ? `<p class="note" style="background:#fef3f2;border-color:#fda29b"><b>⚠ ${e(VALUE_BANNER)}</b></p>` : ''}
<p class="note">Findings are heuristics plus change detection. <b>High</b> = patterns rarely seen in clean code (decoded eval, card-field harvesting, miners, off-site redirects, blocklisted domains). <b>Medium/Low</b> = worth a look; minified libraries and routine vendor updates can trigger these. The <b>loaded by</b> trail and <b>where to look</b> hints are best-effort leads (from the browser's own record of what requested what), not proof.</p>
${report.sites.map((s) => { const rc = ruleChangeLines(s.rules); return `<h2>${e(s.name)}</h2>${s.cspSuggestion ? `<details><summary><b>Suggested Content-Security-Policy</b> (from ${s.cspSuggestion.pages} scanned page(s); deploy as Report-Only first)</summary><pre class="tree">Content-Security-Policy-Report-Only:\n${e(s.cspSuggestion.directives.map(([n, srcs]) => `  ${n}${srcs.length ? ' ' + srcs.join(' ') : ''};`).join('\n'))}</pre><p class="sub">One line, ready to paste:</p><pre>${e(s.cspSuggestion.header)}</pre><ul>${s.cspSuggestion.notes.map((n) => `<li>${e(n)}</li>`).join('')}</ul></details>` : ''}${s.auth ? `<p class="sub">${e(authText(s.auth))}</p>` : ''}${rc.length ? `<div class="note"><b>Rule changes in effect</b><ul>${rc.map((l) => `<li>${e(l)}</li>`).join('')}</ul></div>` : ''}${s.pages.map(pageBlock).join('')}`; }).join('')}
</main><footer>${NAME}${VERSION ? ` v${e(VERSION)}` : ''} · ${e(TAGLINE)}</footer></body></html>`;
}


// ANSI styling for terminal output. makeColors(false) returns pass-through functions.
export function makeColors(enabled) {
  const wrap = (open, close) => (enabled ? (t) => `\x1b[${open}m${t}\x1b[${close}m` : (t) => String(t));
  const c = {
    bold: wrap(1, 22),
    dim: wrap(2, 22),
    red: wrap(31, 39),
    green: wrap(32, 39),
    yellow: wrap(33, 39),
    cyan: wrap(36, 39),
    gray: wrap(90, 39),
  };
  c.sev = (sev, text = sev.toUpperCase()) =>
    ({ high: (t) => c.bold(c.red(t)), medium: c.yellow, low: c.cyan, info: c.gray, clean: c.green, error: (t) => c.bold(c.red(t)) })[sev]?.(text) ?? text;
  return c;
}

// Should terminal output be colored? --color always|never|auto; auto honours NO_COLOR / FORCE_COLOR / TTY.
export function useColor(setting = 'auto', stream = process.stdout, env = process.env) {
  if (setting === 'always') return true;
  if (setting === 'never') return false;
  if (env.NO_COLOR) return false;
  if (env.FORCE_COLOR && env.FORCE_COLOR !== '0') return true;
  return !!stream.isTTY && env.TERM !== 'dumb';
}

const storageCount = (p) => (p.storage || []).length + (p.indexedDB || []).length + (p.cacheStorage || []).length + (p.serviceWorkers || []).length + (p.opfs || []).length + (p.windowName ? 1 : 0) + (p.historyState ? 1 : 0);
const kb = (n) => (n == null ? '?' : n < 1024 ? `${n} B` : n < 1048576 ? `${(n / 1024).toFixed(1)} KB` : `${(n / 1048576).toFixed(1)} MB`);
const VALUE_BANNER = 'This report contains live cookie and storage values (--show-values). Treat it as sensitive; values you supplied (auth, cookie jar) are still masked.';
// Values for the console: one line per ~110 chars, capped, with a pointer to the full value.
const valueLines = (v, indent, c) => {
  const s = String(v);
  const cap = 600;
  const body = s.length > cap ? s.slice(0, cap) : s;
  const rows = body.match(/[\s\S]{1,110}/g) || [''];
  return [...rows.map((r) => `${indent}${c.dim('│')} ${r.replace(/\s/g, ' ')}`), ...(s.length > cap ? [`${indent}${c.dim('│')} ${c.gray(`… ${s.length} chars in total; the full value is in report.json`)}`] : [])];
};
const storageSummary = (p) =>
  [
    `${(p.storage || []).length} local/session keys`,
    (p.indexedDB || []).length && `${p.indexedDB.length} IndexedDB`,
    (p.cacheStorage || []).length && `${p.cacheStorage.length} caches`,
    (p.serviceWorkers || []).length && `${p.serviceWorkers.length} service worker(s)`,
    (p.opfs || []).length && `${p.opfs.filter((f) => f.size != null).length} OPFS file(s)`,
  ]
    .filter(Boolean)
    .join(', ');

// Security headers we check (lib/posture.mjs), to mark present/missing in --show-headers.
const SECURITY_HEADERS = ['content-security-policy', 'strict-transport-security', 'x-content-type-options', 'x-frame-options', 'referrer-policy', 'permissions-policy'];

// --show-headers: main-document response headers (security headers marked) and the request headers sent.
function headerLines(p, c) {
  const lines = [];
  const resp = p.responseHeaders || [];
  lines.push('', `    ${c.bold(`Response headers${p.responseStatus ? ` (HTTP ${p.responseStatus})` : ''}`)}`);
  if (!resp.length) lines.push(`      ${c.gray('none captured (page failed to load?)')}`);
  const w = Math.min(36, Math.max(0, ...resp.map((h) => h.name.length)));
  for (const h of resp) {
    const sec = SECURITY_HEADERS.includes(h.name.toLowerCase());
    lines.push(`      ${sec ? c.green(h.name.padEnd(w)) : h.name.padEnd(w)}  ${c.gray(String(h.value).replace(/\s+/g, ' ').slice(0, 300))}`);
  }
  const have = new Set(resp.map((h) => h.name.toLowerCase()));
  const missing = SECURITY_HEADERS.filter((h) => !have.has(h) && !(h === 'strict-transport-security' && !/^https:/.test(p.finalUrl || p.url)));
  if (missing.length) lines.push(`      ${c.yellow('missing: ' + missing.join(', '))}`);
  const req = p.requestHeaders || [];
  if (req.length) {
    lines.push(`    ${c.bold('Request headers sent')}`);
    const rw = Math.min(36, Math.max(0, ...req.map((h) => h.name.length)));
    for (const h of req) lines.push(`      ${h.name.padEnd(rw)}  ${c.gray(String(h.value).slice(0, 300))}`);
  }
  return lines;
}

const changedByScripts = (p) => {
  const h = p.html;
  if (!h?.server || !h?.rendered) return '';
  return Object.keys(h.rendered.tags)
    .map((t) => [t, h.rendered.tags[t] - h.server.tags[t]])
    .filter(([, d]) => d !== 0)
    .map(([t, d]) => `${d > 0 ? '+' : ''}${d} <${t}>`)
    .join(', ');
};

// --show-html: where the two HTML versions were saved, what scripts added, and the server HTML itself.
const MAX_HTML_LINES = 200;
function htmlLines(p, c, serverHtml, outDir) {
  const h = p.html;
  const lines = ['', `    ${c.bold('HTML')}`];
  if (!h) return [...lines, `      ${c.gray('not captured')}`];
  const where = (x) => (x ? `${outDir}/${x.file} (${kb(x.size)}, ${x.lines} lines)` : 'not available');
  lines.push(`      ${c.gray('server (as sent):     ')}${where(h.server)}`, `      ${c.gray('rendered (after JS):  ')}${where(h.rendered)}`);
  if (h.server && h.rendered) lines.push(`      ${c.gray('changed by scripts:   ')}${changedByScripts(p) ? c.yellow(changedByScripts(p)) : 'no element-count changes'}`);
  if (serverHtml != null) {
    const all = serverHtml.split('\n');
    lines.push(`    ${c.bold('Server HTML')}${all.length > MAX_HTML_LINES ? c.gray(` (first ${MAX_HTML_LINES} of ${all.length} lines; full file above)`) : ''}`);
    for (const l of all.slice(0, MAX_HTML_LINES)) lines.push(`      ${c.dim('│')} ${l.length > 220 ? l.slice(0, 220) + c.gray('…') : l}`);
  }
  return lines;
}

// --show-storage: localStorage/sessionStorage keys grouped by origin, then IndexedDB, caches, workers.
function storageLines(p, c) {
  const list = p.storage || [];
  const lines = ['', `    ${c.bold(`Browser storage (${storageSummary(p)})`)}`];
  if (!storageCount(p)) return [...lines, `      ${c.gray('none')}`];
  const fit = (str, w) => (str.length <= w ? str.padEnd(w) : str.slice(0, Math.ceil((w - 1) / 2)) + '…' + str.slice(str.length - Math.floor((w - 1) / 2)));
  const keyW = Math.min(36, Math.max(4, ...list.map((x) => x.key.length)));
  const kindW = Math.max(4, ...list.map((x) => x.kind.length));
  const whenW = Math.max(0, ...list.map((x) => (x.firstWritten ? phaseName(x.firstWritten).length : 1)));
  const origins = [...new Set(list.map((x) => x.origin))].sort((a, b) => Number(list.find((x) => x.origin === a).thirdParty) - Number(list.find((x) => x.origin === b).thirdParty) || a.localeCompare(b));
  for (const o of origins) {
    const tp = list.find((x) => x.origin === o).thirdParty;
    lines.push(`      ${c.bold(o)}${tp ? c.gray(' (third-party iframe)') : ''}`);
    for (const x of list.filter((y) => y.origin === o).sort((a, b) => a.type.localeCompare(b.type) || a.key.localeCompare(b.key))) {
      const when = x.firstWritten ? phaseName(x.firstWritten) : '–';
      const whenTxt = isInteractionPhase(x.firstWritten) ? c.yellow(when.padEnd(whenW)) : c.gray(when.padEnd(whenW));
      lines.push(`        ${c.gray(x.type === 'localStorage' ? 'local  ' : 'session')}  ${fit(x.key, keyW)}  ${c.gray(x.kind.padEnd(kindW))}  ${whenTxt}  ${x.value !== undefined ? '' : c.gray(x.preview)}`);
      if (x.value !== undefined) lines.push(...valueLines(x.value, '          ', c));
    }
  }
  for (const d of p.indexedDB || []) {
    lines.push(`      ${c.bold('IndexedDB')} ${d.name} ${c.gray(`(${d.origin}, v${d.version})`)}: ${d.stores.map((s) => `${s.name} (${s.count ?? '?'})`).join(', ') || c.gray('no stores')}`);
    for (const s of d.stores) for (const [i, v] of (s.samples || []).entries()) lines.push(`        ${c.gray(`${s.name}[${i}]`)}`, ...valueLines(v, '          ', c));
  }
  for (const f of (p.opfs || []).filter((x) => x.size != null)) lines.push(`      ${c.bold('OPFS file')} ${f.path} ${c.gray(`(${f.origin}, ${kb(f.size)})`)}${f.sqlite ? c.yellow(' SQLite database') : ''}`);
  for (const u of p.storageUsage || []) if (u.usage) lines.push(`      ${c.gray(`Storage used by ${u.origin}: ${kb(u.usage)}`)}`);
  for (const [label, v] of [['window.name', p.windowName], ['history.state', p.historyState]]) {
    if (!v) continue;
    lines.push(`      ${c.bold(label)} ${c.gray(`${v.size} chars${v.kind ? ', ' + v.kind : ''}`)}  ${v.value !== undefined ? '' : c.gray(v.preview)}`);
    if (v.value !== undefined) lines.push(...valueLines(v.value, '          ', c));
  }
  for (const b of p.storageBuckets || []) lines.push(`      ${c.bold('Storage bucket')} ${b.name} ${c.gray(`(${b.origin})`)}`);
  for (const k of p.cacheStorage || []) lines.push(`      ${c.bold('Cache')} ${k.name} ${c.gray(`(${k.origin})`)}: ${k.entries} entries`);
  for (const w of p.serviceWorkers || []) lines.push(`      ${c.bold('Service worker')} ${w.scriptURL} ${c.gray(`scope ${w.scope}, ${w.state}${w.size != null ? ', ' + kb(w.size) + ' (code checked)' : ''}`)}`);
  return lines;
}

// --show-cookies: every cookie after the visit, grouped first-party / third-party, with who set it.
function cookieLines(p, c) {
  const list = p.cookies || [];
  const lines = ['', `    ${c.bold(`Cookies (${list.length}: ${list.filter((x) => x.thirdParty).length} third-party, ${list.filter((x) => x.setBy === 'javascript').length} set by JavaScript)`)}`];
  if (!list.length) return [...lines, `      ${c.gray('none')}`];
  // Column widths fit the longest value across BOTH groups (so first- and third-party line up), capped;
  // longer values are shortened in the middle so the recognisable start and end survive.
  const fit = (str, w) => (str.length <= w ? str.padEnd(w) : str.slice(0, Math.ceil((w - 1) / 2)) + '…' + str.slice(str.length - Math.floor((w - 1) / 2)));
  const nameW = Math.min(40, Math.max(...list.map((x) => x.name.length)));
  const domW = Math.min(30, Math.max(...list.map((x) => x.domain.length)));
  const whoText = (x) => (x.setBy === 'javascript' ? 'set by JavaScript' : x.setBy === 'server' ? 'set by server' : x.setBy === 'earlier page' ? 'earlier page' : x.setBy);
  const whoW = Math.max(...list.map((x) => whoText(x).length));
  for (const party of [false, true]) {
    const group = list.filter((x) => x.thirdParty === party).sort((a, b) => a.domain.localeCompare(b.domain) || a.name.localeCompare(b.name));
    if (!group.length) continue;
    lines.push(`      ${c.bold(party ? 'third-party' : 'first-party')}`);
    for (const x of group) {
      const wt = whoText(x).padEnd(whoW);
      const who = x.setBy === 'javascript' ? c.yellow(wt) : x.setBy === 'server' ? c.gray(wt) : c.cyan(wt);
      lines.push(`        ${fit(x.name, nameW)}  ${c.gray(fit(x.domain, domW))}  ${who}  ${c.gray([cookieFlags(x), cookieLife(x)].filter(Boolean).join(' · '))}`);
      if (x.value !== undefined) lines.push(...valueLines(x.value, '          ', c));
    }
  }
  return lines;
}

// --show-scripts: a loader tree. Root = page HTML; each script sits under what loaded it.
// Only branches that lead to a third-party script are drawn; first-party files and inline scripts
// on those branches are shown dimmed as connectors. Long runs of plain same-host siblings collapse.
const COLLAPSE_AFTER = 4;

function scriptTreeLines(p, c) {
  const ext = p.scripts.filter((s) => !s.inline && s.thirdParty);
  const hosts = new Set(ext.map((s) => s.host));
  const lines = ['', `    ${c.bold(`Third-party scripts (${ext.length}${hosts.size ? ` across ${hosts.size} host${hosts.size > 1 ? 's' : ''}` : ''})`)}`];
  if (!ext.length) return [...lines, `      ${c.gray('none')}`];

  const tagged = (type) => new Set(p.issues.filter((i) => i.type === type).map((i) => i.script));
  const isNew = tagged('new-script');
  const changed = tagged('changed-script');
  const rank = ['high', 'medium', 'low'];

  // Nodes keyed by script URL or inline key; parents from origin.parent.
  const ROOT = 'html';
  const UNTRACED = '?';
  const nodes = new Map();
  for (const s of p.scripts) nodes.set(s.inline ? s.key : s.url, { s, kids: [] });
  const keyOf = (s) => (s.inline ? s.key : s.url);
  const parentKey = (s) => {
    const par = s.origin?.parent;
    if (par === ROOT) return ROOT;
    if (par && nodes.has(par) && par !== keyOf(s)) return par;
    return UNTRACED;
  };
  // Loaders that aren't in the script inventory (usually an iframe's own document, e.g. Shopify's
  // web-pixel sandboxes) become placeholder nodes so their scripts still hang somewhere sensible.
  const frameSrcs = new Set((p.iframes || []).map((f) => f.src));
  const pending = [...nodes.values()].map((n) => n.s.origin?.parent);
  while (pending.length) {
    const par = pending.shift();
    if (!par || par === ROOT || nodes.has(par) || !/^https?:/.test(par)) continue;
    const kind = frameSrcs.has(par) || !/\.m?js(\?|$)/.test(par) ? 'iframe document' : 'loader not in inventory';
    const origin = p.loaderOrigins?.[par] || { parent: null };
    nodes.set(par, { s: { url: par, host: (() => { try { return new URL(par).hostname; } catch { return ''; } })(), placeholder: kind, origin }, kids: [] });
    pending.push(origin.parent);
  }
  const roots = { [ROOT]: [], [UNTRACED]: [] };
  for (const [k, n] of nodes) {
    const pk = parentKey(n.s);
    (pk === ROOT || pk === UNTRACED ? roots[pk] : nodes.get(pk).kids).push(k);
  }

  // Keep only nodes that are third-party or have a third-party descendant (cycle-safe).
  const keep = new Map();
  const wanted = (k, seen = new Set()) => {
    if (keep.has(k)) return keep.get(k);
    if (seen.has(k)) return false;
    seen.add(k);
    const n = nodes.get(k);
    const w = (!n.s.inline && !n.s.placeholder && n.s.thirdParty) || n.kids.some((kid) => wanted(kid, seen));
    keep.set(k, w);
    return w;
  };

  const plain = (n) => !n.kids.some((k) => keep.get(k)) && !isNew.has(n.s.url) && !changed.has(n.s.url) && !(n.s.flags || []).length && !isInteractionPhase(n.s.phase);
  const label = (n) => {
    const s = n.s;
    const worst = (s.flags || []).map((f) => f.severity).sort((a, b) => rank.indexOf(a) - rank.indexOf(b))[0];
    const when = phaseTag(s.phase);
    const flagged = worst && c.sev(worst, `FLAGGED ${worst}: ${(s.flags || []).map((f) => f.rule + (f.line ? `@${f.line}:${f.column}` : '')).join(', ')}`);
    const tags = [isNew.has(s.url) && c.yellow('NEW'), changed.has(s.url) && c.yellow('CHANGED'), flagged, when && (isInteractionPhase(s.phase) ? c.yellow(when.toUpperCase()) : c.gray(when))].filter(Boolean);
    const name = s.placeholder ? c.gray(`${s.url} (${s.placeholder})`) : s.inline ? c.gray(`inline script ${s.key}`) : s.thirdParty ? s.url : c.gray(`${s.url} (1st-party)`);
    return name + (tags.length ? '  ' + tags.join(' ') : '');
  };

  const drawn = new Set();
  const draw = (keys, prefix) => {
    const kept = keys.filter((k) => wanted(k) && !drawn.has(k));
    kept.sort((a, b) => {
      const A = nodes.get(a).s, B = nodes.get(b).s;
      return Number(A.inline) - Number(B.inline) || (A.host || '').localeCompare(B.host || '') || a.localeCompare(b);
    });
    // Collapse long runs of plain (untagged, childless) siblings from the same host.
    const items = [];
    for (let i = 0; i < kept.length; ) {
      const n = nodes.get(kept[i]);
      let j = i;
      while (j < kept.length && plain(nodes.get(kept[j])) && nodes.get(kept[j]).s.host === n.s.host && !nodes.get(kept[j]).s.inline) j++;
      if (j - i > COLLAPSE_AFTER) {
        items.push(...kept.slice(i, i + COLLAPSE_AFTER).map((k) => ({ k })));
        items.push({ more: j - i - COLLAPSE_AFTER, host: n.s.host, keys: kept.slice(i + COLLAPSE_AFTER, j) });
        i = j;
      } else {
        items.push({ k: kept[i] });
        i++;
      }
    }
    items.forEach((it, idx) => {
      const last = idx === items.length - 1;
      const branch = c.gray(last ? '└─ ' : '├─ ');
      if (it.more) {
        it.keys.forEach((k) => drawn.add(k));
        lines.push(`${prefix}${branch}${c.gray(`… ${it.more} more from ${it.host}`)}`);
        return;
      }
      drawn.add(it.k);
      const n = nodes.get(it.k);
      lines.push(`${prefix}${branch}${label(n)}`);
      const via = n.s.origin?.via;
      const hasKids = n.kids.some((k) => wanted(k) && !drawn.has(k));
      if (via) lines.push(`${prefix}${c.gray(last ? '   ' : '│  ')}${c.gray((hasKids ? '│' : ' ') + '  ↳ ' + via)}`);
      draw(n.kids, prefix + c.gray(last ? '   ' : '│  '));
    });
  };

  if (roots[ROOT].some((k) => wanted(k))) {
    lines.push(`      ${c.bold('page HTML')}`);
    draw(roots[ROOT], '      ');
  }
  if (roots[UNTRACED].some((k) => wanted(k))) {
    lines.push(`      ${c.bold('loader not traced')} ${c.gray('(browser-internal, eval/dynamic code, or tracing off)')}`);
    draw(roots[UNTRACED], '      ');
  }
  return lines;
}

// Findings for the terminal / CI log (info-level items omitted), spaced into blocks.
export function renderConsole(report, { color = false, showScripts = false, showCookies = false, showStorage = false, showHeaders = false, showHtml = false, htmlExcerpts = new Map(), outDir = 'reports' } = {}) {
  const c = makeColors(color);
  const banner = report.meta?.containsValues ? ['', c.yellow('  ⚠ ' + VALUE_BANNER)] : [];
  banner.unshift('', `  ${consoleName(c)} ${c.gray(`report${VERSION ? ' · v' + VERSION : ''} · ${report.meta?.startedAt || ''}`)}`);
  const width = 72;
  const out = [];
  for (const site of report.sites) {
    const title = ` ${site.name} (${site.mode || 'url'}${site.session === 'site' ? ', shared session' : ''}) `;
    out.push('', c.bold('━━━' + title + '━'.repeat(Math.max(3, width - title.length - 3))));
    const rc = ruleChangeLines(site.rules);
    if (site.auth) out.push('', c.cyan('  ' + authText(site.auth)));
    if (rc.length) out.push('', c.yellow('  Rule changes in effect:'), ...rc.map((l) => c.yellow('    • ' + l)));
    for (const p of site.pages) {
      const real = p.issues.filter((i) => i.severity !== 'info');
      const status = p.error ? c.sev('error', 'ERROR: ' + p.error) : real.length ? c.sev(real[0].severity, `${real.length} finding(s)`) : c.sev('clean', 'clean');
      const onInteract = p.scripts.filter((s) => isInteractionPhase(s.phase)).length;
      out.push('', `${c.bold('●')} ${c.bold(p.url)} ${c.gray('(' + p.profile + ')')} — ${status}${onInteract ? c.yellow(` · ${onInteract} script(s) loaded only after interaction`) : ''}`);
      for (const it of p.interactions || []) {
        if (it.note) out.push(`    ${c.gray('· ' + it.label)}`);
        else out.push(`    ${it.ok ? c.green('✓') : c.yellow('✗')} ${c.gray('step:')} ${it.label}${it.ok ? '' : c.yellow(' — ' + it.error)}${it.navigatedTo ? c.yellow(' → navigated to ' + it.navigatedTo) : ''}`);
      }
      if (p.suppressed?.length) out.push(`    ${c.gray(`${p.suppressed.length} finding(s) suppressed by config: ${p.suppressed.map((i) => ruleOf(i)).join(', ')}`)}`);
      for (const b of p.blockedSubmissions || []) out.push(`    ${c.yellow('⛔ blocked form submission')} ${b.method} ${b.url} ${c.gray('(' + phaseName(b.phase) + ')')}`);
      for (const i of real) {
        out.push('', `    ${c.sev(i.severity, i.severity.toUpperCase().padEnd(6))}  ${c.bold(ruleOf(i))}${i.custom ? c.gray(' (custom)') : ''}${i.originalSeverity ? c.gray(` (was ${i.originalSeverity})`) : ''}  ${i.message}${i.alsoOn ? c.gray(` (also on ${i.alsoOn} other page(s))`) : ''}`);
        const detail = (label, text) => out.push(`            ${c.dim(label.padEnd(10))} ${text}`);
        if (i.script && i.type === 'suspicious-code') detail('in', i.script);
        if (i.line) detail('at', locText(i));
        if (i.match) detail('match', String(i.match).replace(/\s+/g, ' ').slice(0, 120));
        if (i.context) detail('code', c.yellow(String(i.context).slice(0, 160)));
        if (i.origin?.via) detail('via', i.origin.via);
        if (i.phase && i.phase !== 'load') detail('first seen', isInteractionPhase(i.phase) ? c.yellow(phaseName(i.phase)) : phaseName(i.phase));
        if (i.origin?.trail?.length) detail('loaded by', trailText(i.origin));
        if (i.origin?.hint) detail('look', c.gray(i.origin.hint));
        if (['csp-missing', 'csp-weak', 'csp-report-only'].includes(i.type) && site.cspSuggestion) {
          detail('suggest', c.gray(`a starting policy from what this site loaded (${site.cspSuggestion.pages} page(s)):`));
          out.push(`            ${' '.repeat(11)}${c.cyan('Content-Security-Policy-Report-Only:')}`);
          for (const [n, srcs] of site.cspSuggestion.directives) out.push(`            ${' '.repeat(13)}${c.cyan(`${n}${srcs.length ? ' ' + srcs.join(' ') : ''};`)}`);
          for (const note of site.cspSuggestion.notes) out.push(`            ${' '.repeat(11)}${c.gray('• ' + note)}`);
        }
      }
      if (showScripts) out.push(...scriptTreeLines(p, c));
      if (showCookies) out.push(...cookieLines(p, c));
      if (showStorage) out.push(...storageLines(p, c));
      if (showHeaders) out.push(...headerLines(p, c));
      if (showHtml) out.push(...htmlLines(p, c, htmlExcerpts.get(p), outDir));
    }
  }
  out.push('');
  return [...banner, ...out].join('\n');
}
