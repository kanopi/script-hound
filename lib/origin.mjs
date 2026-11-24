// Best-effort provenance: what loaded each script / made each request, and where to look.
//
// Uses a Chrome DevTools Protocol session alongside Playwright:
//   - Network.requestWillBeSent → each request's initiator (parser, or the script stack that made it)
//   - Debugger.scriptParsed     → for scripts created at runtime, the stack that created them
// The debugger runs with breakpoints off and pauses skipped, so `debugger;` traps in page code
// never stall the page (skimmers use them to detect DevTools). Nothing is injected into the page.
import { hostOf, sha256 } from './util.mjs';
import { analyzeCode } from './heuristics.mjs';
import { parseGtmTags, matchGtmTags, containerIdOf } from './gtm.mjs';

const MAX_SOURCE_LOOKUPS = 800;
const MAX_TRAIL = 6;
const isHttp = (u) => /^https?:/i.test(u || '');

const TAG_MANAGERS = [
  { test: (u) => /(^|\.)googletagmanager\.com$/.test(u.hostname) && u.pathname.startsWith('/gtag/'), name: 'Google tag (gtag.js)', look: 'check the Google tag / Ads / Analytics configuration and anything it loads' },
  { test: (u) => /(^|\.)googletagmanager\.com$/.test(u.hostname), name: 'Google Tag Manager', look: 'review its Custom HTML tags, custom templates and recently published versions' },
  { test: (u) => /(^|\.)tiqcdn\.com$/.test(u.hostname), name: 'Tealium iQ', look: 'review its tags and extensions' },
  { test: (u) => /(^|\.)adobedtm\.com$/.test(u.hostname) || /(^|\.)adoberesources\.net$/.test(u.hostname), name: 'Adobe Experience Platform Tags (Launch)', look: 'review its rules and custom code actions' },
  { test: (u) => /(^|\.)segment\.(com|io)$/.test(u.hostname), name: 'Segment', look: 'review its enabled destinations' },
];

function tagManagerOf(url) {
  let u;
  try {
    u = new URL(url);
  } catch {
    return null;
  }
  const tm = TAG_MANAGERS.find((t) => t.test(u));
  if (!tm) return null;
  const id = u.searchParams.get('id');
  return { ...tm, id };
}

// Static and dynamic ES module imports with literal relative/absolute specifiers, resolved to URLs.
// Bounded patterns only (bundles can be several MB).
const IMPORT_RX = [
  /\b(?:import|export)\s*(?:[\w*{}\s,$]{0,500}?\s*from\s*)?["']([^"'\n]{1,300})["']/g,
  /\bimport\(\s*["']([^"'\n]{1,300})["']\s*\)/g,
];
export function moduleImports(code, baseUrl, max = 300) {
  const out = new Set();
  for (const rx of IMPORT_RX) {
    for (const m of code.matchAll(rx)) {
      const spec = m[1];
      if (!/^(\.{1,2}\/|\/|https?:)/.test(spec)) continue; // skip bare specifiers ("react")
      try {
        out.add(new URL(spec, baseUrl).href);
      } catch {}
      if (out.size >= max) return [...out];
    }
  }
  return [...out];
}

/** Attach CDP listeners to a page. Returns null if CDP isn't available. */
export async function startOriginTrace(context, page, getPhase = () => null) {
  let cdp;
  try {
    cdp = await context.newCDPSession(page);
  } catch {
    return null;
  }
  const requests = new Map(); // url -> initiator (first seen)
  const scripts = new Map(); // scriptId -> { url, stackTrace }
  cdp.on('Network.requestWillBeSent', (e) => {
    if (!requests.has(e.request.url)) requests.set(e.request.url, e.initiator);
  });
  // Scripts the scanner itself runs (Playwright's injected helpers and page.evaluate calls) must not be
  // scanned or counted as page eval. They run in an isolated world, or arrive over DevTools with no
  // stack, or are created by one of those. Page code (eval, new Function, injected scripts) runs in
  // the page's default world and is created by page code.
  const ours = new Set();
  const createdBy = (st) => {
    for (let s = st, n = 0; s && n < 20; s = s.parent, n++) for (const f of s.callFrames || []) if (ours.has(f.scriptId)) return true;
    return false;
  };
  cdp.on('Debugger.scriptParsed', (e) => {
    const mine = e.executionContextAuxData?.type === 'isolated' || (e.url === '' && !e.stackTrace) || (e.url === '' && createdBy(e.stackTrace));
    if (mine) {
      ours.add(e.scriptId);
      return;
    }
    if (scripts.size < 20000) scripts.set(e.scriptId, { url: e.url, stackTrace: e.stackTrace || null, phase: getPhase() });
  });
  // Belt and braces: never leave the page paused.
  cdp.on('Debugger.paused', () => cdp.send('Debugger.resume').catch(() => {}));
  // When each localStorage/sessionStorage key was first written (phase: load, form input, a custom step…).
  const storageWrites = new Map();
  const onStorage = (e) => {
    const origin = String(e.storageId?.securityOrigin || e.storageId?.storageKey || '').replace(/\/$/, '');
    const k = `${origin}|${e.storageId?.isLocalStorage ? 'localStorage' : 'sessionStorage'}|${e.key}`;
    if (!storageWrites.has(k)) storageWrites.set(k, getPhase());
  };
  cdp.on('DOMStorage.domStorageItemAdded', onStorage);
  cdp.on('DOMStorage.domStorageItemUpdated', onStorage);
  try {
    await cdp.send('Network.enable');
    await cdp.send('Debugger.enable');
    await cdp.send('Debugger.setBreakpointsActive', { active: false });
    await cdp.send('Debugger.setSkipAllPauses', { skip: true });
    await cdp.send('Debugger.setAsyncCallStackDepth', { maxDepth: 16 });
    await cdp.send('DOMStorage.enable');
  } catch {
    // Partial tracing is still useful; carry on with whatever was enabled.
  }
  return { cdp, requests, scripts, storageWrites };
}

/**
 * Fill in `origin` on result.scripts and result.domains (domains still keyed by host here).
 * Must run before the browser context closes (it reads inline script sources over CDP).
 */
export async function applyOrigins(trace, result, { docUrl, isFirst, rawHtml = null, gtmBodies = new Map(), codeRules = [] }) {
  const inlineEntries = result.scripts.filter((s) => s.inline);
  const idToInline = new Map(); // scriptId -> inline key
  const inlineToId = new Map(); // inline sha256 -> scriptId

  if (trace) {
    // Match runtime scripts to the inline scripts we found in the DOM by hashing their source.
    const wanted = new Set(inlineEntries.map((s) => s.sha256));
    // trace.scripts only holds page code: the scanner's own evaluate helpers are filtered out when
    // parsed (see startOriginTrace).
    const candidates = [...trace.scripts.entries()].filter(([, s]) => s.url === '' || s.url === docUrl).slice(0, MAX_SOURCE_LOOKUPS);
    const dynamic = [];
    await Promise.all(
      candidates.map(async ([id, info]) => {
        const src = await trace.cdp.send('Debugger.getScriptSource', { scriptId: id }).catch(() => null);
        if (!src?.scriptSource) return;
        const h = sha256(src.scriptSource);
        if (!wanted.has(h)) {
          // Code the browser compiled that isn't in the final DOM: eval / new Function / setTimeout(string)
          // output, WebSocket or fetched payloads, or inline scripts that removed themselves after running.
          // Payloads delivered this way never pass through the network as a "script", so this is the only
          // place their code can be checked. Kept only when a rule fires, to avoid noise from routine eval.
          // eval / new Function / setTimeout(string) code (no URL, not an injected inline script in the DOM):
          // counted for the suggested CSP, which would need 'unsafe-eval' to allow it.
          if (info.url === '') result.evalCount = (result.evalCount || 0) + 1;
          if (src.scriptSource.trim().length < 40) return;
          const flags = analyzeCode(src.scriptSource, codeRules);
          if (flags.length) dynamic.push({ id, h, code: src.scriptSource, flags, removed: info.url === docUrl });
          return;
        }
        const entry = inlineEntries.find((s) => s.sha256 === h);
        idToInline.set(id, entry.key);
        if (!inlineToId.has(h)) inlineToId.set(h, id);
      })
    );
    for (const d of dynamic) {
      if (inlineToId.has(d.h)) continue;
      const key = (d.removed ? 'removed#' : 'dynamic#') + d.h.slice(0, 16);
      result.scripts.push({
        key,
        url: d.removed ? '(inline script removed after running)' : '(dynamically created code)',
        host: hostOf(docUrl),
        thirdParty: false,
        inline: true,
        dynamic: true,
        removed: d.removed,
        inHtml: d.removed ? true : false,
        size: d.code.length,
        sha256: d.h,
        preview: d.code.trim().slice(0, 240),
        flags: d.flags,
        phase: trace.scripts.get(d.id)?.phase,
      });
      idToInline.set(d.id, key);
      inlineToId.set(d.h, d.id);
    }
    await trace.cdp.send('Debugger.disable').catch(() => {});
  }

  // A "ref" is one script in a trail: an external URL, a known inline script, or anonymous code.
  const refOf = (frame) => {
    if (frame.url && !isHttp(frame.url)) return { id: frame.url, label: `browser-internal code (${frame.url})` };
    const pos = { line: frame.lineNumber + 1, col: frame.columnNumber + 1 };
    if (frame.url && frame.url !== docUrl) return { id: frame.url, label: `${frame.url}:${pos.line}:${pos.col}`, url: frame.url, ...pos };
    const key = idToInline.get(frame.scriptId);
    if (key) return { id: 's' + frame.scriptId, label: `inline script ${key} (line ${pos.line})`, scriptId: frame.scriptId, inlineKey: key, ...pos };
    if (frame.url === docUrl) return { id: 's' + frame.scriptId, label: `inline script in the page HTML (line ${pos.line})`, scriptId: frame.scriptId, inHtml: true, ...pos };
    return { id: 's' + frame.scriptId, label: 'dynamically created code (eval, new Function or an injected script)', scriptId: frame.scriptId };
  };

  // Distinct scripts on a stack, innermost first, following async parents (setTimeout, promises…).
  const refsOfStack = (stack) => {
    const out = [];
    const seen = new Set();
    for (let s = stack, depth = 0; s && depth < 20; s = s.parent, depth++) {
      for (const f of s.callFrames || []) {
        const r = refOf(f);
        if (!seen.has(r.id)) {
          seen.add(r.id);
          out.push(r);
        }
      }
    }
    return out;
  };

  const fromInitiator = (init) => {
    if (!init) return { unknown: true };
    if (init.type === 'parser' || init.type === 'preload') return { html: true, where: init.url, tag: init.type };
    if (init.stack) {
      const refs = refsOfStack(init.stack);
      if (refs.length) return { refs };
    }
    if (init.url && !isHttp(init.url)) return { unknown: true };
    if (init.url && init.url !== docUrl) return { refs: [{ id: init.url, label: init.url, url: init.url }] };
    if (init.url === docUrl && init.type !== 'other') return { html: true, where: init.url };
    return { unknown: true };
  };

  const loaderOf = (ref) => {
    if (!trace) return { unknown: true };
    if (ref.url) {
      const l = fromInitiator(trace.requests.get(ref.url));
      return l.unknown ? importerOf(ref.url) || l : l;
    }
    const s = trace.scripts.get(ref.scriptId);
    if (!s) return { unknown: true };
    if (s.stackTrace) {
      const refs = refsOfStack(s.stackTrace);
      if (refs.length) return { refs };
    }
    if (s.url === docUrl) return { html: true, where: docUrl };
    return { unknown: true };
  };

  // Walk loader → loader's loader → … until we reach the page HTML or lose the thread.
  const walk = (first) => {
    const steps = [];
    const seen = new Set();
    let loader = first;
    while (steps.length < MAX_TRAIL) {
      if (loader.html) {
        steps.push({ label: loader.where && loader.where !== docUrl ? `HTML of ${loader.where}` : 'page HTML', html: true });
        break;
      }
      if (!loader.refs) break;
      const [top, ...rest] = loader.refs;
      steps.push({ ...top, label: rest.length ? `${top.label}, called from ${rest.map((r) => r.label).join(', ')}` : top.label, chain: loader.refs });
      const next = loader.refs[loader.refs.length - 1];
      if (seen.has(next.id)) break;
      seen.add(next.id);
      loader = loaderOf(next);
    }
    return steps;
  };

  // Direct parent for tree views: "html", a script URL, an inline key, or null (not traced).
  const parentOf = (trail, delivered) => {
    const t = trail[0];
    if (!t) return delivered === 'html' ? 'html' : null;
    if (t.html) return 'html';
    return t.url || t.inlineKey || (t.inHtml ? 'html' : null);
  };

  // How a script got onto the page, in a few words with a location: the "edge label" in tree views.
  const known = new Set(result.scripts.map((s) => s.url));
  function viaOf(s, first, trail) {
    if (first.html) {
      if (s.inline) return `inline <script> in page HTML${s.htmlLine ? `, line ${s.htmlLine}` : ''}`;
      const line = tagLine(rawHtml, s.url, docUrl);
      const tag = first.tag === 'preload' ? '<link rel=preload>' : '<script src>';
      return `${tag} in page HTML${line ? `, line ${line}` : ''}`;
    }
    if (first.module) return `ES module import by ${shortName(first.refs[0].url)}`;
    const t = trail[0];
    if (!t) return null;
    if (t.url && !known.has(t.url) && !/\.m?js(\?|$)/i.test(t.url)) return `loaded inside iframe ${shortName(t.url)}`;
    const verb = s.dynamic ? 'created by' : 'inserted by';
    if (t.url) return `${verb} ${shortName(t.url)}:${t.line}:${t.col}`;
    if (t.inlineKey) return `${verb} inline script ${t.inlineKey}, line ${t.line}`;
    if (t.inHtml) return `${verb} inline <script> in page HTML, line ${t.line}`;
    if (t.html) return null;
    return 'inserted by dynamic code (eval / new Function)';
  }

  // Module graph fallback: Chrome reports statically imported chunks as initiated by "about:client".
  const importers = new Map();
  const noQuery = (u) => u.split(/[?#]/)[0];
  for (const s of result.scripts) {
    for (const u of s.imports || []) {
      if (!importers.has(u)) importers.set(u, s.url);
      if (!importers.has(noQuery(u))) importers.set(noQuery(u), s.url);
    }
  }
  const importerOf = (url) => {
    const by = importers.get(url) || importers.get(noQuery(url));
    return by && by !== url ? { refs: [{ id: by, label: `${by} (ES module import)`, url: by }], module: true } : null;
  };

  const trails = new Map();
  for (const s of result.scripts) {
    let first;
    let delivered = 'unknown';
    if (s.inline) {
      const id = inlineToId.get(s.sha256);
      // When an inline script ran (it's only read from the DOM at the end of the visit).
      if (id && trace.scripts.get(id)?.phase) s.phase = trace.scripts.get(id).phase;
      first = id ? loaderOf({ scriptId: id }) : { unknown: true };
      if (s.inHtml === true) delivered = 'html';
      else if (s.inHtml === false) delivered = 'injected';
      else if (first.html) delivered = 'html';
      else if (first.refs) delivered = 'injected';
      // The raw HTML is the stronger signal for "was this in the server response".
      if (delivered === 'html' && !first.html) first = { html: true, where: docUrl };
      if (delivered === 'injected' && first.html) first = { unknown: true };
    } else {
      first = trace ? fromInitiator(trace.requests.get(s.url)) : { unknown: true };
      if (first.unknown) first = importerOf(s.url) || first;
      delivered = first.html ? 'html' : first.refs ? 'injected' : 'unknown';
    }
    const trail = walk(first);
    trails.set(s, trail);
    s.origin = {
      delivered,
      parent: parentOf(trail, delivered),
      via: viaOf(s, first, trail),
      trail: trail.map((t) => t.label),
      hint: whereToLook({ kind: s.inline ? 'inline' : 'script', url: s.url, delivered, trail, isFirst }),
    };
  }

  // Which GTM tag added it? Direct: the nearest loader is a gtm.js container, so match this script against
  // that container's tags. Inherited: a parent (e.g. a Custom HTML tag's inline script) already matched.
  const containers = new Map();
  for (const [u, body] of gtmBodies) containers.set(u, { id: containerIdOf(u), tags: parseGtmTags(body) });
  if (containers.size) {
    const byKey = new Map(result.scripts.map((s) => [s.inline ? s.key : s.url, s]));
    for (const s of result.scripts) {
      const step = (trails.get(s) || [])[0];
      const gtmRef = (step?.chain || (step ? [step] : [])).find((r) => r.url && containers.has(r.url));
      if (!gtmRef) continue;
      const c = containers.get(gtmRef.url);
      const tags = matchGtmTags(c.tags, s.inline ? { code: s.preview } : { url: s.url });
      s.origin.gtm = { container: c.id, tags };
    }
    for (const s of result.scripts) {
      if (s.origin?.gtm?.tags?.length) continue;
      for (let p = byKey.get(s.origin?.parent), n = 0; p && n < 10; p = byKey.get(p.origin?.parent), n++) {
        if (p.origin?.gtm?.tags?.length) {
          s.origin.gtm = { ...p.origin.gtm, inherited: true };
          break;
        }
      }
    }
    for (const s of result.scripts) {
      const g = s.origin?.gtm;
      if (!g) continue;
      // Lead with the IDs and mark the type as a type: published containers carry no tag names, and
      // "Floodlight Counter (tag ID 14)" read like a name. Same-type candidates are grouped.
      const ids = g.tags.map((t) => t.id);
      const idList = ids.length > 1 ? `${ids.slice(0, -1).join(', ')} or ${ids[ids.length - 1]}` : String(ids[0]);
      const types = [...new Set(g.tags.map((t) => t.type))];
      const tagText = !g.tags.length
        ? 'tag not identified'
        : types.length === 1
          ? `tag ID ${idList} (type: ${types[0]})`
          : g.tags.map((t) => `tag ID ${t.id} (type: ${t.type})`).join(' or ');
      if (s.origin.via) s.origin.via += ` · ${g.container}: ${tagText}${g.inherited ? ' (via its parent)' : ''}`;
      s.origin.hint = g.tags.length
        ? `Added through Google Tag Manager ${g.container}, ${tagText}${ids.length > 1 ? ' (any of these could have loaded it)' : ''}. In GTM, open that container's Tags and find tag ID ${idList} (the number at the end of the tag's URL; tag names aren't published, so the report can't show them). Check its code and recent published versions.`
        : `Added through Google Tag Manager ${g.container}, but no single tag could be matched: review its Custom HTML tags, custom templates and recently published versions.`;
    }
  }

  // Loaders that aren't scripts (mostly iframe documents, e.g. Shopify web-pixel sandboxes): record what
  // created them too, so tree views can hang them in the right place instead of under "not traced".
  result.loaderOrigins = {};
  const pendingLoaders = result.scripts.map((s) => s.origin?.parent);
  while (pendingLoaders.length && Object.keys(result.loaderOrigins).length < 200) {
    const par = pendingLoaders.shift();
    if (!par || !isHttp(par) || known.has(par) || result.loaderOrigins[par]) continue;
    const first = trace ? fromInitiator(trace.requests.get(par)) : { unknown: true };
    const trail = walk(first);
    const parent = parentOf(trail, first.html ? 'html' : 'unknown');
    result.loaderOrigins[par] = { parent, trail: trail.map((t) => t.label) };
    pendingLoaders.push(parent);
  }

  for (const d of Object.values(result.domains)) {
    if (!trace || !d.firstUrl) continue;
    const first = fromInitiator(trace.requests.get(d.firstUrl));
    if (first.unknown) continue;
    const trail = walk(first);
    const delivered = first.html ? 'html' : 'injected';
    d.origin = { request: d.firstUrl, delivered, trail: trail.map((t) => t.label), hint: whereToLook({ kind: 'request', url: d.firstUrl, delivered, trail, isFirst }) };
  }
}

// "gtm.js?id=GTM-ABC" style short name: last path segment plus a trimmed query string.
export function shortName(url) {
  try {
    const u = new URL(url);
    const parts = u.pathname.split('/').filter(Boolean);
    // Very short names ("js" in gtag/js) keep their parent folder so they still mean something.
    const last = parts.length ? (parts[parts.length - 1].length < 4 && parts.length > 1 ? parts.slice(-2).join('/') : parts[parts.length - 1]) : u.hostname;
    return last + (u.search ? (u.search.length > 41 ? u.search.slice(0, 40) + '…' : u.search) : '');
  } catch {
    return url;
  }
}

// Line in the raw HTML of the tag that references a script URL (absolute, root-relative or as written).
function tagLine(rawHtml, url, docUrl) {
  if (!rawHtml || !url) return null;
  let u;
  try {
    u = new URL(url);
  } catch {
    return null;
  }
  const doc = (() => {
    try {
      return new URL(docUrl);
    } catch {
      return null;
    }
  })();
  const candidates = [url, url.replace(/^https?:/, ''), doc && u.origin === doc.origin ? u.pathname + u.search : null, doc && u.origin === doc.origin ? u.pathname : null].filter(Boolean);
  for (const c of candidates) {
    const esc = c.replace(/[.*+?^${}()|[\]\\]/g, '\\$&').replace(/&/g, '(?:&|&amp;)');
    const m = new RegExp(`(?:src|href)\\s*=\\s*["']?${esc}`, 'i').exec(rawHtml);
    if (m) return rawHtml.slice(0, m.index).split('\n').length;
  }
  return null;
}

/** A plain-language pointer for where to start digging. Exported for tests. */
export function whereToLook({ kind, url, delivered, trail, isFirst = () => false }) {
  for (const step of trail) {
    const urls = (step.chain || [step]).map((r) => r.url).filter(Boolean);
    for (const u of urls) {
      const tm = tagManagerOf(u);
      if (tm) return `Loaded through ${tm.name}${tm.id ? ` (${tm.id})` : ''}: ${tm.look}.`;
    }
  }
  const self = kind === 'request' ? 'This request' : kind === 'inline' ? 'This inline script' : 'This script';
  const thirdPartySelf = url && hostOf(url) && !isFirst(hostOf(url));
  if (delivered === 'html') {
    if (kind === 'inline')
      return `${self} is in the HTML the server sent: check theme templates, CMS blocks/content, plugin or module output, and header/footer script settings stored in the database.`;
    if (kind === 'request') return `${self} is made directly by the page HTML (a tag in the markup): find the template, block or plugin that outputs it.`;
    return thirdPartySelf
      ? `${self} is a third-party <script> tag in the server's HTML: find the template, plugin or setting that adds it.`
      : `${self} is referenced in the server's HTML and served from this site: compare the file on disk with the deployed version and find what enqueues it.`;
  }
  const first = trail[0];
  if (!first) return null;
  if (first.url) {
    const h = hostOf(first.url);
    return isFirst(h)
      ? `${self} was added at runtime by a first-party script (${first.url}): inspect that file and its modification history.`
      : `${self} was added at runtime by a third-party script from ${h}: find which tag, plugin or embed loads that vendor.`;
  }
  if (first.inHtml || trail[1]?.html)
    return `${self} was added at runtime by an inline script in the page HTML: find that inline block in templates or CMS script settings.`;
  return `${self} was created by dynamically generated code: follow the trail to the script that generated it.`;
}
