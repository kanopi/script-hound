import fs from 'node:fs';
import { devices } from 'playwright';
import { analyzeCode } from './heuristics.mjs';
import { startOriginTrace, applyOrigins, moduleImports } from './origin.mjs';
import { runInteractions, startSubmissionGuard } from './interactions.mjs';
import { detectVulnerableLibraries } from './vulndb.mjs';
import { POSTURE_HEADERS } from './posture.mjs';
import { analyzeCss } from './css.mjs';
import { collectStorage, classify, preview, findDummyCard, DUMMY_CARD, looksLikeCode, decodeBase64Text } from './storage.mjs';
import { sha256, hostOf, rootDomain, hostMatches, scriptKey, normalizeInline } from './util.mjs';

// Skimmers often hide from obvious bots, so present as a normal browser. The default user agent uses
// the real engine's major version (browserMajor), so the UA, the client hints and the actual feature
// set all agree. Chrome reduces UA strings to "<major>.0.0.0", so that's what real browsers send.
const desktopUA = (major) => `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${major}.0.0.0 Safari/537.36`;
const mobileUA = (major) => `Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${major}.0.0.0 Mobile Safari/537.36`;
const FALLBACK_MAJOR = 142; // only when the browser version isn't known (e.g. sitemap fetches)

// userAgent: optional override, either a string or { desktop, mobile } keyed by profile.
export function contextOptions(profile, userAgent, browserMajor = FALLBACK_MAJOR) {
  const ua = typeof userAgent === 'string' ? userAgent : userAgent?.[profile];
  const base =
    profile === 'mobile'
      ? { ...devices['Pixel 7'], userAgent: mobileUA(browserMajor), locale: 'en-US' }
      : { userAgent: desktopUA(browserMajor), viewport: { width: 1366, height: 900 }, locale: 'en-US' };
  return ua ? { ...base, userAgent: ua } : base;
}

/**
 * Make the User-Agent Client Hints (sec-ch-ua* headers and navigator.userAgentData) agree with the
 * user agent. Without this, headless Chromium announces "HeadlessChrome" in sec-ch-ua even when the
 * UA string says Chrome, which bot-detection services and some skimmers check.
 */
export function uaMetadata(ua) {
  const chrome = /(?:Chrome|CriOS)\/(\d+)/.exec(ua);
  const major = chrome ? chrome[1] : null;
  const mobile = /Mobile|Android|iPhone/i.test(ua);
  const platform = /Android/i.test(ua) ? 'Android' : /iPhone|iPad/i.test(ua) ? 'iOS' : /Mac OS X|Macintosh/i.test(ua) ? 'macOS' : /Linux/i.test(ua) ? 'Linux' : 'Windows';
  const platformVersion = platform === 'Windows' ? '10.0.0' : platform === 'Android' ? '10.0.0' : platform === 'macOS' ? '14.0.0' : '';
  // Not a Chromium UA (e.g. a custom Firefox/Safari string): send no brands rather than contradict it.
  const brands = major
    ? [
        { brand: 'Google Chrome', version: major },
        { brand: 'Chromium', version: major },
        { brand: 'Not_A Brand', version: '24' },
      ]
    : [];
  return {
    brands,
    fullVersionList: brands.map((b) => ({ brand: b.brand, version: b.brand === 'Not_A Brand' ? '24.0.0.0' : `${major}.0.0.0` })),
    fullVersion: major ? `${major}.0.0.0` : '',
    platform,
    platformVersion,
    architecture: mobile ? '' : 'x86',
    model: /Android/i.test(ua) ? 'K' : '',
    mobile,
    bitness: mobile ? '' : '64',
    wow64: false,
  };
}

async function applyUaOverride(context, page, ua) {
  try {
    const s = await context.newCDPSession(page);
    await s.send('Emulation.setUserAgentOverride', { userAgent: ua, acceptLanguage: 'en-US,en', userAgentMetadata: uaMetadata(ua) });
  } catch {
    // CDP unavailable: Playwright's own UA override still applies
  }
}

function dummyValue(hint) {
  if (/cvv|cvc|security|csc/i.test(hint)) return '123';
  if (/card|cc[-_]?num|ccnum|pan\b/i.test(hint)) return DUMMY_CARD;
  if (/exp/i.test(hint)) return '12/30';
  if (/mail/i.test(hint)) return 'scripthound@example.invalid';
  if (/zip|postal/i.test(hint)) return '97201';
  if (/phone|tel/i.test(hint)) return '5035550100';
  if (/pass/i.test(hint)) return 'NotARealPassword1!';
  return 'ScriptHound test';
}

async function exerciseForms(page) {
  const fields = page.locator(
    'input:visible:not([type=hidden]):not([type=submit]):not([type=button]):not([type=checkbox]):not([type=radio]):not([type=file]):not([type=search]), textarea:visible'
  );
  const n = Math.min(await fields.count(), 12);
  let typed = false;
  for (let i = 0; i < n; i++) {
    const f = fields.nth(i);
    const hint = await f.evaluate((el) => [el.name, el.id, el.type, el.placeholder, el.autocomplete, el.getAttribute('aria-label')].join(' '));
    const val = dummyValue(hint);
    // Type one card-like field key by key so keyloggers see real key events.
    if (!typed && /card|cc|cvv|pass/i.test(hint)) {
      await f.click({ timeout: 2000 });
      await f.pressSequentially(val, { delay: 15, timeout: 5000 });
      typed = true;
    } else {
      await f.fill(val, { timeout: 2000 });
    }
    await f.evaluate((el) => {
      el.dispatchEvent(new Event('change', { bubbles: true }));
      el.dispatchEvent(new Event('blur', { bubbles: true }));
      el.blur();
    });
  }
}

const lineAt = (text, index) => text.slice(0, index).split('\n').length;

async function domXssCanary(context, url, opts) {
  const id = 'sh' + Math.random().toString(36).slice(2, 10);
  const payload = `"'><scripthound-canary id="${id}"></scripthound-canary>`;
  const probe = await context.newPage();
  if (opts._ua) await applyUaOverride(context, probe, opts._ua);
  try {
    const base = url.split('#')[0];
    await probe.goto(`${base}#${payload}`, { waitUntil: 'load', timeout: opts.timeoutMs });
    await probe.waitForTimeout(1500);
    // Also set it after load, for hash-router code that only reacts to hashchange.
    await probe.evaluate((p) => {
      location.hash = p;
    }, payload);
    await probe.waitForTimeout(1000);
    return await probe.evaluate((cid) => {
      const el = document.getElementById(cid);
      if (!el) return { reflected: false };
      const parent = el.parentElement;
      return { reflected: true, where: parent ? `<${parent.tagName.toLowerCase()}${parent.id ? ' id="' + parent.id + '"' : ''}${parent.className && typeof parent.className === 'string' ? ' class="' + parent.className.slice(0, 60) + '"' : ''}>` : '' };
    }, id);
  } finally {
    await probe.close().catch(() => {});
  }
}

/**
 * Load one URL and inventory everything that runs in the browser.
 */
export async function scanPage(browser, { url, profile, firstParty, opts }) {
  // Authenticated scans (opts.auth from sites.json / CLI): a saved Playwright storage state, extra
  // cookies, and extra headers. Values never go into the report.
  const auth = opts.auth || {};
  // Session "site": the previous page's cookies/storage (opts.carriedState) replace a fresh start.
  const startState = opts.carriedState || auth.storageState || null;
  const context = await browser.newContext({
    ...contextOptions(profile, opts.userAgent, Number(browser.version().split('.')[0]) || undefined),
    ignoreHTTPSErrors: !!opts.ignoreTLS,
    ...(startState ? { storageState: startState } : {}),
  });
  const host = new URL(url).hostname;
  // Label cookies the visit didn't create: yours (--cookie/config), a cookie jar file, or (below)
  // carried over from an earlier page.
  const presetLabel = new Map();
  const authCookies = (auth.cookies || []).map(({ _source, ...c }) => {
    const ck = { path: '/', secure: url.startsWith('https:'), ...c, domain: c.domain || host };
    presetLabel.set(`${ck.domain}|${ck.name}`, _source || 'you (auth)');
    return ck;
  });
  if (authCookies.length) await context.addCookies(authCookies);
  if (auth.storageState) {
    try {
      for (const c of JSON.parse(fs.readFileSync(auth.storageState, 'utf8')).cookies || []) presetLabel.set(`${c.domain}|${c.name}`, 'you (auth)');
    } catch {
      // unreadable file: Playwright already reported it when creating the context
    }
  }
  const carriedKeys = new Set((opts.carriedState?.cookies || []).map((c) => `${c.domain}|${c.name}`));
  // Extra headers go ONLY to the site's own hosts. Sending an Authorization header to every
  // third-party script, tracker and ad server on the page would leak it.
  if (auth.headers && Object.keys(auth.headers).length) {
    await context.route(
      (u) => hostMatches(u.hostname, firstParty),
      (route) => route.continue({ headers: { ...route.request().headers(), ...auth.headers } })
    );
  }
  const page = await context.newPage();
  const effectiveUA = contextOptions(profile, opts.userAgent, Number(browser.version().split('.')[0]) || undefined).userAgent;
  await applyUaOverride(context, page, effectiveUA);
  opts = { ...opts, _ua: effectiveUA };
  const isFirst = (host) => hostMatches(host, firstParty);

  const result = {
    url,
    profile,
    finalUrl: null,
    status: null,
    error: null,
    scripts: [],
    domains: {},
    websockets: [],
    workers: [],
    iframes: [],
    forms: [],
    metaRefresh: null,
    inlineHandlers: [],
    interactions: [],
    blockedSubmissions: [],
    // Security posture (lib/posture.mjs)
    docHeaders: {},
    metaCsp: null,
    scriptTags: [],
    paymentPage: false,
    mixed: [],
    cookies: [],
    storageTokens: [],
    canary: null,
    // Browser storage (lib/storage.mjs): previews only, never full values
    storage: [],
    indexedDB: [],
    cacheStorage: [],
    serviceWorkers: [],
    cardDataFound: [],
    stylesheets: [], // external and inline CSS: hash + CSS rule flags (lib/css.mjs)
    windowName: null,
    historyState: null,
    storageBuckets: [],
    storageFindings: [], // pattern-rule hits and code found inside storage values / IndexedDB records
    opfs: [],
    storageUsage: [],
    webSql: false,
  };
  const httpsPage = /^https:/i.test(url);

  const pending = [];
  // Which part of the visit is running. Every script/domain records the phase it first appeared in,
  // so payloads that only load on scroll or typing stand out. See PHASES in lib/util.mjs.
  let phase = 'load';
  const reqPhase = new WeakMap();
  // Provenance tracing (what loaded what). On by default; "traceOrigins": false turns it off.
  const trace = opts.traceOrigins !== false ? await startOriginTrace(context, page, () => phase) : null;
  // Never let anything (built-in or custom interactions, or page code) submit a form.
  await startSubmissionGuard(context, page, () => phase, result.blockedSubmissions);
  let rawHtml = null;
  let renderedHtml = null;
  let docUrl = url;
  // GTM container bodies (gtm.js?id=…), kept only to work out which tag added a script.
  const gtmBodies = new Map();

  page.on('request', (req) => {
    const host = hostOf(req.url());
    reqPhase.set(req, phase);
    if (httpsPage && /^http:/i.test(req.url()) && result.mixed.length < 50) result.mixed.push({ url: req.url(), type: req.resourceType() });
    if (!host || req.url().startsWith('data:')) return;
    const d = (result.domains[host] ||= { host, root: rootDomain(host), thirdParty: !isFirst(host), types: new Set(), count: 0, firstUrl: req.url(), phase, sources: {} });
    d.types.add(req.resourceType());
    d.count++;
    // Origin (scheme://host:port) per request type, for the suggested CSP (lib/csp.mjs).
    try {
      const o = new URL(req.url()).origin;
      (d.sources[req.resourceType()] ||= new Set()).add(o);
    } catch {
      // not a URL with an origin
    }
  });

  // Which hosts set which cookies over HTTP (Set-Cookie). Anything in the jar that no response set
  // was written by JavaScript (document.cookie): trackers, consent tools, or a skimmer.
  const serverSet = new Set();
  page.on('response', (res) => {
    pending.push(
      res
        .headerValue('set-cookie')
        .then((v) => {
          if (v) for (const line of v.split('\n')) serverSet.add(`${hostOf(res.url())}|${line.split('=')[0].trim()}`);
        })
        .catch(() => {})
    );
  });

  // Stylesheets: hash for change detection and CSS rules (keyloggers, hidden payloads, script URLs).
  page.on('response', (res) => {
    if (res.request().resourceType() !== 'stylesheet') return;
    const cUrl = res.url();
    if (!/^https?:/.test(cUrl)) return;
    pending.push(
      res
        .body()
        .then((b) => {
          const css = b.toString('utf8');
          const host = hostOf(cUrl);
          result.stylesheets.push({ key: scriptKey(cUrl), url: cUrl, host, thirdParty: !isFirst(host), inline: false, size: css.length, sha256: sha256(css), flags: analyzeCss(css, opts.cssRules), phase: reqPhase.get(res.request()) || phase });
        })
        .catch(() => {})
    );
  });

  page.on('response', (res) => {
    const req = res.request();
    if (req.resourceType() !== 'script') return;
    const sUrl = res.url();
    if (sUrl.startsWith('data:') || sUrl.startsWith('blob:')) return;
    pending.push(
      (async () => {
        const host = hostOf(sUrl);
        const entry = { key: scriptKey(sUrl), url: sUrl, host, thirdParty: !isFirst(host), status: res.status(), inline: false, phase: reqPhase.get(req) || phase };
        try {
          const body = (await res.body()).toString('utf8');
          entry.size = body.length;
          entry.sha256 = sha256(body);
          entry.flags = analyzeCode(body, opts.codeRules);
          if (/googletagmanager\.com\/gtm\.js\?/.test(sUrl)) gtmBodies.set(sUrl, body);
          const libs = detectVulnerableLibraries({ url: sUrl, code: body });
          if (libs.length) entry.libs = libs;
          // ES module import targets, so chunks Chrome attributes to "about:client" can be linked to their importer.
          const imports = moduleImports(body, sUrl);
          if (imports.length) entry.imports = imports;
        } catch (e) {
          entry.error = 'body unavailable (' + (e.message || e).toString().slice(0, 80) + ')';
          entry.flags = [];
        }
        result.scripts.push(entry);
      })()
    );
  });

  page.on('websocket', (ws) => {
    result.websockets.push({ url: ws.url(), host: hostOf(ws.url()), thirdParty: !isFirst(hostOf(ws.url())) });
    if (httpsPage && /^ws:/i.test(ws.url())) result.mixed.push({ url: ws.url(), type: 'websocket' });
  });
  page.on('worker', (w) => result.workers.push({ url: w.url() }));

  try {
    const resp = await page.goto(url, { waitUntil: 'load', timeout: opts.timeoutMs });
    result.status = resp ? resp.status() : null;
    if (resp) {
      docUrl = resp.url();
      const h = await resp.allHeaders().catch(() => resp.headers());
      for (const k of POSTURE_HEADERS) if (h[k]) result.docHeaders[k] = h[k];
      // Full header lists for the main document (--show-headers, and on record in the reports).
      // Secrets are masked: cookie values unless --show-values, and headers you supplied always.
      const supplied = new Set(Object.keys(auth.headers || {}).map((k) => k.toLowerCase()));
      const maskCookie = (v) => (opts.showValues ? v : v.replace(/^([^=;]+)=[^;]*/, '$1=••••'));
      // Cookies you supplied (--cookie, jars, storage state) stay masked even with --show-values.
      const suppliedCookies = new Set([...presetLabel.keys()].map((k) => k.split('|').slice(1).join('|')));
      const maskCookieHeader = (v) =>
        v
          .split(/;\s*/)
          .map((pair) => {
            const name = pair.split('=')[0];
            return opts.showValues && !suppliedCookies.has(name) ? pair : `${name}=••••`;
          })
          .join('; ');
      result.responseStatus = resp.status();
      result.responseHeaders = (await resp.headersArray().catch(() => Object.entries(h).map(([name, value]) => ({ name, value })))).map(({ name, value }) => ({
        name,
        value: name.toLowerCase() === 'set-cookie' ? maskCookie(value) : value,
      }));
      const reqH = await resp.request().allHeaders().catch(() => ({}));
      result.requestHeaders = Object.entries(reqH).map(([name, value]) => ({
        name,
        value: supplied.has(name.toLowerCase()) ? '•••• (supplied by you, not shown)' : name.toLowerCase() === 'cookie' ? maskCookieHeader(value) : /^(authorization|proxy-authorization)$/i.test(name) && !opts.showValues ? '••••' : value,
      }));
      // Keep the HTML exactly as the server sent it, to tell server-sent inline scripts from injected ones.
      if (/html/i.test(resp.headers()['content-type'] || '')) rawHtml = await resp.text().then((t) => t.replace(/\r\n?/g, '\n')).catch(() => null);
    }
    await page.waitForLoadState('networkidle', { timeout: 10000 }).catch(() => {});

    // Idle before touching anything, so timer-delayed loads aren't blamed on the interactions below.
    phase = 'idle';
    await page.waitForTimeout(opts.idleBeforeInteractMs ?? 2000);

    // Some payloads only fire after interaction or a delay.
    phase = 'mouse';
    await page.mouse.move(200, 300).catch(() => {});
    await page.mouse.move(600, 500, { steps: 8 }).catch(() => {});
    phase = 'scroll';
    await page.evaluate(async () => {
      for (let y = 0; y < document.body.scrollHeight; y += 600) {
        window.scrollTo(0, y);
        await new Promise((r) => setTimeout(r, 150));
      }
      window.scrollTo(0, 0);
    }).catch(() => {});
    // Many skimmers only fire when a card/credential field is typed into or blurred.
    // Fill visible fields with dummy data (never submits).
    phase = 'form-input';
    if (opts.exerciseForms !== false) await exerciseForms(page).catch(() => {});

    // Site-specific interaction steps / scripts from sites.json. Each step is its own phase.
    if (opts.interactions?.length) {
      result.interactions = await runInteractions(page, opts.interactions, { url, profile, setPhase: (p) => (phase = p) });
    }

    phase = 'after-interaction';
    await page.waitForTimeout(opts.waitMs);
    phase = 'inventory';

    result.finalUrl = page.url();
    if (opts.captureHtml) renderedHtml = await page.content().catch(() => null);

    const dom = await page.evaluate((collectLinks) => {
      const JS_TYPES = ['', 'text/javascript', 'application/javascript', 'module', 'text/ecmascript', 'application/ecmascript'];
      const inline = [...document.querySelectorAll('script:not([src])')]
        .filter((s) => JS_TYPES.includes((s.type || '').toLowerCase()))
        .map((s) => s.textContent || '')
        .filter((t) => t.trim().length > 0);

      const iframes = [...document.querySelectorAll('iframe')].map((f) => {
        const r = f.getBoundingClientRect();
        const cs = getComputedStyle(f);
        return {
          src: f.src || '(srcdoc/blank)',
          hidden: r.width <= 2 || r.height <= 2 || cs.display === 'none' || cs.visibility === 'hidden' || cs.opacity === '0',
        };
      });

      const forms = [...document.querySelectorAll('form')].map((f) => ({ action: f.action || '', method: (f.method || 'get').toLowerCase() }));

      const meta = document.querySelector('meta[http-equiv="refresh" i]');

      // on* attributes carrying more than trivial code
      const handlers = [];
      for (const el of document.querySelectorAll('*')) {
        for (const a of el.attributes) {
          if (/^on/i.test(a.name) && /(atob|eval|fromCharCode|createElement\(['"]script|\\x[0-9a-f]{2})/i.test(a.value)) {
            handlers.push({ tag: el.tagName.toLowerCase(), attr: a.name, value: a.value.slice(0, 200) });
          }
        }
        if (handlers.length > 20) break;
      }
      const jsLinks = [...document.querySelectorAll('a[href^="javascript:" i]')]
        .map((a) => a.getAttribute('href'))
        .filter((h) => /(atob|eval|fromCharCode)/i.test(h))
        .slice(0, 10)
        .map((h) => ({ tag: 'a', attr: 'href', value: h.slice(0, 200) }));

      // Crawl mode: same-page links (filtered for scope in scan.mjs). Reading hrefs only; nothing is clicked.
      const links = collectLinks ? [...document.querySelectorAll('a[href]')].slice(0, 3000).map((a) => a.href) : [];

      // Posture: CSP <meta>, script tags with their integrity attribute, payment-page signals, and
      // token-shaped values in browser storage (key names only leave the page, never values).
      const metaCsp = document.querySelector('meta[http-equiv="Content-Security-Policy" i]')?.getAttribute('content') || null;
      const inlineStyles = [...document.querySelectorAll('style')].map((s) => s.textContent || '').filter((t) => t.trim().length > 0).slice(0, 200);
      const scriptTags = [...document.querySelectorAll('script[src]')].map((s) => ({ src: s.src, integrity: s.getAttribute('integrity') || '', crossorigin: s.getAttribute('crossorigin') }));
      const cardField = [...document.querySelectorAll('input')].some((i) => /^cc-/.test(i.autocomplete || '') || /card.?num|cc.?num|cvv|cvc|cc_cid|security.?code/i.test(`${i.name} ${i.id}`));
      const pspFrame = [...document.querySelectorAll('iframe')].some((f) => /(js\.stripe\.com|braintreegateway\.com|paypal\.com|adyen\.com|squareup\.com|checkout\.com|authorize\.net|worldpay\.com|razorpay\.com|mollie\.com)/i.test(f.src || ''));
      const paymentPage = cardField || pspFrame || /\/(checkout|payment|pay|donate)(\/|$|\?)/i.test(location.pathname);
      const storageTokens = [];
      for (const [name, store] of [['localStorage', () => window.localStorage], ['sessionStorage', () => window.sessionStorage]]) {
        try {
          const st = store();
          for (let k = 0; k < Math.min(st.length, 200); k++) {
            const key = st.key(k);
            const v = String(st.getItem(key) || '');
            if (/^(Bearer\s+)?eyJ[\w-]{8,}\.eyJ[\w-]{8,}\.[\w-]*$/.test(v.trim()) || (/(access|id|refresh|auth|bearer)[-_.]?token|jwt/i.test(key) && v.length >= 20)) storageTokens.push({ store: name, key });
          }
        } catch {
          // storage blocked
        }
      }

      return { inline, iframes, forms, meta: meta ? meta.getAttribute('content') : null, handlers: handlers.concat(jsLinks), links, metaCsp, scriptTags, paymentPage, storageTokens, inlineStyles };
    }, !!opts.collectLinks);

    for (const code of dom.inline) {
      result.scripts.push({
        key: 'inline#' + sha256(normalizeInline(code)).slice(0, 16),
        url: '(inline)',
        host: hostOf(result.finalUrl),
        thirdParty: false,
        inline: true,
        size: code.length,
        sha256: sha256(code),
        preview: code.trim().slice(0, 240),
        // true = present in the server's HTML response; false = added at runtime; null = unknown
        inHtml: rawHtml == null ? null : rawHtml.includes(code),
        // Line in the page HTML where this inline script's code starts (server-sent ones only).
        htmlLine: rawHtml != null && rawHtml.includes(code) ? lineAt(rawHtml, rawHtml.indexOf(code)) : undefined,
        flags: analyzeCode(code, opts.codeRules),
        ...(() => {
          const libs = detectVulnerableLibraries({ code });
          return libs.length ? { libs } : {};
        })(),
      });
    }

    result.iframes = dom.iframes.map((f) => ({ ...f, host: hostOf(f.src), thirdParty: hostOf(f.src) ? !isFirst(hostOf(f.src)) : false }));
    result.forms = dom.forms.map((f) => ({ ...f, host: hostOf(f.action), thirdParty: hostOf(f.action) ? !isFirst(hostOf(f.action)) : false }));
    result.metaRefresh = dom.meta;
    result.inlineHandlers = dom.handlers;
    if (opts.collectLinks) result.links = dom.links;
    Object.assign(result, { metaCsp: dom.metaCsp, scriptTags: dom.scriptTags, paymentPage: dom.paymentPage, storageTokens: dom.storageTokens });
    for (const css of dom.inlineStyles || []) {
      result.stylesheets.push({ key: 'inline-style#' + sha256(normalizeInline(css)).slice(0, 16), url: '(inline <style>)', host: hostOf(docUrl), thirdParty: false, inline: true, size: css.length, sha256: sha256(css), flags: analyzeCss(css, opts.cssRules), preview: css.trim().slice(0, 160) });
    }

    // Storage inventory for the page and its iframes. Values stay in memory: they're classified,
    // previewed (masked) and searched for the dummy card number, then dropped.
    const st = await collectStorage(page).catch(() => null);
    // Check one stored value: card honeytoken, pattern rules (also on base64-decoded text), and
    // whether it's JavaScript sitting in storage (a known way to persist a payload across visits).
    // codeExpected: Cache Storage and service-worker scripts hold code legitimately, so they only get the
    // pattern rules, not the "code in storage" note. css: also run the CSS rules (cached stylesheets).
    const inspect = (value, where, { codeExpected = false, css = false } = {}) => {
      if (!value) return;
      const found = findDummyCard(value);
      if (found) result.cardDataFound.push({ ...where, encoding: found });
      const decoded = decodeBase64Text(value);
      for (const [text, viaBase64] of [[value, false], ...(decoded ? [[decoded, true]] : [])]) {
        const flags = [...analyzeCode(text, opts.codeRules), ...(css ? analyzeCss(text, opts.cssRules) : [])];
        if (flags.length) result.storageFindings.push({ ...where, flags, decoded: viaBase64 });
        if (!codeExpected && looksLikeCode(text)) result.storageFindings.push({ ...where, code: true, decoded: viaBase64, preview: text.replace(/\s+/g, ' ').slice(0, 160) });
      }
    };
    if (st) {
      for (const e of st.entries) {
        const kind = classify(e.value);
        inspect(e.value, { where: e.type, origin: e.origin, key: e.key });
        result.storage.push({
          origin: e.origin,
          thirdParty: !isFirst(hostOf(e.origin)),
          type: e.type,
          key: e.key,
          size: e.size,
          kind,
          preview: preview(e.value, kind),
          firstWritten: trace?.storageWrites?.get(`${e.origin}|${e.type}|${e.key}`) || null,
          ...(opts.showValues ? { value: e.value } : {}),
        });
      }
      for (const d of st.indexedDB) for (const s of d.stores) for (const v of s.samples || []) inspect(v, { where: 'IndexedDB', origin: d.origin, key: `${d.name}/${s.name}` });
      result.indexedDB = st.indexedDB.map((d) => ({
        ...d,
        thirdParty: !isFirst(hostOf(d.origin)),
        // Sampled records only with --show-values; otherwise just store names and counts.
        stores: d.stores.map(({ samples, ...s }) => (opts.showValues ? { ...s, samples } : s)),
      }));
      // Everything else a page can read back: cached responses, service-worker code, OPFS files,
      // window.name and history.state.
      for (const b of st.cacheBodies) inspect(b.body, { where: 'Cache Storage', origin: b.origin, key: `${b.cache} ${b.url}` }, { codeExpected: true, css: /css/.test(b.type) || /\.css(\?|$)/i.test(b.url) });
      for (const w of st.serviceWorkers) inspect(w.code, { where: 'service worker', origin: hostOf(w.scriptURL) ? new URL(w.scriptURL).origin : '', key: w.scriptURL }, { codeExpected: true });
      for (const f of st.opfs) if (f.text) inspect(f.text, { where: 'OPFS file', origin: f.origin, key: f.path });
      for (const n of st.windowName) inspect(n.value, { where: 'window.name', origin: n.origin, key: 'window.name' });
      for (const h of st.historyState) inspect(h.value, { where: 'history.state', origin: h.origin, key: 'history.state' });
      result.opfs = st.opfs.map(({ text, ...f }) => f);
      result.serviceWorkers = st.serviceWorkers.map(({ code, ...w }) => ({ ...w, size: code ? code.length : null }));
      result.storageBuckets = st.buckets;
      const top = st.windowName.find((n) => n.origin === new URL(docUrl).origin);
      if (top) result.windowName = { size: top.value.length, kind: classify(top.value), preview: preview(top.value, classify(top.value)), ...(opts.showValues ? { value: top.value } : {}) };
      const hs = st.historyState.find((n) => n.origin === new URL(docUrl).origin);
      if (hs) result.historyState = { size: hs.value.length, preview: preview(hs.value, classify(hs.value)), ...(opts.showValues ? { value: hs.value } : {}) };
      result.storageUsage = st.usage;
      result.webSql = st.webSql;
      result.cacheStorage = st.caches;
    }
  } catch (e) {
    result.error = (e.message || String(e)).split('\n')[0];
  }

  await Promise.allSettled(pending);
  // Cookie inventory: every cookie in the browser after the visit, with flags and who set it.
  // Names and flags only; values never leave the browser.
  const setByServer = (c) => [...serverSet].some((k) => {
    const [h, n] = k.split('|');
    return n === c.name && (h === c.domain.replace(/^\./, '') || h.endsWith(c.domain.startsWith('.') ? c.domain : '.' + c.domain) || c.domain.replace(/^\./, '').endsWith(h));
  });
  result.cookies = await context
    .cookies()
    .then((cs) => {
      // Honeytoken check on cookie values too, before the values are dropped.
      for (const c of cs) {
        const found = findDummyCard(c.value);
        if (found) result.cardDataFound.push({ where: 'cookie', origin: c.domain, key: c.name, encoding: found });
        let cv = c.value;
        try {
          cv = decodeURIComponent(c.value);
        } catch {
          // keep raw
        }
        const flags = analyzeCode(cv, opts.codeRules);
        if (flags.length) result.storageFindings.push({ where: 'cookie', origin: c.domain, key: c.name, flags });
        const dec = decodeBase64Text(cv);
        if (looksLikeCode(cv) || (dec && looksLikeCode(dec))) result.storageFindings.push({ where: 'cookie', origin: c.domain, key: c.name, code: true, decoded: !looksLikeCode(cv), preview: (looksLikeCode(cv) ? cv : dec).replace(/\s+/g, ' ').slice(0, 160) });
        // --show-values keeps cookie values, except ones you supplied (auth / cookie jar), which stay masked.
        if (opts.showValues) c._value = presetLabel.has(`${c.domain}|${c.name}`) ? '•••• (supplied by you, not shown)' : c.value;
      }
      return cs;
    })
    .then((cs) =>
      cs.map((c) => ({
        name: c.name,
        domain: c.domain,
        path: c.path,
        thirdParty: !isFirst(c.domain.replace(/^\./, '')),
        httpOnly: c.httpOnly,
        secure: c.secure,
        sameSite: c.sameSite,
        session: c.expires === -1,
        expiresDays: c.expires > 0 ? Math.round((c.expires * 1000 - Date.now()) / 86400000) : null,
        ...(c._value !== undefined ? { value: c._value } : {}),
        setBy: presetLabel.get(`${c.domain}|${c.name}`) || (setByServer(c) ? 'server' : carriedKeys.has(`${c.domain}|${c.name}`) ? 'earlier page' : c.httpOnly ? 'server' : 'javascript'),
      }))
    )
    .catch(() => []);
  result.authenticated = !!(auth.storageState || auth.cookies?.length || (auth.headers && Object.keys(auth.headers).length));
  result.sharedSession = !!opts.keepState;
  // Opt-in DOM-XSS canary: a separate load with an inert custom element in the URL fragment (#…). The
  // fragment is never sent to the server; we only check whether page scripts write it into the DOM.
  if (opts.domXssCanary && !result.error) result.canary = await domXssCanary(context, docUrl, opts).catch((e) => ({ error: String(e.message || e).slice(0, 120) }));
  // Session "site": hand this visit's cookies + localStorage to the next page (not kept in reports).
  if (opts.keepState) result.storageState = await context.storageState().catch(() => null);
  // --cookie-jar: full cookies, values included, for the jar file only (scan.mjs removes this before reporting).
  if (opts.collectJar) result.jar = await context.cookies().catch(() => []);
  // --show-html: the HTML as the server sent it and the rendered DOM after scripts ran. scan.mjs writes
  // them to files and removes the strings before reporting.
  if (opts.captureHtml) result.htmlCapture = { server: rawHtml, rendered: renderedHtml };
  // Custom "html" rules run against the HTML exactly as the server sent it.
  if (rawHtml && opts.htmlRules?.length) {
    result.htmlHits = [];
    for (const r of opts.htmlRules) {
      const hit = r.test(rawHtml);
      if (hit) result.htmlHits.push({ rule: r.id, severity: r.severity, description: r.description, match: hit.match, line: lineAt(rawHtml, hit.index) });
    }
  }
  await applyOrigins(trace, result, { docUrl, isFirst, rawHtml, gtmBodies, codeRules: opts.codeRules }).catch((e) => {
    result.originError = String(e?.message || e).slice(0, 200);
  });
  await context.close();

  result.domains = Object.values(result.domains).map(({ firstUrl, ...d }) => ({ ...d, types: [...d.types].sort(), sources: Object.fromEntries(Object.entries(d.sources).map(([t, set]) => [t, [...set]])) }));
  // De-duplicate scripts loaded more than once
  const seen = new Set();
  result.scripts = result.scripts.filter((s) => {
    const k = s.key + '|' + s.sha256;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
  return result;
}
