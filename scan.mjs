#!/usr/bin/env node
/**
 * ScriptHound: sniffs out malicious front-end code. Run `./scan --help` for every option (text in lib/usage.mjs).
 *
 * Writes reports/report.json, the requested formats and reports/baseline.next.json.
 */
import fs from 'node:fs';
import path from 'node:path';
import { parseArgs } from 'node:util';
import { chromium, request as pwRequest } from 'playwright';
import { scanPage, contextOptions } from './lib/page-scan.mjs';
import { evaluatePage, baselineEntry, pageId, summarize } from './lib/evaluate.mjs';
import { renderHtml, renderMarkdown, renderConsole, makeColors, useColor } from './lib/report.mjs';
import { hostOf, rootDomain, runQueue, SEVERITY_ORDER } from './lib/util.mjs';
import { makeScope, normalizeUrl, spreadPick, readSitemap, findSitemaps } from './lib/discover.mjs';
import { validateInteractions, parseInteractionsArg } from './lib/interactions.mjs';
import { BUILTIN_RULES, compileCustomRules, compileSuppressions, effectiveRules } from './lib/rules.mjs';
import { USAGE, argError } from './lib/usage.mjs';
import { readCookieJar, writeCookieJar } from './lib/cookiejar.mjs';
import { suggestCsp } from './lib/csp.mjs';
import { NAME, VERSION, consoleName } from './lib/brand.mjs';

const env = process.env;
const OPTIONS = {
    help: { type: 'boolean', short: 'h', default: false },
    config: { type: 'string', default: 'sites.json' },
    'global-config': { type: 'string', default: env.SCAN_GLOBAL_CONFIG || 'config.json' },
    'disable-rule': { type: 'string', multiple: true, default: (env.SCAN_DISABLE_RULES || '').split(/[\s,]+/).filter(Boolean) },
    'list-rules': { type: 'boolean', default: false },
    baseline: { type: 'string', default: 'baseline.json' },
    out: { type: 'string', default: 'reports' },
    urls: { type: 'string', default: env.SCAN_URLS || '' },
    site: { type: 'string', default: env.SCAN_SITE || '' },
    mode: { type: 'string', default: env.SCAN_MODE || '' },
    sitemap: { type: 'string', default: env.SCAN_SITEMAP || '' },
    'max-pages': { type: 'string', default: env.SCAN_MAX_PAGES || '' },
    depth: { type: 'string', default: env.SCAN_DEPTH || '' },
    'include-subdomains': { type: 'boolean', default: env.SCAN_INCLUDE_SUBDOMAINS === '1' },
    format: { type: 'string', default: env.SCAN_FORMAT || 'html,md' },
    'user-agent': { type: 'string', default: env.SCAN_USER_AGENT || '' },
    color: { type: 'string', default: 'auto' },
    'show-scripts': { type: 'boolean', default: env.SCAN_SHOW_SCRIPTS === '1' },
    'dom-xss-canary': { type: 'boolean', default: env.SCAN_DOM_XSS_CANARY === '1' },
    'show-cookies': { type: 'boolean', default: env.SCAN_SHOW_COOKIES === '1' },
    'show-storage': { type: 'boolean', default: env.SCAN_SHOW_STORAGE === '1' },
    'show-values': { type: 'boolean', default: env.SCAN_SHOW_VALUES === '1' },
    'show-headers': { type: 'boolean', default: env.SCAN_SHOW_HEADERS === '1' },
    'show-html': { type: 'boolean', default: env.SCAN_SHOW_HTML === '1' },
    header: { type: 'string', multiple: true, default: (env.SCAN_HEADERS || '').split('\n').filter((l) => l.trim()) },
    cookie: { type: 'string', multiple: true, default: (env.SCAN_COOKIES || '').split(';').filter((l) => l.trim()) },
    'storage-state': { type: 'string', default: env.SCAN_STORAGE_STATE || '' },
    'cookie-jar': { type: 'string', default: env.SCAN_COOKIE_JAR || '' },
    session: { type: 'string', default: env.SCAN_SESSION || '' },
    interactions: { type: 'string', multiple: true, default: env.SCAN_INTERACTIONS ? [env.SCAN_INTERACTIONS] : [] },
    'update-baseline': { type: 'boolean', default: false },
    'fail-on': { type: 'string', default: env.SCAN_FAIL_ON || 'none' },
};
let args;
try {
  ({ values: args } = parseArgs({ options: OPTIONS, strict: true, allowPositionals: false }));
} catch (e) {
  console.error(`${argError(e, Object.keys(OPTIONS))}\nRun "node scan.mjs --help" for usage.`);
  process.exit(2);
}
if (args.help) {
  console.log(USAGE);
  process.exit(0);
}

const fail = (msg) => {
  console.error(msg);
  process.exit(2);
};

const readJson = (p, fallback) => {
  try {
    return JSON.parse(fs.readFileSync(p, 'utf8'));
  } catch (e) {
    if (fallback !== undefined && e.code === 'ENOENT') return fallback;
    throw new Error(`Could not read ${p}: ${e.message}`);
  }
};

if (!['auto', 'always', 'never'].includes(args.color)) fail('--color must be auto, always or never');
if (args.session && !['page', 'site'].includes(args.session)) fail(`--session must be page or site (got "${args.session}")`);
if (!['none', 'high', 'medium', 'low'].includes(args['fail-on'])) fail(`--fail-on must be none, high, medium or low (got "${args['fail-on']}")`);
const colorOn = useColor(args.color);
const col = makeColors(colorOn);

const FORMATS = ['html', 'md', 'console', 'json'];
const formats = new Set(args.format.split(/[\s,]+/).filter(Boolean));
// CSV was removed in favour of jq over report.json (docs/jq-recipes.md), which can still produce CSV.
if (formats.has('csv')) fail('--format csv was removed. Build CSVs from report.json with jq instead: see docs/jq-recipes.md (findings, PCI script inventory, cookies, storage…).');
// --show-values adds values to the lists you asked for; on its own, it shows both lists.
if (args['show-values'] && !args['show-cookies'] && !args['show-storage']) args['show-cookies'] = args['show-storage'] = true;
if (args['show-scripts'] || args['show-cookies'] || args['show-storage'] || args['show-headers'] || args['show-html']) formats.add('console'); // these lists are part of the console output
for (const f of formats) if (!FORMATS.includes(f)) fail(`Unknown --format "${f}". Use any of: ${FORMATS.join(', ')}`);

const MODES = ['url', 'crawl', 'sitemap'];
if (args.mode && !MODES.includes(args.mode)) fail(`Unknown --mode "${args.mode}". Use url, crawl or sitemap.`);
const intArg = (v, name) => {
  if (v === '') return undefined;
  const n = Number(v);
  if (!Number.isInteger(n) || n < 0) fail(`--${name} must be a whole number`);
  return n;
};
const cliMaxPages = intArg(args['max-pages'], 'max-pages');
const cliDepth = intArg(args.depth, 'depth');

const siteConfig = fs.existsSync(args.config) ? readJson(args.config) : { sites: [] };
// config.json: global defaults (options, domain lists) and rule settings for every site. sites.json
// values win for options; domain lists are combined.
const globalConfig = fs.existsSync(args['global-config']) ? readJson(args['global-config']) : {};
const config = {
  ...siteConfig,
  options: { ...(globalConfig.options || {}), ...(siteConfig.options || {}) },
  allowDomains: [...(globalConfig.allowDomains || []), ...(siteConfig.allowDomains || [])],
  blockDomains: [...(globalConfig.blockDomains || []), ...(siteConfig.blockDomains || [])],
  volatileScripts: [...(globalConfig.volatileScripts || []), ...(siteConfig.volatileScripts || [])],
};

// Rules: built-in → config.json → site → --disable-rule. Validated up front so typos fail loudly.
const globalWhere = args['global-config'];
const builtinIds = new Set(BUILTIN_RULES.map((r) => r.id));
function rulesetFor(site) {
  const where = site ? `site "${site.name}"` : null;
  const custom = [
    ...compileCustomRules(globalConfig.customRules, globalWhere, builtinIds).map((r) => ({ ...r, source: globalWhere })),
    ...(site ? compileCustomRules(site.customRules, where, builtinIds).map((r) => ({ ...r, source: where })) : []),
  ];
  const seen = new Set();
  for (const r of custom) {
    if (seen.has(r.id)) throw new Error(`custom rule id "${r.id}" is defined twice (${r.source})`);
    seen.add(r.id);
  }
  const knownIds = new Set([...builtinIds, ...seen]);
  const settings = effectiveRules(
    [{ rules: globalConfig.rules, where: globalWhere }, ...(site ? [{ rules: site.rules, where }] : [])],
    args['disable-rule'],
    knownIds
  );
  const suppress = [...compileSuppressions(globalConfig.suppress, globalWhere, knownIds), ...(site ? compileSuppressions(site.suppress, where, knownIds) : [])];
  const on = (r) => settings.get(r.id)?.severity !== 'off';
  return {
    settings,
    suppress,
    custom,
    codeRules: custom.filter((r) => r.target === 'code' && on(r)),
    cssRules: custom.filter((r) => r.target === 'css' && on(r)),
    htmlRules: custom.filter((r) => r.target === 'html' && on(r)),
    urlRules: custom.filter((r) => r.target === 'url' && on(r)),
  };
}

// --- Authenticated scans -----------------------------------------------------------------------
// Values may reference environment variables as ${env:NAME}, so secrets can stay out of sites.json.
function expandEnv(v, where) {
  return String(v).replace(/\$\{env:([A-Za-z0-9_]+)\}/g, (_, name) => {
    if (env[name] === undefined) throw new Error(`${where}: environment variable ${name} is not set`);
    return env[name];
  });
}
const parseCookieString = (s, where) =>
  String(s)
    .split(';')
    .map((p) => p.trim())
    .filter(Boolean)
    .map((p) => {
      const i = p.indexOf('=');
      if (i < 1) throw new Error(`${where}: cookie "${p}" must look like name=value`);
      return { name: p.slice(0, i).trim(), value: expandEnv(p.slice(i + 1).trim(), where) };
    });
// headers: { Name: value } from config, plus "Name: value" strings from --header.
// cookies: [{ name, value, domain?, path?, httpOnly?, secure?, sameSite? }] or "a=1; b=2", plus --cookie.
// storageState: a Playwright storage-state file (cookies + localStorage), e.g. from
//   npx playwright codegen --save-storage=auth.json https://shop.example.com/account/login
function authFor(site, configDir) {
  const where = `site "${site.name}"`;
  const headers = {};
  for (const [k, v] of Object.entries({ ...(opts.headers || {}), ...(site.headers || {}) })) headers[k] = expandEnv(v, where);
  for (const h of args.header) {
    const i = h.indexOf(':');
    if (i < 1) throw new Error(`--header "${h}" must look like "Name: value"`);
    headers[h.slice(0, i).trim()] = expandEnv(h.slice(i + 1).trim(), '--header');
  }
  // A cookie value without "=" is a cookie file (curl -b style): Netscape/curl format or Playwright JSON.
  const fromFile = (file, base, label) => {
    const p = path.resolve(base, file);
    if (!fs.existsSync(p)) throw new Error(`${label}: "${file}" isn't name=value and no such cookie file exists`);
    return readCookieJar(p).map((c) => ({ ...c, _source: 'cookie jar' }));
  };
  const cfgCookies = site.cookies ?? opts.cookies ?? [];
  const cookies = [
    ...(typeof cfgCookies === 'string'
      ? cfgCookies.includes('=')
        ? parseCookieString(cfgCookies, where)
        : fromFile(cfgCookies, configDir, where)
      : cfgCookies.map((c) => ({ ...c, value: expandEnv(c.value, where) }))),
    ...args.cookie.flatMap((c) => (c.includes('=') ? parseCookieString(c, '--cookie') : fromFile(c.trim(), '.', '--cookie'))),
  ];
  let storageState = args['storage-state'] || site.storageState || opts.storageState || '';
  if (storageState) {
    storageState = path.resolve(args['storage-state'] ? '.' : configDir, storageState);
    if (!fs.existsSync(storageState)) throw new Error(`storage state file not found: ${storageState}`);
  }
  return { headers, cookies, storageState: storageState || null };
}

if (args['list-rules']) {
  const site = args.site ? (siteConfig.sites || []).find((s) => s.name.toLowerCase() === args.site.toLowerCase()) : null;
  if (args.site && !site) fail(`--site "${args.site}" not found in ${args.config}`);
  let rs;
  try {
    rs = rulesetFor(site);
  } catch (e) {
    fail(e.message);
  }
  const rows = [...BUILTIN_RULES, ...rs.custom.map((r) => ({ ...r, kind: `custom ${r.target}` }))];
  console.log(`Rules${site ? ` for site "${site.name}"` : ''} (built-in → ${globalWhere} → ${site ? 'site → ' : ''}--disable-rule)\n`);
  for (const r of rows) {
    const set = rs.settings.get(r.id);
    const eff = set ? set.severity : r.severity;
    const note = set ? `  ← ${set.source}${set.reason ? ': ' + set.reason : ''}` : r.custom ? `  ← ${r.source}` : '';
    console.log(`  ${col.sev(eff === 'off' ? 'info' : eff, eff.toUpperCase().padEnd(6))} ${r.id.padEnd(26)} ${col.gray(r.kind.padEnd(11))} ${r.description}${col.gray(note)}`);
  }
  if (rs.suppress.length) {
    console.log('\nSuppressions:');
    for (const s of rs.suppress) console.log(`  ${s.rule} on ${[s.page && 'page ' + s.page, s.script && 'script ' + s.script].filter(Boolean).join(', ')} — ${s.reason} ${col.gray('(' + s.where + ')')}`);
  }
  process.exit(0);
}

// --interactions (repeatable): inline JSON, a .json file, a .js/.mjs hook, or inline JS. Replaces sites.json interactions.
let cliInteractions = null;
if (args.interactions.length) {
  try {
    cliInteractions = args.interactions.flatMap((v) =>
      parseInteractionsArg(v, { readFile: (f) => fs.readFileSync(f, 'utf8'), exists: fs.existsSync, resolve: (f) => path.resolve(f) })
    );
  } catch (e) {
    fail(e.message);
  }
}
const opts = { waitMs: 4000, timeoutMs: 45000, concurrency: 3, profiles: ['desktop'], ...(config.options || {}) };

// Ad-hoc URLs (handy for on-demand runs) replace the configured site list.
let sites = config.sites || [];
if (args.urls.trim()) {
  const byRoot = {};
  for (const u of args.urls.split(/[\s,]+/).filter(Boolean)) {
    const root = rootDomain(hostOf(u));
    (byRoot[root] ||= { name: root, urls: [], firstParty: [root] }).urls.push(u);
  }
  sites = Object.values(byRoot);
} else if (args.sitemap && !sites.length) {
  // `--sitemap <url|file>` alone is enough. A remote sitemap's host sets the scope; for a local
  // file the scope comes from the first page URL listed in it (resolved below).
  if (/^https?:/i.test(args.sitemap)) {
    const root = rootDomain(hostOf(args.sitemap));
    sites = [{ name: root, urls: [new URL(args.sitemap).origin + '/'], firstParty: [root] }];
  } else {
    sites = [{ name: '', urls: [] }];
  }
}
if (args.site) sites = sites.filter((s) => s.name.toLowerCase() === args.site.toLowerCase());
if (!sites.length) fail('No sites to scan. Add sites to sites.json or pass --urls (or --sitemap with a URL).');

// Per-site discovery settings: CLI flags override sites.json, which overrides defaults.
for (const s of sites) {
  s.mode = args.mode || (args.sitemap ? 'sitemap' : '') || s.mode || opts.mode || 'url';
  if (!MODES.includes(s.mode)) fail(`Site "${s.name}": unknown mode "${s.mode}"`);
  s.maxPages = cliMaxPages ?? s.maxPages ?? opts.maxPages ?? 25;
  s.depth = cliDepth ?? s.depth ?? opts.depth ?? 2;
  s.includeSubdomains = args['include-subdomains'] || s.includeSubdomains || false;
  if (args.sitemap) s.sitemap = args.sitemap;
  // Session: "page" (default) = every page is a first visit; "site" = one visitor whose cookies and
  // storage carry from page to page, in the order listed (that site's pages then run one at a time).
  s.session = args.session || s.session || opts.session || 'page';
  if (!['page', 'site'].includes(s.session)) fail(`Site "${s.name}": session must be "page" or "site"`);
  // User agent: --user-agent > site.userAgent > options.userAgent > built-in per-profile default.
  s.userAgent = args['user-agent'] || s.userAgent || opts.userAgent || undefined;
  // Custom interactions: site list, else options.interactions. Script paths are relative to sites.json.
  s.interactions = cliInteractions || s.interactions || opts.interactions || [];
  const errs = validateInteractions(s.interactions, `site "${s.name}"`);
  if (errs.length) fail(errs.join('\n'));
  const configDir = path.dirname(path.resolve(args.config));
  s.interactions = s.interactions.map((b) => (b.script && !path.isAbsolute(b.script) ? { ...b, scriptLabel: b.script, script: path.resolve(configDir, b.script) } : b));
  for (const b of s.interactions) if (b.script && !fs.existsSync(b.script)) fail(`site "${s.name}": interaction script not found: ${b.script}`);
  try {
    s.ruleset = rulesetFor(s);
    s.auth = authFor(s, path.dirname(path.resolve(args.config)));
  } catch (e) {
    fail(e.message);
  }
}

const proxy = env.SCAN_PROXY ? { server: env.SCAN_PROXY } : undefined;
opts.ignoreTLS = env.SCAN_IGNORE_TLS === '1'; // only for testing behind TLS-intercepting proxies

// Sitemap mode: resolve each site's page list before scanning.
const sitemapSites = sites.filter((s) => s.mode === 'sitemap');
if (sitemapSites.length) {
  for (const s of sitemapSites) {
    const api = await pwRequest.newContext({ userAgent: contextOptions('desktop', s.userAgent).userAgent, ignoreHTTPSErrors: opts.ignoreTLS, proxy });
    const sources = s.sitemap ? [s.sitemap] : await findSitemaps(api, s.urls[0]);
    let found = [];
    for (const src of sources) found.push(...(await readSitemap(api, src, { log: console.log })));
    const scopeUrls = s.urls.length ? s.urls : found.slice(0, 1);
    if (!scopeUrls.length) fail(`Site "${s.name}": sitemap ${sources.join(', ')} had no page URLs`);
    const inScope = makeScope(scopeUrls, s);
    const seen = new Set(s.urls.map((u) => normalizeUrl(u, { keepQuery: true })));
    const extra = [];
    let outOfScope = 0;
    for (const u of found) {
      const n = normalizeUrl(u, { keepQuery: true });
      if (!n || seen.has(n)) continue;
      seen.add(n);
      if (inScope(n)) extra.push(n);
      else outOfScope++;
    }
    const room = s.maxPages ? Math.max(0, s.maxPages - s.urls.length) : extra.length;
    const picked = spreadPick(extra, room);
    s.urls = [...s.urls, ...picked];
    if (!s.name) s.name = rootDomain(hostOf(scopeUrls[0]));
    console.log(
      `Sitemap for ${s.name}: ${found.length} URL(s) in ${sources.join(', ')}; scanning ${s.urls.length}` +
        (picked.length < extra.length ? ` (capped by max-pages ${s.maxPages}; sampled across sections)` : '') +
        (outOfScope ? `; skipped ${outOfScope} off-site/excluded` : '')
    );
    await api.dispose();
  }
}

const baseline = readJson(args.baseline, null);
const started = Date.now();

// Initial jobs. In crawl mode, scanning a page on the first profile feeds its links back into the queue.
let seq = 0;
const crawl = new Map(); // site -> { inScope, seen:Set }
const jobs = [];
for (const site of sites) {
  site.firstParty = site.firstParty?.length ? site.firstParty : [...new Set(site.urls.map((u) => rootDomain(hostOf(u))))];
  site.profiles = site.profiles || opts.profiles;
  if (site.mode === 'crawl') crawl.set(site, { inScope: makeScope(site.urls, site), seen: new Set(site.urls.map((u) => normalizeUrl(u))) });
  if (site.session === 'site') {
    // One chain per browser profile: only the chain's first page starts now; each finished page hands
    // its cookies/storage to the next one.
    site.chains = {};
    for (const profile of site.profiles) {
      const chain = (site.chains[profile] = { queue: [], state: null, running: false });
      for (const url of site.urls) chain.queue.push({ seq: seq++, site, url, profile, depth: 0, chain });
      chain.running = true;
      jobs.push(chain.queue.shift());
    }
  } else {
    for (const url of site.urls) for (const profile of site.profiles) jobs.push({ seq: seq++, site, url, profile, depth: 0 });
  }
}

const modeSummary = [...new Set(sites.map((s) => s.mode))].join('/');
console.log(`${consoleName(col)}${VERSION ? col.gray(` v${VERSION}`) : ''} · scanning ${jobs.length} page load(s) across ${sites.length} site(s) [mode: ${modeSummary}]…`);
let browser;
try {
  browser = await chromium.launch({
    args: ['--disable-blink-features=AutomationControlled'],
    // Optional: route through an egress proxy (e.g. corporate CI runners).
    ...(proxy ? { proxy } : {}),
  });
} catch (e) {
  if (/Executable doesn't exist|playwright install/i.test(String(e.message))) {
    fail('Playwright\'s Chromium isn\'t installed for this version. Run: make install   (or: npx playwright install chromium)\nOr use Docker, which has it built in: make docker-scan URL=…');
  }
  throw e;
}

const jarCookies = new Map();
const htmlExcerpts = new Map();

// Elements worth counting to show what scripts added to the page.
const HTML_TAGS = ['script', 'iframe', 'form', 'input', 'style', 'link', 'img', 'div'];
const countTags = (html) => Object.fromEntries(HTML_TAGS.map((t) => [t, (String(html || '').match(new RegExp(`<${t}[\\s>/]`, 'gi')) || []).length]));
function saveHtml(page, job) {
  const dir = path.join(args.out, 'html');
  fs.mkdirSync(dir, { recursive: true });
  let slug;
  try {
    const u = new URL(page.url);
    slug = (u.hostname + u.pathname).replace(/[^a-z0-9.-]+/gi, '_').replace(/_+$/, '').slice(0, 80);
  } catch {
    slug = 'page';
  }
  const base = `${String(job.seq).padStart(3, '0')}-${slug}-${page.profile}`;
  const out = { server: null, rendered: null };
  for (const kind of ['server', 'rendered']) {
    const html = page.htmlCapture[kind];
    if (html == null) continue;
    const file = `${base}.${kind}.html`;
    fs.writeFileSync(path.join(dir, file), html);
    out[kind] = { file: `html/${file}`, size: html.length, lines: html.split('\n').length, tags: countTags(html) };
  }
  return out;
}
const results = await runQueue(jobs, opts.concurrency, async (job) => {
  const t = Date.now();
  const c = crawl.get(job.site);
  const collectLinks = !!c && job.profile === job.site.profiles[0] && job.depth < job.site.depth;
  const page = await scanPage(browser, { url: job.url, profile: job.profile, firstParty: job.site.firstParty, opts: { ...opts, domXssCanary: args['dom-xss-canary'] || job.site.domXssCanary || opts.domXssCanary || false, collectLinks, userAgent: job.site.userAgent, interactions: job.site.interactions, auth: job.site.auth, showValues: args['show-values'], captureHtml: args['show-html'], collectJar: !!args['cookie-jar'], codeRules: job.site.ruleset.codeRules, cssRules: job.site.ruleset.cssRules, htmlRules: job.site.ruleset.htmlRules, ...(job.chain ? { keepState: true, carriedState: job.chain.state } : {}) } });
  if (job.chain) {
    if (page.storageState) job.chain.state = page.storageState;
    delete page.storageState;
  }
  // --show-html: save server HTML and rendered DOM to files; keep only paths and a summary in the report.
  if (page.htmlCapture) {
    page.html = saveHtml(page, job);
    // Console excerpt kept outside the report object, so report.json only gets paths and counts.
    if (page.htmlCapture.server != null) htmlExcerpts.set(page, page.htmlCapture.server);
    delete page.htmlCapture;
  }
  // --cookie-jar: collect full cookies (with values) for the jar file; never kept in the report.
  if (page.jar) {
    for (const ck of page.jar) jarCookies.set(`${ck.domain}|${ck.path}|${ck.name}`, ck);
    delete page.jar;
  }
  page.issues = evaluatePage(page, { baseline, config, firstParty: job.site.firstParty, rules: job.site.ruleset });
  const real = page.issues.filter((i) => i.severity !== 'info');
  const worst = page.error ? 'error' : real[0]?.severity || 'clean';
  console.log(
    `  ${col.sev(worst, `[${worst.toUpperCase().padEnd(6)}]`)} ${job.url} ${col.gray(`(${job.profile})`)} — ${page.scripts.length} scripts, ${real.length} finding(s), ${((Date.now() - t) / 1000).toFixed(1)}s${
      page.error ? col.sev('error', ' — ERROR: ' + page.error) : ''
    }`
  );

  const more = [];
  if (collectLinks) {
    for (const link of page.links || []) {
      const n = normalizeUrl(link);
      if (!n || c.seen.has(n) || !c.inScope(n)) continue;
      if (job.site.maxPages && c.seen.size >= job.site.maxPages) break;
      c.seen.add(n);
      for (const profile of job.site.profiles) {
        const next = { seq: seq++, site: job.site, url: n, profile, depth: job.depth + 1 };
        const chain = job.site.chains?.[profile];
        if (chain) {
          next.chain = chain;
          chain.queue.push(next);
          // Wake a chain that had already run out of pages (another profile's crawl found more).
          if (!chain.running) {
            chain.running = true;
            more.push(chain.queue.shift());
          }
        } else more.push(next);
      }
    }
  }
  if (job.chain) {
    const next = job.chain.queue.shift();
    if (next) more.push(next);
    else job.chain.running = false;
  }
  delete page.links;
  return { result: { seq: job.seq, siteName: job.site.name, page }, more };
});
await browser.close();
results.sort((a, b) => a.seq - b.seq);

// Site-wide settings (headers, cookies) usually look the same on every page. Report each distinct one
// once per site, on the first page it appears, with a count of the other pages that share it.
const SITE_WIDE = new Set(['csp-missing', 'csp-weak', 'csp-report-only', 'hsts-missing', 'nosniff-missing', 'clickjacking-unprotected', 'referrer-policy-missing', 'session-cookie-insecure']);
for (const site of sites) {
  const first = new Map();
  for (const r of results.filter((x) => x.siteName === site.name)) {
    r.page.issues = r.page.issues.filter((i) => {
      if (!SITE_WIDE.has(i.type)) return true;
      const k = `${i.type}|${i.message}`;
      if (!first.has(k)) {
        first.set(k, i);
        return true;
      }
      first.get(k).alsoOn = (first.get(k).alsoOn || 0) + 1;
      return false;
    });
  }
}

// Assemble report
const report = {
  meta: {
    startedAt: new Date(started).toISOString(),
    durationSec: Math.round((Date.now() - started) / 1000),
    pageCount: results.length,
    baselineUsed: !!baseline,
    modes: modeSummary,
    // --show-values: cookie and storage values are in this report; treat it as sensitive.
    containsValues: !!args['show-values'],
    ci: env.CIRCLE_BUILD_URL || null,
  },
  summary: summarize(results.map((r) => r.page)),
  sites: sites.map((s) => ({ name: s.name, mode: s.mode, session: s.session, cspSuggestion: cspFor(s), rules: ruleSummary(s.ruleset), auth: authSummary(s.auth), pages: results.filter((r) => r.siteName === s.name).map((r) => r.page) })),
};

// Suggested CSP for a site whose pages have no, a weak, or only a report-only policy (lib/csp.mjs).
function cspFor(site) {
  const pages = results.filter((r) => r.siteName === site.name).map((r) => r.page);
  if (!pages.some((p) => p.issues.some((i) => ['csp-missing', 'csp-weak', 'csp-report-only'].includes(i.type)))) return null;
  return suggestCsp(pages);
}

// Names only: header and cookie values are never written to reports.
function authSummary(a) {
  if (!a || (!a.storageState && !a.cookies.length && !Object.keys(a.headers).length)) return null;
  return { headers: Object.keys(a.headers), cookies: a.cookies.map((c) => c.name), storageState: a.storageState ? path.basename(a.storageState) : null };
}

// What was changed from the built-in rules for this site, so the report can't hide it.
function ruleSummary(rs) {
  const defaults = new Map(BUILTIN_RULES.map((r) => [r.id, r.severity]));
  return {
    changed: [...rs.settings].map(([id, v]) => ({ id, severity: v.severity, default: defaults.get(id) || rs.custom.find((c) => c.id === id)?.severity, reason: v.reason, source: v.source })),
    custom: rs.custom.map(({ id, severity, target, pattern, description, source }) => ({ id, severity, target, pattern, description, source })),
    suppress: rs.suppress.map(({ rule, script, page, reason, where, hits }) => ({ rule, script, page, reason, source: where, hits })),
  };
}

// Next baseline = previous baseline with this run's pages replaced (pages that errored keep their old entry).
const nextBaseline = { generatedAt: report.meta.startedAt, pages: { ...(baseline?.pages || {}) } };
for (const { page } of results) if (!page.error) nextBaseline.pages[pageId(page)] = baselineEntry(page);

fs.mkdirSync(args.out, { recursive: true });
// report.json is always written: it's the machine-readable record other tooling reads.
fs.writeFileSync(path.join(args.out, 'report.json'), JSON.stringify(report, null, 2));
// The --show-* views go to every output: console, Markdown (as code blocks) and HTML (which always
// includes all of them, collapsed). report.json always has everything; see docs/jq-recipes.md.
const views = { scripts: args['show-scripts'], cookies: args['show-cookies'], storage: args['show-storage'], headers: args['show-headers'], html: args['show-html'] };
if (formats.has('md')) fs.writeFileSync(path.join(args.out, 'report.md'), renderMarkdown(report, { views, htmlExcerpts, outDir: args.out }));
if (formats.has('html')) fs.writeFileSync(path.join(args.out, 'report.html'), renderHtml(report, { htmlExcerpts, outDir: args.out }));
fs.writeFileSync(path.join(args.out, 'baseline.next.json'), JSON.stringify(nextBaseline, null, 2));
if (args['cookie-jar']) {
  writeCookieJar(args['cookie-jar'], [...jarCookies.values()]);
  console.log(`Cookie jar written to ${args['cookie-jar']} (${jarCookies.size} cookies, readable by you only)`);
}
if (args['update-baseline']) {
  fs.writeFileSync(args.baseline, JSON.stringify(nextBaseline, null, 2));
  console.log(`Baseline written to ${args.baseline}`);
}

if (formats.has('console')) console.log(renderConsole(report, { color: colorOn, showScripts: args['show-scripts'], showCookies: args['show-cookies'], showStorage: args['show-storage'], showHeaders: args['show-headers'], showHtml: args['show-html'], htmlExcerpts, outDir: args.out }));
const c = report.summary;
console.log(`\n${col.sev('high', `High: ${c.high}`)}  ${col.sev('medium', `Medium: ${c.medium}`)}  ${col.sev('low', `Low: ${c.low}`)}  ${col.gray(`Info: ${c.info}`)}`);
const written = ['json', ...['html', 'md'].filter((f) => formats.has(f))].map((f) => path.join(args.out, `report.${f}`));
console.log(`Reports: ${written.join(', ')}`);

// Optional gate. Default "none" = always exit 0 (report only).
const failOn = args['fail-on'];
if (failOn !== 'none' && SEVERITY_ORDER[failOn]) {
  const hit = results.some((r) => r.page.issues.some((i) => SEVERITY_ORDER[i.severity] >= SEVERITY_ORDER[failOn]));
  if (hit) {
    console.error(`Findings at or above "${failOn}" severity; failing.`);
    process.exit(1);
  }
}
