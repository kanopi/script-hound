// Custom, per-site interaction scripting, plus the submission guard that keeps it safe.
//
// sites.json:
//   "interactions": [
//     { "match": "/checkout", "steps": [
//         { "click": "#show-card-form", "label": "open card form" },
//         { "type": "input[name=cardnumber]", "value": "4111111111111111", "frame": "iframe[title*=card]" },
//         { "wait": 1500 }
//     ]},
//     { "script": "interactions/shop.mjs" }
//   ]
//
// A script module exports: async function ({ page, url, profile, step, log }) { await step('label', async () => {...}) }
import path from 'node:path';
import { pathToFileURL } from 'node:url';

const ACTIONS = ['click', 'fill', 'type', 'hover', 'press', 'select', 'check', 'scrollTo', 'waitFor', 'wait'];
const DEFAULT_STEP_TIMEOUT = 5000;

/**
 * Parse one --interactions value into blocks. Accepts inline JSON, a .json file, a .js/.mjs hook
 * file, or inline JavaScript (a hook body). JSON may be a list of steps, one block, or a list of blocks.
 */
export function parseInteractionsArg(value, { readFile, exists, resolve }) {
  const v = value.trim();
  const fromJson = (data, label) => {
    const list = Array.isArray(data) ? data : [data];
    const isBlock = (x) => x && typeof x === 'object' && ('steps' in x || 'script' in x || 'code' in x);
    if (list.every(isBlock)) return list;
    if (list.every((x) => x && typeof x === 'object' && !isBlock(x))) return [{ steps: list }];
    throw new Error(`${label}: expected a list of steps, a block ({ "steps": [...] }) or a list of blocks`);
  };
  if (v.startsWith('[') || v.startsWith('{')) {
    try {
      return fromJson(JSON.parse(v), '--interactions');
    } catch (e) {
      throw new Error(`--interactions looks like JSON but didn't parse: ${e.message}`);
    }
  }
  const file = resolve(v);
  if (/\.json$/i.test(v)) {
    if (!exists(file)) throw new Error(`--interactions: file not found: ${v}`);
    // "script" paths inside a JSON file are relative to that file.
    return fromJson(JSON.parse(readFile(file)), v).map((b) =>
      b.script && !path.isAbsolute(b.script) ? { ...b, scriptLabel: b.script, script: path.resolve(path.dirname(file), b.script) } : b
    );
  }
  if (/\.m?js$/i.test(v)) {
    if (!exists(file)) throw new Error(`--interactions: file not found: ${v}`);
    return [{ script: file, scriptLabel: v }];
  }
  return [{ code: v }];
}

/** Does an interaction block apply to this URL? match: substring, "/regex/flags", or absent (= all). */
export function matchesUrl(match, url) {
  if (!match) return true;
  const list = Array.isArray(match) ? match : [match];
  return list.some((m) => {
    const rx = /^\/(.+)\/([a-z]*)$/.exec(m);
    return rx ? new RegExp(rx[1], rx[2]).test(url) : url.includes(m);
  });
}

export function actionOf(step) {
  return ACTIONS.find((a) => a in step);
}

/** Validate config up front so typos fail fast instead of silently doing nothing on every page. */
export function validateInteractions(list, where) {
  const errs = [];
  (list || []).forEach((block, i) => {
    if (!block.steps && !block.script && !block.code) errs.push(`${where}.interactions[${i}]: needs "steps", "script" or "code"`);
    (block.steps || []).forEach((s, j) => {
      if (!actionOf(s)) errs.push(`${where}.interactions[${i}].steps[${j}]: unknown action (use one of ${ACTIONS.join(', ')})`);
    });
  });
  return errs;
}

async function runStep(page, s) {
  const timeout = s.timeout ?? DEFAULT_STEP_TIMEOUT;
  // "frame": selector of an iframe (e.g. hosted card fields); the action's selector is looked up inside it.
  const scope = s.frame ? page.frameLocator(s.frame) : page;
  const loc = (sel) => scope.locator(sel).first();
  const a = actionOf(s);
  switch (a) {
    case 'click':
      return loc(s.click).click({ timeout });
    case 'fill':
      return loc(s.fill).fill(String(s.value ?? ''), { timeout });
    case 'type':
      return loc(s.type).pressSequentially(String(s.value ?? ''), { delay: s.delay ?? 15, timeout });
    case 'hover':
      return loc(s.hover).hover({ timeout });
    case 'press':
      return s.selector ? loc(s.selector).press(s.press, { timeout }) : page.keyboard.press(s.press);
    case 'select':
      return loc(s.select).selectOption(s.value, { timeout });
    case 'check':
      return loc(s.check).check({ timeout });
    case 'scrollTo':
      return loc(s.scrollTo).scrollIntoViewIfNeeded({ timeout });
    case 'waitFor':
      return loc(s.waitFor).waitFor({ state: s.state || 'visible', timeout });
    case 'wait':
      return page.waitForTimeout(Number(s.wait) || 0);
  }
}

const describe = (s) => {
  const a = actionOf(s);
  return `${a}${typeof s[a] === 'string' ? ' ' + s[a] : a === 'wait' ? ' ' + s.wait + 'ms' : ''}${s.frame ? ` (in ${s.frame})` : ''}`;
};

/**
 * Run every interaction block matching this URL. setPhase(label) tags whatever loads during a step.
 * Returns a log: [{ label, ok, ms, error?, navigatedTo? }]. Failures are logged, never fatal.
 */
export async function runInteractions(page, blocks, { url, profile, setPhase }) {
  const log = [];
  const step = async (label, fn) => {
    setPhase(`custom:${label}`);
    const before = page.url();
    const t = Date.now();
    const entry = { label };
    try {
      await fn();
      entry.ok = true;
    } catch (e) {
      entry.ok = false;
      entry.error = (e.message || String(e)).split('\n')[0].slice(0, 200);
    }
    entry.ms = Date.now() - t;
    if (page.url() !== before) entry.navigatedTo = page.url();
    log.push(entry);
  };
  // Hooks get the same 5s default as JSON steps (Playwright's own default is 30s per action).
  page.setDefaultTimeout(DEFAULT_STEP_TIMEOUT);
  for (const block of blocks.filter((b) => matchesUrl(b.match, url))) {
    for (const s of block.steps || []) await step(s.label || describe(s), () => runStep(page, s));
    if (block.script || block.code) {
      await step(block.code ? 'inline script' : `script ${block.scriptLabel || block.script}`, async () => {
        // Inline code (from --interactions) is wrapped as a hook body and imported from a data: URL.
        const src = block.code
          ? 'data:text/javascript,' + encodeURIComponent(`export default async function ({ page, url, profile, step, log }) {\n${block.code}\n}`)
          : pathToFileURL(block.script).href;
        const mod = await import(src);
        const fn = mod.default || mod.interact;
        if (typeof fn !== 'function') throw new Error('script must export a default async function');
        await fn({ page, url, profile, step, log: (msg) => log.push({ label: String(msg), ok: true, ms: 0, note: true }) });
      });
    }
  }
  page.setDefaultTimeout(30000);
  return log;
}

/**
 * Block anything that would submit a form: non-GET document navigations (form POSTs) in the page.
 * Uses CDP Fetch for Document requests only, so normal resource loading isn't intercepted.
 * Blocked attempts are recorded (and still visible as requests, so exfil-by-form is still reported).
 */
export async function startSubmissionGuard(context, page, getPhase, blocked) {
  let cdp;
  try {
    cdp = await context.newCDPSession(page);
    cdp.on('Fetch.requestPaused', (e) => {
      if (e.request.method !== 'GET' && e.request.method !== 'HEAD') {
        blocked.push({ url: e.request.url, method: e.request.method, phase: getPhase() });
        // 204 No Content: the browser cancels the navigation and stays on the current page (failing the
        // request instead would load Chrome's error page and wipe out the inventory).
        cdp.send('Fetch.fulfillRequest', { requestId: e.requestId, responseCode: 204, responseHeaders: [], body: '' }).catch(() => {});
      } else {
        cdp.send('Fetch.continueRequest', { requestId: e.requestId }).catch(() => {});
      }
    });
    await cdp.send('Fetch.enable', { patterns: [{ urlPattern: '*', resourceType: 'Document', requestStage: 'Request' }] });
  } catch {
    // Without CDP the guard can't run; built-in interactions never submit anyway.
  }
  return cdp;
}
