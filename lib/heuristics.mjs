// Pattern checks run against every script body (external and inline).
// Each rule: id, severity (high | medium | low), description, test(code) -> { match, index } | null
// (a plain match string is also accepted). analyzeCode() turns `index` into line/column + a snippet.
// These are heuristics: minified libraries can trip the low/medium ones. Treat them as
// "look at this", not "this is malware". High-severity rules are rarely seen in clean code.

const re = (rx) => (code) => {
  const m = code.match(rx);
  return m ? { match: m[0].slice(0, 160), index: m.index } : null;
};

// --- Card-skimmer building blocks ----------------------------------------------
// A skimmer needs four things close together: a card field, a read of its value (or a listener),
// a way to send data, and an external destination. Requiring them within PROXIMITY characters
// (instead of anywhere in the file) is what keeps large SDKs such as gtag.js, fbevents.js and
// Stripe.js from matching: they contain each piece somewhere, but not together.
const PROXIMITY = 1500;
const SMALL_FILE = 20000; // small standalone files are judged as a whole
const CARD_FIELD =
  /(?:['"`#\[\/|.:]|name=|id=)[^'"`\n]{0,40}?(cc[-_ ]?(?:num(?:ber)?|cvv|cid|cvc|exp)|card[-_ ]?(?:number|num|code|cvv|cvc)|credit[-_]?card[-_]?(?:number|cvc|cvv|expiry)|\bcvv\b|\bcvc\b|security[-_]?code)/gi;
const SEND = /(new\s+Image\s*\(\s*\)[\s\S]{0,120}\.src\s*=|\(new\s+Image\)?\s*\(\s*\)\)\.src\s*=|navigator\.sendBeacon\s*\(|new\s+WebSocket\s*\(|\.ajax\s*\(|\$\.post\s*\(|\bfetch\s*\(|new\s+XMLHttpRequest|\.open\s*\(\s*['"`]POST)/g;
const READ = /(\.value\b|\.val\s*\(\s*\)|new\s+FormData|\.serialize\s*\(|addEventListener\s*\(\s*['"`](?:submit|click|change|blur|input|key(?:up|down|press))|onsubmit\s*=)/g;
const URL_LITERAL = /['"`]((?:https?:|wss?:)?\/\/(?:[a-z0-9.-]+\.[a-z]{2,}|localhost|\d{1,3}(?:\.\d{1,3}){3})(?::\d+)?)[^'"`]*['"`]/gi;
// Card data sent to a payment processor's own API is not skimming. Matched on the exact registrable
// domain, so look-alikes (stripe-cdn.example, paypal-secure.example) still count as external.
const PAYMENT_PROCESSORS =
  /(^|\.)(stripe\.com|stripe\.network|braintreegateway\.com|braintree-api\.com|paypal\.com|paypalobjects\.com|adyen\.com|adyenpayments\.com|squareup\.com|squareupsandbox\.com|authorize\.net|razorpay\.com|checkout\.com|worldpay\.com|mollie\.com|klarna\.com|afterpay\.com|paddle\.com|cybersource\.com|globalpay\.com|nmi\.com|bluesnap\.com|2checkout\.com|recurly\.com|chargebee\.com)$/i;

const positions = (rx, code) => [...code.matchAll(rx)].map((m) => m.index);
// allowProcessor(host, index): lets a payment-processor host count anyway (e.g. a secret key is nearby).
function externalDestinations(code, allowProcessor = () => false) {
  const out = [];
  for (const m of code.matchAll(URL_LITERAL)) {
    try {
      const host = new URL(m[1].startsWith('//') ? 'https:' + m[1] : m[1]).hostname;
      if (!PAYMENT_PROCESSORS.test(host) || allowProcessor(host, m.index)) out.push({ index: m.index, host });
    } catch {
      // not a URL after all
    }
  }
  return out;
}

// A destination that's decoded or assembled at runtime instead of written out: fetch(atob(…)),
// 'https://' + btoa(counter) + '.com', open('POST', atob(…)). Skimmers do this to hide the drop host.
const HIDDEN_DEST =
  /((?:\bfetch|sendBeacon|new\s+WebSocket|\.open\s*\(\s*['"`]\w+['"`]\s*,)\s*\(?\s*(?:window\.)?(?:atob|unescape|decodeURIComponent\s*\(\s*escape)\s*\(|\.src\s*=\s*(?:window\.)?atob\s*\(|['"`](?:https?|wss?):\/\/['"`]\s*\+\s*(?:window\.)?(?:btoa|atob|String\.fromCharCode)\s*\()/g;
// Card data parked in browser storage for a separate routine to upload later (Sansec 2026 Stripe-C2 kit).
const STASH = /((?:localStorage|sessionStorage)\s*\.\s*setItem\s*\(|(?:localStorage|sessionStorage)\s*\[[^\]]{1,40}\]\s*=(?!=))/g;
// A Stripe *secret* or restricted key in page code. Legitimate front ends only ever hold publishable
// (pk_) keys; with a secret key, "sent to api.stripe.com" can mean "sent to the attacker's account".
const STRIPE_SECRET = /\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{10,}/g;

function skimmerTest(code) {
  const fields = [...code.matchAll(CARD_FIELD)];
  if (!fields.length) return null;
  const reads = positions(READ, code);
  if (!reads.length) return null;
  const sends = positions(SEND, code);
  const secrets = positions(STRIPE_SECRET, code);
  const whole = code.length <= SMALL_FILE;
  const near = (list, i) => list.length > 0 && (whole || list.some((x) => Math.abs(x - i) <= PROXIMITY));
  // External URL literals; payment-processor hosts only count when a secret key sits nearby.
  const dests = externalDestinations(code, (host, idx) => secrets.length && near(secrets, idx));
  const hidden = positions(HIDDEN_DEST, code);
  const stashes = positions(STASH, code);
  for (const f of fields) {
    const i = f.index;
    if (!near(reads, i)) continue;
    const at = i + f[0].length - f[1].length;
    if (near(sends, i)) {
      const close = dests.filter((d) => whole || Math.abs(d.index - i) <= PROXIMITY);
      if (close.length) {
        const dest = close.reduce((a, b) => (Math.abs(b.index - i) < Math.abs(a.index - i) ? b : a));
        return { match: `card field "${f[1]}" read and sent to ${dest.host}`, index: at };
      }
      if (near(hidden, i)) return { match: `card field "${f[1]}" read and sent to a decoded or runtime-built address`, index: at };
    }
    if (near(stashes, i)) return { match: `card field "${f[1]}" read and stashed in browser storage for later upload`, index: at };
  }
  return null;
}

// Credentials that should never ship to a browser. Formats are specific enough to avoid guesswork;
// generic "looks random" strings are deliberately not matched. The match is masked in reports.
const SECRETS = [
  ['private key', /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----\s*(?:\\n)?[A-Za-z0-9+/=\r\n]{60}/],
  ['AWS access key ID', /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/],
  ['Braintree/PayPal access token', /access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}/],
  ['Square OAuth secret', /\bsq0csp-[0-9A-Za-z_-]{43}\b/],
  ['Shopify admin/app token', /\bshp(?:at|ss|ca|pa)_[a-fA-F0-9]{32}\b/],
  ['GitHub token', /\b(?:gh[pousr]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82})\b/],
  ['Slack token', /\bxox[baprs]-[0-9A-Za-z]{10,}-[0-9A-Za-z-]{10,}/],
  ['SendGrid API key', /\bSG\.[\w-]{22}\.[\w-]{43}\b/],
  ['Mailchimp API key', /\b[0-9a-f]{32}-us\d{1,2}\b/],
  ['OpenAI/Anthropic API key', /\bsk-(?:proj-|ant-(?:api\d+-)?)?[A-Za-z0-9_-]{40,}\b/],
];
function secretTest(code) {
  for (const [kind, rx] of SECRETS) {
    const m = rx.exec(code);
    if (m) return { match: `${kind}: ${m[0].replace(/\s+/g, ' ').slice(0, 14)}…`, index: m.index };
  }
  return null;
}

// --- Loader / staging patterns ------------------------------------------------------
// Running code that just arrived over the network: new Function(event.data), eval(xhr.responseText),
// or eval/new Function inside a fetch(...).then(...) chain. Literal arguments (new Function('return this'))
// don't count.
const NET_SOURCE = /(\bfetch\s*\(|new\s+XMLHttpRequest|new\s+WebSocket\s*\(|addEventListener\s*\(\s*['"`]message['"`]|\.onmessage\s*=)/g;
const EXEC = /(?:\bnew\s+Function|(?<![.\w])eval)\s*\(\s*(?!['"`)])/g;
const EXEC_ON_DATA = /(?:\bnew\s+Function|(?<![.\w])eval)\s*\(\s*(?:\w+\.)?(?:data|responseText)\b/;
function remoteExecTest(code) {
  const m = EXEC_ON_DATA.exec(code);
  if (m && positions(NET_SOURCE, code).some((x) => Math.abs(x - m.index) <= PROXIMITY)) return { match: m[0], index: m.index };
  const sources = positions(NET_SOURCE, code);
  if (!sources.length) return null;
  for (const e of code.matchAll(EXEC)) {
    // Must come after a network call and inside its .then(...) chain, close by.
    const src = sources.filter((x) => x < e.index && e.index - x <= 600).pop();
    if (src !== undefined && /\.then\s*\(/.test(code.slice(src, e.index))) return { match: code.slice(src, Math.min(e.index + 30, src + 160)).replace(/\s+/g, ' '), index: e.index };
  }
  return null;
}

// Mr.SNIFFA-style steganography: spaces/tabs turned back into bits, bits into characters.
const WS_TO_BITS = /\.replace\(\s*\/(?: |\\s|\\t|\[ \]|\[\\t\])\/g\s*,\s*['"`][01]['"`]\s*\)/g;
function whitespaceDecodeTest(code) {
  for (const m of code.matchAll(WS_TO_BITS)) {
    const win = code.slice(m.index, m.index + 600);
    if (/parseInt\s*\([\s\S]{0,80}?,\s*2\s*\)/.test(win)) return { match: win.slice(0, 120).replace(/\s+/g, ' '), index: m.index };
  }
  return null;
}

// EtherHiding: read a value from a smart contract (eth_call) and use it to load or run code.
function blockchainLoaderTest(code) {
  const calls = positions(/['"`]eth_call['"`]/g, code);
  if (!calls.length) return null;
  const loads = positions(/(createElement\s*\(\s*['"`]script['"`]|\bnew\s+Function\s*\(|(?<![.\w])eval\s*\()/g, code);
  for (const c of calls) if (loads.some((x) => Math.abs(x - c) <= PROXIMITY)) return { match: 'eth_call result used to load or run code', index: c };
  return null;
}

// "Grab every input" harvesters with no card-field names (cside 2024): all inputs/selects/textareas
// collected and sent out, with the data encoded first. Medium: session-replay tools also read inputs.
const ALL_INPUTS = /querySelectorAll\s*\(\s*['"`]\s*input\s*,\s*select\s*,\s*textarea\s*['"`]\s*\)/g;
const ENCODE = /(btoa\s*\(|\.toString\s*\(\s*16\s*\)|charCodeAt\s*\([^)]{0,40}\)\s*\^)/g;
function genericHarvestTest(code) {
  const all = positions(ALL_INPUTS, code);
  if (!all.length) return null;
  const sends = positions(SEND, code), reads = positions(READ, code), enc = positions(ENCODE, code);
  const whole = code.length <= SMALL_FILE;
  const near = (list, i) => list.length > 0 && (whole || list.some((x) => Math.abs(x - i) <= PROXIMITY));
  for (const i of all) if (near(sends, i) && near(reads, i) && near(enc, i)) return { match: 'every input/select/textarea read, encoded and sent', index: i };
  return null;
}

// A "Google Tag Manager" snippet that decodes hidden code. The real GTM snippet never calls atob();
// fake ones (Confiant 2026, Sucuri 2025) wrap a base64 loader in GTM-looking markup.
function fakeGtmTest(code) {
  if (code.length > SMALL_FILE) return null;
  const gtm = /(GTM-[A-Z0-9]{4,}|googletagmanager|Google Tag Manager)/.exec(code);
  if (!gtm) return null;
  const dec = /(?<![.\w])atob\s*\(/.exec(code);
  return dec ? { match: `GTM-looking snippet (${gtm[1]}) calls atob()`, index: dec.index } : null;
}

export const RULES = [
  // --- Execution of hidden code -------------------------------------------
  {
    id: 'eval-decoded',
    severity: 'high',
    description: 'eval / Function called on decoded data (atob, unescape, fromCharCode)',
    test: re(/(?:\beval|\bFunction)\s*\(\s*(?:window\.)?(?:atob|unescape|decodeURIComponent|String\.fromCharCode)\s*\(/),
  },
  {
    id: 'script-injection-decoded',
    severity: 'high',
    description: 'Injects a <script> whose src or body comes from decoded data',
    test: re(/(?:src|innerHTML|text)\s*=\s*(?:window\.)?atob\s*\(/),
  },
  {
    id: 'document-write-script',
    severity: 'medium',
    description: 'document.write of a <script> tag',
    test: re(/document\.write(?:ln)?\s*\(\s*['"`][^'"`]{0,40}<\s*script/i),
  },
  {
    id: 'charcode-blob',
    severity: 'medium',
    description: 'Long String.fromCharCode sequence (common obfuscation)',
    test: re(/String\.fromCharCode\s*\(\s*(?:\d{2,3}\s*,\s*){30,}/),
  },
  {
    id: 'hex-escape-density',
    severity: 'medium',
    description: 'Dense \\xNN escaped string (obfuscated payload)',
    test: re(/(?:\\x[0-9a-fA-F]{2}){60,}/),
  },
  {
    id: 'base64-blob',
    severity: 'low',
    description: 'Very long base64 string literal (may hide a payload; also used for fonts/images)',
    test: (code) => {
      const m = code.match(/['"`]([A-Za-z0-9+/]{1500,}={0,2})['"`]/);
      if (!m) return null;
      // Ignore obvious data: URIs for images/fonts
      const before = code.slice(Math.max(0, m.index - 40), m.index);
      if (/data:(?:image|font|application\/font)/i.test(before)) return null;
      return { match: m[0].slice(0, 80) + '…', index: m.index };
    },
  },
  {
    id: 'obfuscator-io',
    severity: 'low',
    description: 'javascript-obfuscator style identifiers (_0x1a2b…)',
    test: (code) => {
      const hits = code.match(/\b_0x[a-f0-9]{4,6}\b/g);
      return hits && hits.length > 25 ? { match: `${hits.length} _0x identifiers, e.g. ${hits[0]}`, index: code.search(/\b_0x[a-f0-9]{4,6}\b/) } : null;
    },
  },

  // --- Card / credential skimming ------------------------------------------
  {
    id: 'skimmer-field-harvest',
    severity: 'high',
    description: 'Reads payment card fields and sends them to an external host',
    test: skimmerTest,
  },
  {
    id: 'credential-harvest',
    severity: 'medium',
    description: 'Reads password/login fields and encodes or beacons the data out',
    test: (code) => {
      // Password field + a beacon-style send, close together (same PROXIMITY idea as the card rule).
      // Stricter send set (no generic XHR/fetch) since plenty of legit login code posts passwords.
      // Selectors that *exclude* passwords (":not([type=password])") don't count.
      const fieldRx = /(?<!:not\(\[?)(type=["']?password|\[name=["']?(?:pass|pwd|password)|getElementById\(["'](?:pass|pwd|password))/gi;
      const sendRx = /(btoa\s*\([\s\S]{0,200}(?:sendBeacon|Image|WebSocket)|navigator\.sendBeacon|new\s+WebSocket\s*\(\s*['"`]wss?:|new\s+Image\s*\(\s*\)[\s\S]{0,200}\.src\s*=)/g;
      const sends = positions(sendRx, code);
      if (!sends.length) return null;
      const whole = code.length <= SMALL_FILE;
      for (const f of code.matchAll(fieldRx)) {
        if (whole || sends.some((x) => Math.abs(x - f.index) <= PROXIMITY)) return { match: `"${f[0]}" + beacon send nearby`, index: f.index };
      }
      return null;
    },
  },
  {
    id: 'keylogger',
    severity: 'medium',
    description: 'Document-wide key listener that collects keystrokes',
    // A document/window-wide key listener that ACCUMULATES key data (buf += e.key, log.push(e.keyCode),
    // String.fromCharCode(e.which)). Listeners that only check for a shortcut (ctrlKey + keyCode) don't count.
    test: (code) => {
      const LISTEN = /(?:document|window)\.(?:addEventListener\s*\(\s*['"`]key(?:down|up|press)['"`]|onkey(?:down|up|press)\s*=)/g;
      const COLLECT = /(?:\+=|\.push\s*\(|\.concat\s*\()\s*(?:String\.fromCharCode\s*\(\s*)?[\w$]+\.(?:key|keyCode|which|charCode|code)\b/;
      for (const m of code.matchAll(LISTEN)) {
        const win = code.slice(m.index, m.index + 400);
        if (COLLECT.test(win)) return { match: win.slice(0, 160).replace(/\s+/g, ' '), index: m.index };
      }
      return null;
    },
  },

  // --- Cryptomining --------------------------------------------------------
  {
    id: 'cryptominer',
    severity: 'high',
    description: 'Known in-browser cryptominer signature',
    test: re(/\b(coinhive|coin-hive|CoinImp|cryptonight|CryptoLoot|webminepool|jsecoin|deepMiner|minero\.cc|\.Anonymous\s*\(\s*['"`][a-f0-9]{30,})/i),
  },

  // --- Redirects / cloaking ------------------------------------------------
  {
    id: 'cloaked-redirect',
    severity: 'medium',
    description: 'Redirect gated on referrer/user-agent/cookie (common SEO-spam / malvertising pattern)',
    test: re(/(?:document\.referrer|navigator\.userAgent|document\.cookie)[\s\S]{0,250}(?:window\.|document\.|top\.)?location(?:\.href)?\s*(?:=|\.replace\s*\(|\.assign\s*\()/),
  },
  {
    id: 'stripe-secret-key',
    severity: 'high',
    description: 'Stripe secret/restricted API key in browser code (never legitimate; skimmers use one to write stolen cards into their own Stripe account)',
    test: (code) => {
      const m = /\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{10,}/.exec(code);
      return m ? { match: m[0].slice(0, 12) + '…', index: m.index } : null;
    },
  },
  {
    id: 'exposed-secret',
    severity: 'medium',
    description: 'Credential that should never be in browser code (private key, cloud or SaaS API token)',
    test: secretTest,
  },
  {
    id: 'remote-code-exec',
    severity: 'high',
    description: 'Runs code received over the network (eval / new Function on fetched or WebSocket data)',
    test: remoteExecTest,
  },
  {
    id: 'whitespace-decode',
    severity: 'high',
    description: 'Decodes a payload hidden as whitespace (spaces/tabs → bits → characters)',
    test: whitespaceDecodeTest,
  },
  {
    id: 'blockchain-loader',
    severity: 'high',
    description: 'Reads a smart contract (eth_call) and uses the result to load or run code (EtherHiding)',
    test: blockchainLoaderTest,
  },
  {
    id: 'fake-gtm-loader',
    severity: 'high',
    description: 'Google-Tag-Manager-looking snippet that decodes hidden code (real GTM snippets never call atob)',
    test: fakeGtmTest,
  },
  {
    id: 'form-harvest-generic',
    severity: 'medium',
    description: 'Reads every input/select/textarea, encodes the values and sends them out',
    test: genericHarvestTest,
  },
  {
    id: 'encoded-redirect',
    severity: 'high',
    description: 'Redirect to a decoded URL',
    test: re(/location(?:\.href)?\s*(?:=|\.replace\s*\(|\.assign\s*\()\s*(?:window\.)?(?:atob|unescape|String\.fromCharCode)\s*\(/),
  },
];

// extraRules: custom rules from config (same { id, severity, description, test } shape).
export function analyzeCode(code, extraRules = []) {
  if (!code || typeof code !== 'string') return [];
  // Cap analysis size so a huge bundle can't stall the job.
  const sample = code.length > 3_000_000 ? code.slice(0, 3_000_000) : code;
  const flags = [];
  for (const rule of extraRules.length ? RULES.concat(extraRules) : RULES) {
    let hit = null;
    try {
      hit = rule.test(sample);
    } catch {
      /* ignore regex blowups */
    }
    if (!hit) continue;
    const { match, index } = typeof hit === 'string' ? { match: hit, index: sample.indexOf(hit) } : hit;
    const flag = { rule: rule.id, severity: rule.severity, description: rule.description, match, ...(rule.custom ? { custom: true } : {}) };
    if (index >= 0) Object.assign(flag, locate(sample, index));
    flags.push(flag);
  }
  return flags;
}

// 1-based line/column of a character offset, plus a one-line snippet around it (minified code is
// often one huge line, so the snippet is cut to ~70 chars either side).
export function locate(code, index) {
  let line = 1;
  let lineStart = 0;
  for (let i = code.indexOf('\n'); i !== -1 && i < index; i = code.indexOf('\n', i + 1)) {
    line++;
    lineStart = i + 1;
  }
  const from = Math.max(lineStart, index - 70);
  const lineEnd = code.indexOf('\n', index);
  const to = Math.min(lineEnd === -1 ? code.length : lineEnd, index + 70);
  const context = (from > lineStart ? '…' : '') + code.slice(from, to).replace(/\s+/g, ' ').trim() + (to < (lineEnd === -1 ? code.length : lineEnd) ? '…' : '');
  return { line, column: index - lineStart + 1, context };
}
