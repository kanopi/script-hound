// ScriptHound brand: name, tagline, colors and logo SVGs (from brand/, see brand/README.md).
//
// The SVGs in brand/ carry a C2PA content-credentials manifest in <metadata>. That's kept in the
// source files, but stripped here before a logo is inlined into a report (it's large and not needed).
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export const NAME = 'ScriptHound';
export const TAGLINE = 'Sniffs out malicious front-end code';
export const COLORS = { navy: '#14213D', amber: '#F77F00', cream: '#F4F1EA', earBrown: '#B5835A', slate: '#5B6475' };

const BRAND_DIR = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'brand');
const cache = new Map();

/** A brand SVG with metadata, comments and the width/height attributes removed (sized by CSS). '' if missing. */
export function brandSvg(name) {
  if (cache.has(name)) return cache.get(name);
  let svg = '';
  try {
    svg = fs
      .readFileSync(path.join(BRAND_DIR, `${name}.svg`), 'utf8')
      .replace(/<metadata>[\s\S]*?<\/metadata>/g, '')
      .replace(/<!--[\s\S]*?-->/g, '')
      .replace(/\s+xmlns:c2pa="[^"]*"/, '')
      .replace(/(<svg\b[^>]*?)\s+width="[^"]*"/, '$1')
      .replace(/(<svg\b[^>]*?)\s+height="[^"]*"/, '$1')
      .replace(/>\s+</g, '><')
      .trim();
  } catch {
    svg = '';
  }
  cache.set(name, svg);
  return svg;
}

/** data: URI for an SVG (favicons). */
export const svgDataUri = (svg) => (svg ? `data:image/svg+xml;charset=utf-8,${encodeURIComponent(svg)}` : '');

/** "ScriptHound" with "Hound" in amber, for terminal output (c = makeColors(...)). */
export const consoleName = (c) => `${c.bold('Script')}${c.bold(c.yellow('Hound'))}`;

export const VERSION = (() => {
  try {
    return JSON.parse(fs.readFileSync(path.join(BRAND_DIR, '..', 'package.json'), 'utf8')).version || '';
  } catch {
    return '';
  }
})();
