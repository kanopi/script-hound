// Known-vulnerable JavaScript library detection, using the Retire.js database
// (data/retire-jsrepository.json, Apache-2.0; refresh with `make update-vulndb`).
//
// Uses Retire.js's "uri", "filename", "filecontent" and "hashes" extractors. The "func" and "ast"
// extractors would need code to run in the page or a parser, so they're not used.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';

const DB_PATH = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'data', 'retire-jsrepository.json');
const VERSION = '[0-9][0-9.a-z_\\-]+';

let db = null;
function load() {
  if (db) return db;
  let raw = {};
  try {
    raw = JSON.parse(fs.readFileSync(DB_PATH, 'utf8'));
  } catch {
    raw = {};
  }
  const compile = (list = []) =>
    list
      .map((p) => {
        try {
          return new RegExp(p.replace(/§§version§§/g, VERSION));
        } catch {
          return null;
        }
      })
      .filter(Boolean);
  db = Object.entries(raw)
    .filter(([name, lib]) => lib.vulnerabilities?.length && name !== 'retire-example')
    .map(([name, lib]) => ({
      name,
      vulnerabilities: lib.vulnerabilities,
      uri: compile(lib.extractors?.uri),
      filename: compile(lib.extractors?.filename),
      filecontent: compile(lib.extractors?.filecontent),
      hashes: lib.extractors?.hashes || {},
    }));
  return db;
}

// Retire.js-style comparison: numeric parts numerically, otherwise as strings; a pre-release
// ("3.0.0-beta") sorts before its release ("3.0.0").
export function compareVersions(a, b) {
  const pa = String(a).split(/[.-]/);
  const pb = String(b).split(/[.-]/);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const x = pa[i];
    const y = pb[i];
    if (x === undefined) return /^\d+$/.test(y) ? (Number(y) === 0 ? 0 : -1) : 1;
    if (y === undefined) return /^\d+$/.test(x) ? (Number(x) === 0 ? 0 : 1) : -1;
    const nx = /^\d+$/.test(x);
    const ny = /^\d+$/.test(y);
    if (nx && ny) {
      if (Number(x) !== Number(y)) return Number(x) < Number(y) ? -1 : 1;
    } else if (nx !== ny) return nx ? 1 : -1;
    else if (x !== y) return x < y ? -1 : 1;
  }
  return 0;
}

const affects = (v, version) =>
  (!v.below || compareVersions(version, v.below) < 0) && (!v.atOrAbove || compareVersions(version, v.atOrAbove) >= 0);

/**
 * Detect vulnerable libraries in one script. Returns [{ library, version, detectedBy, severity,
 * vulnerabilities: [{ severity, summary, cves, info }] }] (only libraries with known issues).
 */
export function detectVulnerableLibraries({ url = '', code = '' }) {
  const out = [];
  const file = url ? url.split(/[?#]/)[0].split('/').pop() : '';
  const sample = code.length > 3_000_000 ? code.slice(0, 3_000_000) : code;
  let sha1 = null;
  for (const lib of load()) {
    let version = null;
    let by = null;
    for (const [kind, list, text] of [
      ['url', lib.uri, url],
      ['filename', lib.filename, file],
      ['file content', lib.filecontent, sample],
    ]) {
      if (version || !text) continue;
      for (const rx of list) {
        const m = rx.exec(text);
        if (m && m[1]) {
          version = m[1].replace(/\.min$/, '');
          by = kind;
          break;
        }
      }
    }
    if (!version && code && Object.keys(lib.hashes).length) {
      sha1 ||= crypto.createHash('sha1').update(code).digest('hex');
      if (lib.hashes[sha1]) {
        version = lib.hashes[sha1];
        by = 'file hash';
      }
    }
    if (!version) continue;
    const vulns = lib.vulnerabilities.filter((v) => affects(v, version));
    if (!vulns.length) continue;
    const rank = { low: 1, medium: 2, high: 3, critical: 4 };
    const worst = vulns.reduce((a, v) => ((rank[v.severity] || 0) > (rank[a] || 0) ? v.severity : a), 'low');
    out.push({
      library: lib.name,
      version,
      detectedBy: by,
      severity: worst,
      vulnerabilities: vulns.map((v) => ({
        severity: v.severity,
        summary: v.identifiers?.summary || '',
        cves: v.identifiers?.CVE || [],
        info: (v.info || []).slice(0, 2),
      })),
    });
  }
  return out;
}

export const vulnDbInfo = () => ({ libraries: load().length, path: DB_PATH });
