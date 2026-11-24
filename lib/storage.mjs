// Browser-storage inventory: localStorage / sessionStorage (page and iframe origins), IndexedDB,
// Cache Storage and service workers. Plus the card-data honeytoken check: the scanner types a known
// dummy card number into forms, so finding it in storage (raw or encoded) means a script is stashing
// what visitors type.
//
// Reports get a short, masked preview of each value, never the full value.

export const DUMMY_CARD = '4111111111111111';

const MAX_FRAMES = 12;
const MAX_KEYS = 300;
const MAX_VALUE = 20000; // characters inspected per value (card search, classification)

/** Read storage in the page and in each distinct iframe origin. Values are kept only in memory. */
export async function collectStorage(page) {
  const seen = new Set();
  const out = { entries: [], indexedDB: [], caches: [], cacheBodies: [], serviceWorkers: [], opfs: [], usage: [], webSql: false, windowName: [], historyState: [], buckets: [] };
  for (const frame of page.frames().slice(0, 40)) {
    let origin;
    try {
      origin = new URL(frame.url()).origin;
    } catch {
      continue;
    }
    if (!/^https?:/.test(origin) || seen.has(origin) || seen.size >= MAX_FRAMES) continue;
    seen.add(origin);
    const data = await frame
      .evaluate(
        async ({ MAX_KEYS, MAX_VALUE, isTop }) => {
          const r = { entries: [], indexedDB: [], caches: [], serviceWorkers: [], opfs: [], usage: null, webSql: typeof window.openDatabase === 'function' };
          for (const type of ['localStorage', 'sessionStorage']) {
            try {
              const st = window[type];
              for (let i = 0; i < Math.min(st.length, MAX_KEYS); i++) {
                const key = st.key(i);
                const v = String(st.getItem(key) ?? '');
                r.entries.push({ type, key, size: v.length, value: v.slice(0, MAX_VALUE) });
              }
            } catch {
              // blocked (e.g. sandboxed frame)
            }
          }
          try {
            if (indexedDB.databases) {
              for (const db of (await indexedDB.databases()).slice(0, 20)) {
                const info = { name: db.name, version: db.version, stores: [] };
                try {
                  // Open without a version so nothing is created or upgraded.
                  const conn = await new Promise((res, rej) => {
                    const req = indexedDB.open(db.name);
                    req.onsuccess = () => res(req.result);
                    req.onerror = () => rej(req.error);
                    req.onupgradeneeded = () => {
                      req.transaction.abort();
                      rej(new Error('would upgrade'));
                    };
                  });
                  for (const s of [...conn.objectStoreNames].slice(0, 30)) {
                    const count = await new Promise((res) => {
                      try {
                        const q = conn.transaction(s, 'readonly').objectStore(s).count();
                        q.onsuccess = () => res(q.result);
                        q.onerror = () => res(null);
                      } catch {
                        res(null);
                      }
                    });
                    // Sample up to 20 records per store (stringified, capped) so they can be checked for
                    // code and the card honeytoken like other storage values.
                    const samples = await new Promise((res) => {
                      try {
                        const q = conn.transaction(s, 'readonly').objectStore(s).getAll(null, 50);
                        q.onsuccess = () =>
                          res(
                            (q.result || []).map((v) => {
                              let t;
                              try {
                                t = typeof v === 'string' ? v : JSON.stringify(v);
                              } catch {
                                t = String(v);
                              }
                              return String(t ?? '').slice(0, 4000);
                            })
                          );
                        q.onerror = () => res([]);
                      } catch {
                        res([]);
                      }
                    });
                    info.stores.push({ name: s, count, samples });
                  }
                  conn.close();
                } catch {
                  // unreadable database: keep the name
                }
                r.indexedDB.push(info);
              }
            }
          } catch {
            // IndexedDB unavailable
          }
          // Cache Storage: names, entry counts, and the bodies of text responses (scripts, CSS, HTML,
          // JSON) so they can be checked like any other code. Budgeted to keep big PWA caches cheap.
          r.cacheBodies = [];
          let budget = 5_000_000;
          try {
            if (window.caches) {
              for (const name of (await caches.keys()).slice(0, 30)) {
                const c = await caches.open(name);
                const reqs = await c.keys();
                r.caches.push({ name, entries: reqs.length });
                for (const req of reqs.slice(0, 50)) {
                  if (budget <= 0) break;
                  const res = await c.match(req);
                  const type = (res?.headers.get('content-type') || '').toLowerCase();
                  if (!res || !/(javascript|ecmascript|css|html|json|text|xml)/.test(type) && !/\.(m?js|css|html?|json)(\?|$)/i.test(req.url)) continue;
                  const body = (await res.text()).slice(0, 300_000);
                  budget -= body.length;
                  r.cacheBodies.push({ cache: name, url: req.url, type, body });
                }
              }
            }
          } catch {
            // Cache Storage unavailable (insecure context)
          }
          // window.name and history.state survive navigations, so they're used to smuggle data/payloads.
          try {
            r.windowName = String(window.name || '').slice(0, 100_000);
          } catch {
            r.windowName = '';
          }
          try {
            r.historyState = history.state == null ? '' : JSON.stringify(history.state).slice(0, 100_000);
          } catch {
            r.historyState = '';
          }
          // Storage Buckets (newer Chrome): names only.
          try {
            r.buckets = navigator.storageBuckets?.keys ? await navigator.storageBuckets.keys() : [];
          } catch {
            r.buckets = [];
          }
          // Origin Private File System: where in-browser SQLite (WASM) and other app files live.
          try {
            if (navigator.storage?.getDirectory) {
              const walk = async (dir, prefix, depth) => {
                for await (const [name, h] of dir.entries()) {
                  if (r.opfs.length >= 100) return;
                  const p = prefix + '/' + name;
                  if (h.kind === 'file') {
                    const f = await h.getFile();
                    const head = new Uint8Array(await f.slice(0, 16).arrayBuffer());
                    // First 1 MB as text (latin1, so binary SQLite pages keep their embedded strings).
                    const bytes = new Uint8Array(await f.slice(0, 1_000_000).arrayBuffer());
                    let text = '';
                    for (let i = 0; i < bytes.length; i += 8192) text += String.fromCharCode(...bytes.subarray(i, i + 8192));
                    r.opfs.push({ path: p, size: f.size, sqlite: String.fromCharCode(...head) === 'SQLite format 3\u0000', text });
                  } else if (depth < 4) {
                    r.opfs.push({ path: p + '/', size: null });
                    await walk(h, p, depth + 1);
                  }
                }
              };
              await walk(await navigator.storage.getDirectory(), '', 0);
            }
          } catch {
            // OPFS unavailable
          }
          try {
            const est = await navigator.storage?.estimate?.();
            if (est) r.usage = { usage: est.usage, quota: est.quota };
          } catch {
            // unavailable
          }
          if (isTop) {
            try {
              for (const reg of (await navigator.serviceWorker?.getRegistrations?.()) || []) {
                const w = reg.active || reg.waiting || reg.installing;
                // The worker's own code (same origin): a malicious worker persists and can rewrite responses.
                let code = '';
                try {
                  if (w?.scriptURL) code = (await (await fetch(w.scriptURL, { cache: 'force-cache' })).text()).slice(0, 2_000_000);
                } catch {
                  code = '';
                }
                r.serviceWorkers.push({ scope: reg.scope, scriptURL: w?.scriptURL || '', state: w?.state || '', code });
              }
            } catch {
              // unavailable
            }
          }
          return r;
        },
        { MAX_KEYS, MAX_VALUE, isTop: frame === page.mainFrame() }
      )
      .catch(() => null);
    if (!data) continue;
    for (const e of data.entries) out.entries.push({ origin, ...e });
    for (const d of data.indexedDB) out.indexedDB.push({ origin, ...d });
    for (const c of data.caches) out.caches.push({ origin, ...c });
    out.serviceWorkers.push(...data.serviceWorkers);
    for (const f of data.opfs) out.opfs.push({ origin, ...f });
    if (data.usage) out.usage.push({ origin, ...data.usage });
    if (data.webSql) out.webSql = true;
    for (const b of data.cacheBodies || []) out.cacheBodies.push({ origin, ...b });
    if (data.windowName) out.windowName.push({ origin, value: data.windowName });
    if (data.historyState) out.historyState.push({ origin, value: data.historyState });
    for (const b of data.buckets || []) out.buckets.push({ origin, name: b });
  }
  return out;
}

/** What kind of value this is, for the inventory. */
export function classify(v) {
  const t = v.trim();
  if (!t) return 'empty';
  if (/^(Bearer\s+)?eyJ[\w-]{8,}\.eyJ[\w-]{8,}\.[\w-]*$/.test(t)) return 'jwt';
  if (/^-?\d+(\.\d+)?$/.test(t)) return 'number';
  if (/^(true|false|null)$/.test(t)) return 'boolean';
  if (/^[[{]/.test(t)) {
    try {
      JSON.parse(t);
      return 'json';
    } catch {
      // fall through
    }
  }
  if (/^https?:\/\//.test(t)) return 'url';
  if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(t)) return 'uuid';
  if (t.length >= 16 && /^[0-9a-f]+$/i.test(t) && /\d/.test(t) && /[a-f]/i.test(t)) return 'hex blob';
  // Short base64 needs padding or a mix of cases and digits, so long plain words aren't mislabelled.
  if (t.length >= 16 && /^[A-Za-z0-9+/_-]+={0,2}$/.test(t) && (/=$/.test(t) || t.length >= 32 || (/[A-Z]/.test(t) && /[a-z]/.test(t) && /\d/.test(t)))) return 'base64 blob';
  return 'text';
}

/** Short, single-line preview with tokens masked. */
export function preview(v, kind) {
  if (kind === 'jwt') return `eyJ… (JWT, ${v.length} chars)`;
  const one = v.replace(/\s+/g, ' ').trim();
  const masked = one.replace(/eyJ[\w-]{8,}\.eyJ[\w-]{8,}\.[\w-]*/g, 'eyJ…(JWT)');
  return masked.length > 70 ? masked.slice(0, 70) + '…' : masked;
}

// Card-data honeytoken: the dummy card number, raw or in a common encoding. Returns how it was found.
const toHex = (s) => [...s].map((c) => c.charCodeAt(0).toString(16).padStart(2, '0')).join('');
export function findDummyCard(value) {
  if (!value) return null;
  const v = String(value);
  if (v.includes(DUMMY_CARD) || v.replace(/[\s-]/g, '').includes(DUMMY_CARD)) return 'as-is';
  try {
    if (decodeURIComponent(v).replace(/[\s-]/g, '').includes(DUMMY_CARD)) return 'URL-encoded';
  } catch {
    // not URL-encoded
  }
  if (v.toLowerCase().includes(toHex(DUMMY_CARD))) return 'hex-encoded';
  // base64 (standard or URL-safe), possibly nested once.
  for (const m of v.matchAll(/[A-Za-z0-9+/_-]{16,}={0,2}/g)) {
    for (const candidate of [m[0], m[0].replace(/-/g, '+').replace(/_/g, '/')]) {
      let dec;
      try {
        dec = Buffer.from(candidate, 'base64').toString('latin1');
      } catch {
        continue;
      }
      if (dec.includes(DUMMY_CARD)) return 'base64-encoded';
      if (/^[A-Za-z0-9+/=]{16,}$/.test(dec.trim())) {
        try {
          if (Buffer.from(dec.trim(), 'base64').toString('latin1').includes(DUMMY_CARD)) return 'double base64-encoded';
        } catch {
          // not nested
        }
      }
      if (dec.toLowerCase().includes(toHex(DUMMY_CARD))) return 'base64 of hex';
    }
  }
  return null;
}

// Does a stored value look like JavaScript (rather than data)? Needs several code markers, so JSON,
// URLs and prose don't count. Used for the `code-in-storage` note; pattern rules run on every value anyway.
const CODE_MARKERS = [/\bfunction\s*\(/, /=>\s*[{(]/, /\bdocument\.(createElement|querySelector|getElementById|cookie|write)/, /\bwindow\.[a-zA-Z]/, /\b(eval|new Function)\s*\(/, /\baddEventListener\s*\(/, /\b(var|let|const)\s+[A-Za-z_$][\w$]*\s*=/, /\breturn\b[^;]{0,80};/];
export function looksLikeCode(v) {
  if (!v || v.length < 80) return false;
  return CODE_MARKERS.filter((rx) => rx.test(v)).length >= 3;
}

// If a value is base64 that decodes to readable text, return the decoded text (for code checks).
export function decodeBase64Text(v) {
  const t = String(v || '').trim();
  if (t.length < 40 || !/^[A-Za-z0-9+/_-]+={0,2}$/.test(t)) return null;
  try {
    const dec = Buffer.from(t.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8');
    const printable = dec.replace(/[\x20-\x7e\s]/g, '').length / Math.max(1, dec.length) < 0.05;
    return printable ? dec : null;
  } catch {
    return null;
  }
}
