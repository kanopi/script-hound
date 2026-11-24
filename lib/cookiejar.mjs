// Cookie jar files, curl-style: read cookies before a scan (like `curl -b file`) and write them after
// (like `curl -c file`). Reads curl/Netscape format or Playwright JSON (storage state or a plain array);
// writes Netscape format so the jar also works with curl and wget.
//
// Unlike reports, a jar holds cookie VALUES (that's its purpose), so it's written with mode 0600.
import fs from 'node:fs';

const SAME_SITE = { strict: 'Strict', lax: 'Lax', none: 'None' };

/** Parse a jar file's text into Playwright cookies. Expired cookies are dropped. */
export function parseCookieJar(text, where = 'cookie file') {
  const t = text.trim();
  const now = Date.now() / 1000;
  if (t.startsWith('{') || t.startsWith('[')) {
    let data;
    try {
      data = JSON.parse(t);
    } catch (e) {
      throw new Error(`${where}: invalid JSON (${e.message})`);
    }
    const list = Array.isArray(data) ? data : data.cookies;
    if (!Array.isArray(list)) throw new Error(`${where}: expected a cookie array or a Playwright storage state ({ "cookies": [...] })`);
    return list
      .filter((c) => c && c.name && c.domain)
      .filter((c) => !(c.expires > 0 && c.expires < now))
      .map((c) => ({
        name: c.name,
        value: String(c.value ?? ''),
        domain: c.domain,
        path: c.path || '/',
        expires: c.expires > 0 ? c.expires : -1,
        httpOnly: !!c.httpOnly,
        secure: !!c.secure,
        ...(c.sameSite ? { sameSite: SAME_SITE[String(c.sameSite).toLowerCase()] || 'Lax' } : {}),
      }));
  }
  // Netscape: domain, include-subdomains flag, path, secure, expiry (epoch, 0 = session), name, value.
  // curl marks HttpOnly cookies by prefixing the domain with "#HttpOnly_".
  const out = [];
  for (const raw of t.split(/\r?\n/)) {
    let line = raw;
    let httpOnly = false;
    if (line.startsWith('#HttpOnly_')) {
      httpOnly = true;
      line = line.slice('#HttpOnly_'.length);
    } else if (!line.trim() || line.startsWith('#')) continue;
    const f = line.split('\t');
    if (f.length < 7) throw new Error(`${where}: not a Netscape cookie line (need 7 tab-separated fields): ${raw.slice(0, 80)}`);
    const [domain, , path, secure, expiry, name, ...rest] = f;
    const exp = Number(expiry);
    if (exp > 0 && exp < now) continue;
    out.push({ name, value: rest.join('\t'), domain, path: path || '/', expires: exp > 0 ? exp : -1, httpOnly, secure: secure.toUpperCase() === 'TRUE' });
  }
  return out;
}

export function readCookieJar(file) {
  return parseCookieJar(fs.readFileSync(file, 'utf8'), file);
}

/** Write Playwright cookies to a Netscape-format jar, readable by the owner only. */
export function writeCookieJar(file, cookies) {
  const lines = ['# Netscape HTTP Cookie File', '# Written by ScriptHound. Contains live cookie values: keep it private.', ''];
  for (const c of cookies) {
    const sub = c.domain.startsWith('.') ? 'TRUE' : 'FALSE';
    const exp = c.expires > 0 ? Math.round(c.expires) : 0;
    lines.push(`${c.httpOnly ? '#HttpOnly_' : ''}${c.domain}\t${sub}\t${c.path || '/'}\t${c.secure ? 'TRUE' : 'FALSE'}\t${exp}\t${c.name}\t${c.value}`);
  }
  fs.writeFileSync(file, lines.join('\n') + '\n', { mode: 0o600 });
  fs.chmodSync(file, 0o600); // also tighten an existing file
}
