// Google Tag Manager tag identification.
//
// A published container (googletagmanager.com/gtm.js?id=GTM-XXXX) includes every tag's code and
// numeric tag ID, but not the tag *names*; those exist only in the GTM admin. The ID is the number
// at the end of the tag's URL in the GTM interface (…/tags/107), so it's enough to jump to the tag.

// Friendly names for common built-in tag types ("function" in the container).
const TAG_TYPES = {
  __html: 'Custom HTML',
  __img: 'Custom Image',
  __awct: 'Google Ads Conversion Tracking',
  __sp: 'Google Ads Remarketing',
  __gclidw: 'Conversion Linker',
  __googtag: 'Google Tag',
  __gaawe: 'GA4 Event',
  __gaawc: 'GA4 Configuration',
  __ua: 'Universal Analytics',
  __flc: 'Floodlight Counter',
  __fls: 'Floodlight Sales',
  __bzi: 'LinkedIn Insight',
  __hjtc: 'Hotjar Tracking',
  __twitter_website_tag: 'Twitter/X Pixel',
  __baut: 'Microsoft Ads UET',
  __crto: 'Criteo OneTag',
  __pntr: 'Pinterest Tag',
  __paused: 'Paused tag',
};
// Built-in auto-event listeners and trigger groups also sit in the "tags" array; they never load scripts.
const NOT_TAGS = new Set(['__cl', '__tg', '__lcl', '__fsl', '__hl', '__evl', '__sdl', '__tl', '__ytl', '__jel', '__ctv']);
export const tagTypeName = (fn) => TAG_TYPES[fn] || (fn?.startsWith('__cvt_') ? 'Custom Template' : fn || 'unknown');

export const containerIdOf = (url) => {
  try {
    const u = new URL(url);
    return /(^|\.)googletagmanager\.com$/.test(u.hostname) && u.pathname === '/gtm.js' ? u.searchParams.get('id') : null;
  } catch {
    return null;
  }
};

// Extract the container's "tags":[…] array (it's JSON inside the JS) without evaluating anything.
export function parseGtmTags(body) {
  const start = body.indexOf('"tags":[');
  if (start === -1) return [];
  let i = start + 7;
  let depth = 0;
  let inStr = false;
  for (; i < body.length; i++) {
    const ch = body[i];
    if (inStr) {
      if (ch === '\\') i++;
      else if (ch === '"') inStr = false;
    } else if (ch === '"') inStr = true;
    else if (ch === '[') depth++;
    else if (ch === ']' && --depth === 0) break;
  }
  try {
    return JSON.parse(body.slice(start + 7, i + 1))
      .filter((t) => t && typeof t === 'object' && t.tag_id != null && !NOT_TAGS.has(t.function))
      .map((t) => ({ id: t.tag_id, fn: t.function, type: tagTypeName(t.function), text: flatten(t) }));
  } catch {
    return [];
  }
}

// All string/number values of a tag, joined, so URLs, IDs and HTML can be searched in one place.
function flatten(v, out = []) {
  if (typeof v === 'string' || typeof v === 'number') out.push(String(v));
  else if (Array.isArray(v)) v.forEach((x) => flatten(x, out));
  else if (v && typeof v === 'object') Object.values(v).forEach((x) => flatten(x, out));
  return out.join('\n');
}

const squash = (s) => s.replace(/\s+/g, ' ').trim();

/**
 * Which tags in a container could have added this script? Matches, in order of confidence:
 * the script's full URL, URL without query, path, or a distinctive query value (conversion/pixel IDs)
 * appearing in the tag; or, for inline code, an 80-character slice of the code appearing in a
 * Custom HTML tag. Returns up to 3 tags, Custom HTML first.
 */
export function matchGtmTags(tags, { url, code }) {
  const needles = [];
  if (code) {
    const c = squash(code);
    if (c.length >= 30) needles.push(c.slice(0, 80));
  }
  if (url && /^https?:/.test(url)) {
    const u = new URL(url);
    needles.push(url, url.split('?')[0], u.host + u.pathname);
    if (u.pathname.length >= 10) needles.push(u.pathname);
    for (const v of u.searchParams.values()) if (/^[A-Za-z0-9_-]{6,}$/.test(v) && !/^\d{1,5}$/.test(v)) needles.push(v.replace(/^(AW|G|UA|DC)-/, ''));
  }
  const hits = tags.filter((t) => {
    const text = code ? squash(t.text) : t.text;
    return needles.some((n) => n && text.includes(n));
  });
  hits.sort((a, b) => Number(b.fn === '__html') - Number(a.fn === '__html'));
  return hits.slice(0, 3).map(({ id, type }) => ({ id, type }));
}
