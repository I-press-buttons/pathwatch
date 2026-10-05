// Small shared helpers: DOM builder, formatting, hash/query handling, colour parsing.

/** Hyperscript-style DOM builder. Children may be nodes, strings, numbers, arrays or null. Never uses innerHTML. */
export function h(tag, attrs, ...children) {
  const el = document.createElement(tag);
  if (attrs) {
    for (const [k, v] of Object.entries(attrs)) {
      if (v == null || v === false) continue;
      if (k === 'class') el.className = v;
      else if (k === 'style') { if (typeof v === 'object') Object.assign(el.style, v); } // a string would become a style attribute, which the CSP blocks
      else if (k === 'dataset') Object.assign(el.dataset, v);
      else if (k.startsWith('on') && typeof v === 'function') el.addEventListener(k.slice(2).toLowerCase(), v);
      else if (v === true) el.setAttribute(k, '');
      else el.setAttribute(k, String(v));
    }
  }
  append(el, children);
  return el;
}
function append(el, children) {
  for (const c of children) {
    if (c == null || c === false) continue;
    if (Array.isArray(c)) append(el, c);
    else if (c instanceof Node) el.appendChild(c);
    else el.appendChild(document.createTextNode(String(c)));
  }
}
export function clear(el) { while (el.firstChild) el.removeChild(el.firstChild); return el; }
export function setChildren(el, ...children) { clear(el); append(el, children); return el; }

const SVGNS = 'http://www.w3.org/2000/svg';
export function svg(tag, attrs, ...children) {
  const el = document.createElementNS(SVGNS, tag);
  if (attrs) for (const [k, v] of Object.entries(attrs)) if (v != null) el.setAttribute(k, String(v));
  for (const c of children) if (c != null) el.appendChild(typeof c === 'string' ? document.createTextNode(c) : c);
  return el;
}

// ---------- number formatting ----------
export const DASH = '–';
export function isNum(v) { return typeof v === 'number' && Number.isFinite(v); }
/** ms with 1 decimal; below 10 ms use 2 decimals. */
export function fmtMs(v) {
  if (!isNum(v)) return DASH;
  return v < 10 ? v.toFixed(2) : v.toFixed(1);
}
export function fmtMsU(v) { return isNum(v) ? fmtMs(v) + ' ms' : DASH; }
export function fmtPct(v) { return isNum(v) ? v.toFixed(1) + '%' : DASH; }
export function fmtMos(v) { return isNum(v) ? v.toFixed(2) : DASH; }
export function fmtInt(v) { return isNum(v) ? Math.round(v).toLocaleString() : DASH; }

export function fmtDuration(ms) {
  if (!isNum(ms)) return DASH;
  ms = Math.max(0, ms);
  const s = Math.round(ms / 1000);
  if (s < 60) return s + 's';
  const m = Math.floor(s / 60);
  if (m < 60) return m + 'm ' + String(s % 60).padStart(2, '0') + 's';
  const hh = Math.floor(m / 60);
  if (hh < 48) return hh + 'h ' + String(m % 60).padStart(2, '0') + 'm';
  const d = Math.floor(hh / 24);
  return d + 'd ' + (hh % 24) + 'h';
}

// ---------- time formatting (always the browser's local timezone) ----------
const dfCache = {};
function df(key, opts) { return dfCache[key] || (dfCache[key] = new Intl.DateTimeFormat(undefined, opts)); }
export function fmtTime(ts) { return isNum(ts) ? df('t', { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false }).format(ts) : DASH; }
export function fmtHM(ts) { return df('hm', { hour: '2-digit', minute: '2-digit', hour12: false }).format(ts); }
export function fmtDateTime(ts) {
  if (!isNum(ts)) return DASH;
  return df('dt', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false }).format(ts);
}
export function fmtDay(ts) { return df('d', { month: 'short', day: 'numeric' }).format(ts); }
export function fmtAgo(ts, now = Date.now()) {
  if (!isNum(ts)) return DASH;
  const d = now - ts;
  if (d < 0) return 'in ' + fmtDuration(-d);
  if (d < 5000) return 'just now';
  return fmtDuration(d) + ' ago';
}
/** Value for <input type=datetime-local> in local time. */
export function toLocalInput(ts) {
  const d = new Date(ts);
  const p = (n) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}T${p(d.getHours())}:${p(d.getMinutes())}`;
}
export function fromLocalInput(s) { const t = new Date(s).getTime(); return Number.isFinite(t) ? t : null; }

// ---------- misc ----------
export function clamp(v, a, b) { return Math.min(b, Math.max(a, v)); }
export function percentile(sorted, p) {
  if (!sorted.length) return null;
  const i = clamp(Math.ceil(p * sorted.length) - 1, 0, sorted.length - 1);
  return sorted[i];
}
export function throttle(fn, ms) {
  let last = 0, timer = null, pending = null;
  const run = () => { timer = null; last = Date.now(); fn(...pending); };
  const t = (...args) => {
    pending = args;
    const wait = ms - (Date.now() - last);
    if (wait <= 0) { if (timer) clearTimeout(timer); run(); }
    else if (!timer) timer = setTimeout(run, wait);
  };
  t.cancel = () => { if (timer) clearTimeout(timer); timer = null; };
  return t;
}
export function debounce(fn, ms) {
  let timer = null;
  const d = (...args) => { clearTimeout(timer); timer = setTimeout(() => fn(...args), ms); };
  d.cancel = () => clearTimeout(timer);
  return d;
}
export function lsGet(key, dflt = null) { try { const v = localStorage.getItem(key); return v == null ? dflt : v; } catch (e) { return dflt; } }
export function lsSet(key, val) { try { localStorage.setItem(key, val); } catch (e) { /* storage unavailable */ } }

// ---------- hash routing helpers ----------
export function parseHash(hash = location.hash) {
  let s = hash.replace(/^#/, '');
  if (!s.startsWith('/')) s = '/' + s;
  const qi = s.indexOf('?');
  const path = qi >= 0 ? s.slice(0, qi) : s;
  const query = new URLSearchParams(qi >= 0 ? s.slice(qi + 1) : '');
  return { path, parts: path.split('/').filter(Boolean), query };
}
export function buildHash(path, query) {
  const q = query instanceof URLSearchParams ? query.toString() : new URLSearchParams(query || {}).toString();
  return '#' + path + (q ? '?' + q : '');
}

// ---------- colour helpers (theme values are #rrggbb) ----------
export function parseColor(str) {
  str = (str || '').trim();
  let m = /^#([0-9a-f]{3,8})$/i.exec(str);
  if (m) {
    let x = m[1];
    if (x.length === 3 || x.length === 4) x = x.split('').map((c) => c + c).join('');
    const n = parseInt(x.slice(0, 6), 16);
    return [(n >> 16) & 255, (n >> 8) & 255, n & 255, x.length === 8 ? parseInt(x.slice(6), 16) / 255 : 1];
  }
  m = /^rgba?\(([^)]+)\)$/i.exec(str);
  if (m) {
    const p = m[1].split(/[ ,\/]+/).filter(Boolean).map(parseFloat);
    return [p[0], p[1], p[2], p.length > 3 ? p[3] : 1];
  }
  return [128, 128, 128, 1];
}
export function rgba(c, a = 1) { return `rgba(${Math.round(c[0])},${Math.round(c[1])},${Math.round(c[2])},${a})`; }
export function lerpColor(a, b, t) { return [a[0] + (b[0] - a[0]) * t, a[1] + (b[1] - a[1]) * t, a[2] + (b[2] - a[2]) * t, 1]; }
/** Piecewise-linear gradient through stops for t in 0..1 */
export function gradient(stops, t) {
  t = clamp(t, 0, 1) * (stops.length - 1);
  const i = Math.min(Math.floor(t), stops.length - 2);
  return lerpColor(stops[i], stops[i + 1], t - i);
}
export function hex(c) { return '#' + [c[0], c[1], c[2]].map((v) => Math.round(v).toString(16).padStart(2, '0')).join(''); }

export function plural(n, one, many) { return n + ' ' + (n === 1 ? one : many || one + 's'); }
