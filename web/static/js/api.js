// API client + SSE stream. Coded strictly against docs/API.md.
// Timestamps are Unix ms, latencies ms floats, null = missing.

export class ApiError extends Error {
  constructor(message, status) { super(message); this.status = status || 0; this.name = 'ApiError'; }
}

let skew = 0; // serverNow - Date.now(), learned from /api/status
export function serverNow() { return Date.now() + skew; }
export function setServerTime(ms) { if (typeof ms === 'number') skew = ms - Date.now(); }
export function getSkew() { return skew; }

// ---- health tracking drives the non-blocking "backend unreachable" banner ----
const failing = new Map(); // endpoint key -> message
const healthListeners = new Set();
export function onHealth(fn) { healthListeners.add(fn); return () => healthListeners.delete(fn); }
function notifyHealth() { for (const fn of healthListeners) { try { fn([...failing.entries()]); } catch (e) { console.error(e); } } }
function markOk(key) {
  let changed = failing.delete(key);
  // A successful response proves the server is reachable again: drop stale "cannot reach" entries of other endpoints.
  for (const [k, m] of failing) if (/reach/i.test(m)) { failing.delete(k); changed = true; }
  if (changed) notifyHealth();
}
function markFail(key, msg) { if (failing.get(key) !== msg) { failing.set(key, msg); notifyHealth(); } }

function handle401() {
  // The browser re-prompts for Basic auth on reload. Guard against reload loops.
  try {
    const last = Number(sessionStorage.getItem('pathwatch.reload401') || 0);
    if (Date.now() - last < 15000) return;
    sessionStorage.setItem('pathwatch.reload401', String(Date.now()));
  } catch (e) { /* ignore */ }
  location.reload();
}

export async function request(method, path, { params, body, signal, quiet } = {}) {
  let url = path;
  if (params) {
    const q = new URLSearchParams();
    for (const [k, v] of Object.entries(params)) if (v != null && v !== '') q.set(k, String(v));
    const s = q.toString();
    if (s) url += (url.includes('?') ? '&' : '?') + s;
  }
  const key = method + ' ' + path;
  const init = { method, signal, headers: { Accept: 'application/json' }, credentials: 'same-origin', cache: 'no-store' };
  if (body !== undefined) { init.body = JSON.stringify(body); init.headers['Content-Type'] = 'application/json'; }
  let res;
  try {
    res = await fetch(url, init);
  } catch (e) {
    if (e && e.name === 'AbortError') throw e;
    if (!quiet) markFail(key, 'Cannot reach the pathwatch server');
    throw new ApiError('Cannot reach the pathwatch server', 0);
  }
  if (res.status === 401) { handle401(); throw new ApiError('Authentication required', 401); }
  const text = await res.text(); // always drain the body, even for 204
  if (res.status === 204) { markOk(key); return null; }
  let data = null;
  if (text) { try { data = JSON.parse(text); } catch (e) { data = null; } }
  if (!res.ok) {
    const msg = (data && data.error) || `Request failed (${res.status})`;
    // Validation-style errors (4xx other than 401) are the caller's business, not a backend outage.
    if (res.status >= 500 && !quiet) markFail(key, msg);
    throw new ApiError(msg, res.status);
  }
  markOk(key);
  return data;
}

export const api = {
  status: (o) => request('GET', '/api/status', o),
  targets: (o) => request('GET', '/api/targets', o),
  createTarget: (body) => request('POST', '/api/targets', { body, quiet: true }),
  updateTarget: (id, body) => request('PUT', `/api/targets/${id}`, { body, quiet: true }),
  targetConfig: (id) => request('GET', `/api/targets/${id}/config`, { quiet: true }),
  revertTarget: (id) => request('DELETE', `/api/targets/${id}/override`, { quiet: true }),
  settings: (o) => request('GET', '/api/settings', o),
  putSetting: (section, body) => request('PUT', `/api/settings/${section}`, { body, quiet: true }),
  revertSetting: (section) => request('DELETE', `/api/settings/${section}`, { quiet: true }),
  resolve: (host, o) => request('GET', '/api/resolve', { params: { host }, quiet: true, ...o }),
  deleteTarget: (id) => request('DELETE', `/api/targets/${id}`, { quiet: true }),
  pauseTarget: (id) => request('POST', `/api/targets/${id}/pause`, { quiet: true }),
  resumeTarget: (id) => request('POST', `/api/targets/${id}/resume`, { quiet: true }),
  overview: (params, o) => request('GET', '/api/overview', { params, ...o }),
  hops: (id, params, o) => request('GET', `/api/targets/${id}/hops`, { params, ...o }),
  timeline: (id, params, o) => request('GET', `/api/targets/${id}/timeline`, { params, ...o }),
  series: (id, params, o) => request('GET', `/api/targets/${id}/series`, { params, ...o }),
  probes: (id, params, o) => request('GET', `/api/targets/${id}/probes`, { params, ...o }),
  dns: (params, o) => request('GET', '/api/dns', { params, ...o }),
  alerts: (params, o) => request('GET', '/api/alerts', { params, ...o }),
  events: (params, o) => request('GET', '/api/events', { params, ...o }),
  silences: (o) => request('GET', '/api/silences', o),
  createSilence: (body) => request('POST', '/api/silences', { body, quiet: true }),
  deleteSilence: (id) => request('DELETE', `/api/silences/${id}`, { quiet: true }),
};

// ---------------- SSE ----------------
// One shared EventSource with manual reconnect + exponential backoff.
const handlers = new Map(); // event -> Set<fn>
const stateListeners = new Set();
let es = null;
let backoff = 1000;
let retryTimer = null;
let streamState = 'idle'; // idle | connecting | open | retrying
let wanted = false;

function setState(s) { streamState = s; for (const fn of stateListeners) { try { fn(s); } catch (e) { console.error(e); } } }
export function getStreamState() { return streamState; }
export function onStreamState(fn) { stateListeners.add(fn); fn(streamState); return () => stateListeners.delete(fn); }
export function onStream(event, fn) {
  if (!handlers.has(event)) handlers.set(event, new Set());
  handlers.get(event).add(fn);
  return () => handlers.get(event).delete(fn);
}
function dispatch(event, data) {
  const set = handlers.get(event);
  if (!set) return;
  for (const fn of set) { try { fn(data); } catch (e) { console.error(e); } }
}
function connect() {
  if (!wanted || es) return;
  setState('connecting');
  let src;
  try { src = new EventSource('/api/stream'); } catch (e) { scheduleRetry(); return; }
  es = src;
  src.onopen = () => { backoff = 1000; setState('open'); };
  for (const ev of ['round', 'probe', 'alert', 'targets']) {
    src.addEventListener(ev, (m) => {
      let data = null;
      try { data = JSON.parse(m.data); } catch (e) { return; }
      dispatch(ev, data);
    });
  }
  src.onerror = () => {
    if (es !== src) return;
    src.close(); es = null;
    scheduleRetry();
  };
}
function scheduleRetry() {
  if (!wanted) return;
  setState('retrying');
  clearTimeout(retryTimer);
  retryTimer = setTimeout(connect, backoff);
  backoff = Math.min(backoff * 2, 30000);
}
export function startStream() { wanted = true; connect(); }
export function stopStream() { wanted = false; clearTimeout(retryTimer); if (es) { es.close(); es = null; } setState('idle'); }
