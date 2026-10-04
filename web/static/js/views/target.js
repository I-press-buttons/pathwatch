// Target page: summary cards, hop grid, path timeline heatmap, hop latency graph, HTTP phases, recent alerts.
// All time-based panels share one time axis ({from,to} in ms) and refetch together on range/zoom changes.
import { h, clear, isNum, fmtMs, fmtPct, fmtMos, fmtInt, fmtDateTime, fmtDuration, fmtAgo, fmtTime, clamp, lsGet, lsSet, toLocalInput, fromLocalInput, DASH, percentile } from '../util.js';
import { api, serverNow, onStream, onStreamState, getStreamState } from '../api.js';
import { statusPill, panel, alertPill, deliveryPill, metricClass } from '../ui.js';
import { Heatmap } from '../charts/heatmap.js';
import { LatencyChart } from '../charts/latency.js';
import { PhasesChart } from '../charts/phases.js';
import { openTargetEditor } from './target-editor.js';

export const RANGES = { '1h': 3600e3, '6h': 6 * 3600e3, '24h': 86400e3, '7d': 7 * 86400e3, '30d': 30 * 86400e3, '90d': 90 * 86400e3 };
const REFRESH_MS = 7000;        // live cadence of the summary cards (and the floor for the range panels)
const PANEL_MAX_MS = 60000;     // live cadence ceiling of the range panels
const HEAD_TIPS = { Count: 'Probes sent over the range', 'Loss %': 'Percent of probes without a reply. Intermediate hops may rate-limit ICMP.', Cur: 'Most recent reply', Jitter: 'Mean absolute difference of consecutive RTTs', Latency: 'Bar = average, whiskers = min to max' };

export function mount(root, ctx) {
  const id = Number(ctx.params.id);
  const S = { rangeKey: '1h', custom: null, zoom: null, ttl: null, live: true, scale: 'auto', httpProbe: null };
  const axis = { from: 0, to: 1 };
  const D = { target: null, targets: [], hops: null, timeline: null, series: null, probes: null, alerts: null };
  const seq = { targets: 0, hops: 0, timeline: 0, series: 0, probes: 0, alerts: 0 };
  let destroyed = false;
  const cleanups = [];
  // In-flight requests, one controller per load: a newer load of the same kind (or abortAll) cancels the older one.
  const inflight = new Map();
  function begin(name) { const old = inflight.get(name); if (old) old.abort(); const c = new AbortController(); inflight.set(name, c); return c.signal; }
  function abortAll() { for (const c of inflight.values()) c.abort(); inflight.clear(); }

  // ================= header + range controls =================
  const targetSel = h('select', { 'aria-label': 'Select target', onchange: () => ctx.navigate('/target/' + targetSel.value, currentQuery()) });
  const title = h('h1', null, 'Target');
  const hostLine = h('span', { class: 'sub muted' });
  const statusEl = h('span');
  const editBtn = h('button', { class: 'btn sm', type: 'button', hidden: true, title: 'Host, probes, intervals, timeouts, retries and alert thresholds',
    onclick: () => openTargetEditor({ id, onSaved: () => refreshAll() }) }, 'Edit target');
  const head = h('div', { class: 'target-head' }, h('a', { class: 'btn sm', href: '#/' }, '← Overview'), targetSel, title, statusEl, hostLine, editBtn);

  const rangeBtns = Object.keys(RANGES).map((k) => h('button', { type: 'button', class: 'btn sm', dataset: { range: k }, onclick: () => setRange(k) }, k));
  const customBtn = h('button', { type: 'button', class: 'btn sm', dataset: { range: 'custom' }, onclick: () => toggleCustom() }, 'Custom');
  const fromIn = h('input', { type: 'datetime-local', 'aria-label': 'From' });
  const toIn = h('input', { type: 'datetime-local', 'aria-label': 'To' });
  const applyBtn = h('button', { type: 'button', class: 'btn sm primary', onclick: () => applyCustom() }, 'Apply');
  const customErr = h('span', { class: 'zoom-note', style: { color: 'var(--crit)' } });
  const customBox = h('div', { class: 'custom', hidden: true }, fromIn, '→', toIn, applyBtn, customErr);
  const resetBtn = h('button', { type: 'button', class: 'btn sm', hidden: true, onclick: () => resetZoom() }, 'Reset zoom');
  const zoomNote = h('span', { class: 'zoom-note' });
  const liveEl = h('span', { class: 'live', title: 'Live updates via the event stream' }, h('span', { class: 'dot' }), h('span', { class: 'lbl' }, 'paused'));
  const rangeBar = h('div', { class: 'range-bar' },
    h('div', { class: 'btn-group', role: 'group', 'aria-label': 'Time range' }, rangeBtns, customBtn),
    customBox, resetBtn, zoomNote, h('div', { style: { flex: 1 } }), liveEl);

  // ================= panels =================
  const cardsEl = h('div', { class: 'cards' });
  const hopsP = panel('Hops', { flush: true, actions: h('span', { class: 'muted', style: { fontSize: '12.5px' } }, 'Click a row to graph that hop') });
  const hopNote = h('div', { class: 'note', hidden: true });
  const hopTable = h('table', { class: 'grid hops' });
  const hopTbody = h('tbody');
  hopTable.append(
    h('thead', null, h('tr', null,
      [['Hop', 'ttl'], ['Count', ''], ['IP', 'l'], ['Hostname', 'l'], ['Loss %', ''], ['Min', ''], ['Avg', ''], ['Cur', ''], ['Max', ''], ['p95', ''], ['Jitter', ''], ['Latency', 'l']]
        .map(([t, c]) => h('th', { class: c === 'l' ? 'l' : '', title: HEAD_TIPS[t] || null }, t)))),
    hopTbody);
  clear(hopsP.content).append(hopNote, h('div', { class: 'table-scroll' }, hopTable));

  const scaleSel = h('select', { 'aria-label': 'Heatmap colour scale max', onchange: () => { S.scale = scaleSel.value; heat.setScale(S.scale); updateLegend(); } },
    [['auto', 'Auto (p99)'], ['25', '25 ms'], ['50', '50 ms'], ['100', '100 ms'], ['250', '250 ms'], ['500', '500 ms'], ['1000', '1000 ms']].map(([v, l]) => h('option', { value: v }, l)));
  const legendMax = h('span', null, '');
  const heatLegend = h('div', { class: 'heat-controls' }, 'Scale', scaleSel, h('span', null, '0'),
    h('span', { class: 'legend-grad', style: { background: 'linear-gradient(to right, var(--lat-0), var(--lat-1), var(--lat-2), var(--lat-3), var(--lat-4))' } }), legendMax,
    h('span', { title: 'Red = packet loss' }, h('i', { style: { display: 'inline-block', width: '10px', height: '10px', background: 'var(--loss-1)', borderRadius: '2px', verticalAlign: '-1px', marginRight: '4px' } }), 'loss'),
    h('span', { title: 'Hatched = monitor gap (no data)' }, h('i', { style: { display: 'inline-block', width: '10px', height: '10px', border: '1px solid var(--gap-hatch)', background: 'repeating-linear-gradient(45deg, var(--gap-hatch) 0 1px, var(--gap-bg) 1px 4px)', borderRadius: '2px', verticalAlign: '-1px', marginRight: '4px' } }), 'gap'));
  const heatP = panel('Path timeline', { actions: heatLegend });
  const heatHost = h('div');
  clear(heatP.content).append(heatHost);
  const heat = new Heatmap(heatHost, { onSelectTtl: (ttl, isDest) => selectTtl(ttl, isDest), onZoom: (a, b) => zoomTo(a, b) });

  const latP = panel('Latency & loss');
  const latSub = h('div', { class: 'chart-title' });
  const latHost = h('div');
  clear(latP.content).append(latSub, latHost);
  const latency = new LatencyChart(latHost, { axis, onZoom: (a, b) => zoomTo(a, b) });

  const httpSel = h('select', { 'aria-label': 'HTTP probe', hidden: true, onchange: () => { S.httpProbe = Number(httpSel.value); renderProbes(); } });
  const phasesP = panel('HTTP phases', { actions: httpSel });
  const phaseLegend = h('div', { class: 'legend-inline' },
    [['dns', 'DNS'], ['tcp', 'TCP connect'], ['tls', 'TLS'], ['ttfb', 'TTFB'], ['transfer', 'Transfer']].map(([k, l]) => h('span', null, h('i', { style: { background: `var(--ph-${k})` } }), l)),
    h('span', null, h('i', { style: { background: 'var(--tcp-line)', height: '3px', verticalAlign: '3px' } }), 'TCP probe'),
    h('span', null, h('i', { style: { background: 'var(--fail)' } }), 'failure'));
  const phasesHost = h('div');
  clear(phasesP.content).append(phaseLegend, phasesHost);
  const phases = new PhasesChart(phasesHost, { axis, onZoom: (a, b) => zoomTo(a, b) });

  const alertsP = panel('Recent alerts', { flush: true, actions: h('a', { href: '#/alerts', style: { fontSize: '12.5px' } }, 'All alerts →') });

  root.append(head, rangeBar, cardsEl, hopsP.el, heatP.el, latP.el, phasesP.el, alertsP.el);
  hopsP.showLoading('Loading hops…'); heatP.showLoading('Loading path timeline…'); latP.showLoading(); phasesP.showLoading(); alertsP.showLoading();
  renderCards();

  // ================= route state =================
  function parseQuery(q) {
    const from = Number(q.get('from')), to = Number(q.get('to'));
    const rk = q.get('range');
    const st = { rangeKey: '1h', custom: null, zoom: null, ttl: null };
    if (q.get('from') && q.get('to') && from > 0 && to > from) st.custom = { from, to };
    else if (rk && RANGES[rk]) st.rangeKey = rk;
    else { const saved = lsGet('pathwatch.range', '1h'); st.rangeKey = RANGES[saved] ? saved : '1h'; }
    const z = (q.get('zoom') || '').split('-').map(Number);
    if (z.length === 2 && z[0] > 0 && z[1] > z[0]) st.zoom = [z[0], z[1]];
    const t = q.get('ttl');
    if (t != null && t !== '' && Number.isFinite(Number(t))) st.ttl = Number(t);
    return st;
  }
  function currentQuery() {
    const q = new URLSearchParams();
    if (S.custom) { q.set('from', String(S.custom.from)); q.set('to', String(S.custom.to)); } else q.set('range', S.rangeKey);
    if (S.zoom) q.set('zoom', S.zoom[0] + '-' + S.zoom[1]);
    if (S.ttl != null) q.set('ttl', String(S.ttl));
    return q;
  }
  // Compute the next query without committing it: the router calls update() which applies it (single source of truth = URL hash).
  function push(mutate, replace = false) {
    const saved = { rangeKey: S.rangeKey, custom: S.custom, zoom: S.zoom, ttl: S.ttl };
    mutate();
    const q = currentQuery();
    Object.assign(S, saved);
    ctx.navigate('/target/' + id, q, { replace });
  }
  function setRange(k) { push(() => { S.rangeKey = k; S.custom = null; S.zoom = null; lsSet('pathwatch.range', k); }); }
  function zoomTo(a, b) { push(() => { S.zoom = [Math.round(a), Math.round(b)]; }); }
  function resetZoom() { push(() => { S.zoom = null; }); }
  function selectTtl(ttl, isDest) {
    push(() => { S.ttl = isDest || ttl === S.ttl ? null : ttl; }, true);
  }
  function toggleCustom() {
    customBox.hidden = !customBox.hidden;
    if (!customBox.hidden) {
      fromIn.value = toLocalInput(axis.from); toIn.value = toLocalInput(axis.to);
      customErr.textContent = '';
    }
  }
  function applyCustom() {
    const a = fromLocalInput(fromIn.value), b = fromLocalInput(toIn.value);
    if (a == null || b == null) { customErr.textContent = 'Pick both times.'; return; }
    if (b <= a) { customErr.textContent = 'End must be after start.'; return; }
    if (b - a < 60000) { customErr.textContent = 'Range must be at least 1 minute.'; return; }
    customErr.textContent = '';
    push(() => { S.custom = { from: a, to: b }; S.zoom = null; });
  }

  function applyRoute(c, initial) {
    const st = parseQuery(c.query);
    const rangeChanged = initial || st.rangeKey !== S.rangeKey || JSON.stringify(st.custom) !== JSON.stringify(S.custom) || JSON.stringify(st.zoom) !== JSON.stringify(S.zoom);
    const ttlChanged = initial || st.ttl !== S.ttl;
    S.rangeKey = st.rangeKey; S.custom = st.custom; S.zoom = st.zoom; S.ttl = st.ttl;
    syncControls();
    if (rangeChanged) refreshAll();
    else if (ttlChanged) { heat.setSelected(S.ttl); markSelected(); track([loadSeries()]); }
  }

  function syncControls() {
    for (const b of rangeBtns) b.setAttribute('aria-pressed', String(!S.custom && b.dataset.range === S.rangeKey));
    customBtn.setAttribute('aria-pressed', String(!!S.custom));
    if (S.custom) { customBox.hidden = false; fromIn.value = toLocalInput(S.custom.from); toIn.value = toLocalInput(S.custom.to); }
    else if (!S.zoom && !customErr.textContent) customBox.hidden = true;
    resetBtn.hidden = !S.zoom;
    S.live = !S.custom && !S.zoom;
    updateLive();
  }
  function updateZoomNote() {
    zoomNote.textContent = S.zoom ? `Zoomed: ${fmtDateTime(axis.from)} → ${fmtDateTime(axis.to)} (${fmtDuration(axis.to - axis.from)})`
      : S.custom ? `${fmtDateTime(axis.from)} → ${fmtDateTime(axis.to)}` : '';
  }
  function updateLive() {
    const st = getStreamState();
    liveEl.className = 'live';
    const lbl = liveEl.querySelector('.lbl');
    if (!S.live) { lbl.textContent = 'paused (fixed range)'; liveEl.title = 'Live updates are off for custom or zoomed ranges'; return; }
    if (st === 'open') { liveEl.classList.add('on'); lbl.textContent = 'live'; liveEl.title = 'Receiving live updates'; }
    else if (st === 'retrying' || st === 'connecting') { liveEl.classList.add('retry'); lbl.textContent = 'reconnecting…'; liveEl.title = 'Event stream disconnected; retrying. Panels still refresh periodically.'; }
    else lbl.textContent = 'live (polling)';
  }

  function resolveAxis() {
    if (S.zoom) return { from: S.zoom[0], to: S.zoom[1] };
    if (S.custom) return { from: S.custom.from, to: S.custom.to };
    const to = Math.round(serverNow());
    return { from: to - RANGES[S.rangeKey], to };
  }
  function rangeParams() { return { from: Math.round(axis.from), to: Math.round(axis.to) }; }
  function bucketCount() { return clamp(Math.round((heatHost.clientWidth || 900) / 3), 120, 300); }

  // ================= data loading =================
  function failIn(p, e) { if (e && e.name !== 'AbortError' && !destroyed) p.showError(e.message); }

  async function loadTargets() {
    const my = ++seq.targets;
    lastCards = Date.now();
    try {
      const list = await api.targets({ signal: begin('targets') });
      if (my !== seq.targets || destroyed) return;
      D.targets = list || [];
      D.target = D.targets.find((t) => t.id === id) || null;
      renderHeader(); renderCards(); renderHopNote();
      if (!D.target) { hopsP.showEmpty('Target not found.', 'It may have been deleted.'); }
    } catch (e) { /* banner; aborts are silent */ }
  }

  async function loadHops() {
    const my = ++seq.hops;
    hopsP.showLoading('Loading hops…');
    try {
      const d = await api.hops(id, rangeParams(), { signal: begin('hops') });
      if (my !== seq.hops || destroyed) return;
      D.hops = d; hopsP.clearStale();
      renderHops();
    } catch (e) { if (my === seq.hops) failIn(hopsP, e); }
  }
  async function loadTimeline() {
    const my = ++seq.timeline;
    heatP.showLoading('Loading path timeline…');
    try {
      const d = await api.timeline(id, { ...rangeParams(), buckets: bucketCount() }, { signal: begin('timeline') });
      if (my !== seq.timeline || destroyed) return;
      D.timeline = d; stepMs = d && d.step_ms > 0 ? d.step_ms : null; heatP.clearStale();
      renderHeat();
    } catch (e) { if (my === seq.timeline) failIn(heatP, e); }
  }
  async function loadSeries() {
    const my = ++seq.series;
    latP.showLoading('Loading latency…');
    try {
      const p = { ...rangeParams(), buckets: bucketCount() };
      if (S.ttl != null) p.ttl = S.ttl;
      const d = await api.series(id, p, { signal: begin('series') });
      if (my !== seq.series || destroyed) return;
      D.series = d; latP.clearStale();
      renderLatency();
    } catch (e) { if (my === seq.series) failIn(latP, e); }
  }
  async function loadProbes() {
    const my = ++seq.probes;
    phasesP.showLoading('Loading probes…');
    try {
      const d = await api.probes(id, { ...rangeParams(), buckets: bucketCount() }, { signal: begin('probes') });
      if (my !== seq.probes || destroyed) return;
      D.probes = d; phasesP.clearStale();
      renderProbes(); renderLatency();
    } catch (e) { if (my === seq.probes) failIn(phasesP, e); }
  }
  async function loadAlerts() {
    const my = ++seq.alerts;
    try {
      const d = await api.alerts({ target_id: id, limit: 8 }, { signal: begin('alerts') });
      if (my !== seq.alerts || destroyed) return;
      D.alerts = d || []; alertsP.clearStale();
      renderAlerts();
    } catch (e) { if (my === seq.alerts) failIn(alertsP, e); }
  }

  // Live refresh. Cards (/api/targets) follow REFRESH_MS; the range panels (hops, timeline, series, probes) only need to
  // follow the bucket width: min(max(REFRESH_MS, step), PANEL_MAX_MS). Refreshes never overlap: a trigger that arrives while
  // anything is still loading is remembered and becomes a single follow-up once the loads settle.
  let stepMs = null;                 // step_ms of the last timeline for the current range
  let lastCards = 0, lastPanels = 0; // when each group was last requested
  let pending = 0, again = false, liveTimer = null;
  const panelEvery = () => clamp(stepMs || (axis.to - axis.from) / bucketCount(), REFRESH_MS, PANEL_MAX_MS);
  function track(jobs) {
    pending++;
    Promise.allSettled(jobs).then(() => { pending--; if (!pending && again && !destroyed) { again = false; scheduleLive(); } });
  }
  function cancelLive() { clearTimeout(liveTimer); liveTimer = null; again = false; }

  function refreshAll() {
    abortAll(); cancelLive();
    Object.assign(axis, resolveAxis());
    updateZoomNote();
    heat.setAxis(axis);
    latency.redraw(); phases.redraw();
    stepMs = null;
    lastPanels = Date.now();
    track([loadTargets(), loadHops(), loadTimeline(), loadSeries(), loadProbes(), loadAlerts()]);
  }
  /** live refresh: move the window forward and refetch whatever is due */
  function refreshLive() {
    if (!S.live || destroyed) return;
    if (pending) { again = true; return; }
    const now = Date.now(), due = now + 50; // timers may fire a hair early
    const cards = due - lastCards >= REFRESH_MS, panels = due - lastPanels >= panelEvery();
    if (!cards && !panels) return;
    const jobs = [];
    if (cards) jobs.push(loadTargets());
    if (panels) {
      lastPanels = now;
      Object.assign(axis, resolveAxis());
      updateZoomNote();
      jobs.push(loadHops(), loadTimeline(), loadSeries(), loadProbes());
    }
    track(jobs);
  }
  /** arm one timer for the next due refresh; every event and the fallback poll just call this */
  function scheduleLive() {
    if (liveTimer || !S.live || destroyed) return;
    const wait = Math.max(0, Math.min(lastCards + REFRESH_MS, lastPanels + panelEvery()) - Date.now());
    liveTimer = setTimeout(() => { liveTimer = null; refreshLive(); }, wait);
  }

  // ================= rendering =================
  function renderHeader() {
    const t = D.target;
    clear(targetSel).append(...D.targets.map((x) => h('option', { value: x.id, selected: x.id === id }, x.name)));
    targetSel.value = String(id);
    editBtn.hidden = !t || t.removed;
    if (!t) { title.textContent = 'Target #' + id; clear(statusEl); hostLine.textContent = ''; return; }
    title.textContent = t.name;
    document.title = t.name + ' · pathwatch';
    clear(statusEl).append(statusPill(t.status, t.active));
    hostLine.textContent = t.host + (t.resolved_ip && t.resolved_ip !== t.host ? ' · ' + t.resolved_ip : '') + (t.icmp_interval_ms ? ' · every ' + fmtDuration(t.icmp_interval_ms) : '');
  }

  function sumCard(k, v, sub, cls, title) {
    return h('div', { class: 'card sumcard ' + (cls || ''), title: title || null }, h('div', { class: 'k' }, k), h('div', { class: 'v' }, v), h('div', { class: 's' }, sub || ' '));
  }
  const mosLabel = (m) => (!isNum(m) ? '' : m >= 4.3 ? 'excellent' : m >= 4.0 ? 'good' : m >= 3.6 ? 'fair' : m >= 3.1 ? 'poor' : 'bad');
  function renderCards() {
    clear(cardsEl);
    const t = D.target;
    if (!t) { for (let i = 0; i < 6; i++) cardsEl.append(sumCard(' ', DASH, '')); return; }
    const s = t.summary || {};
    const hasHttp = (t.probes || []).some((p) => p.type === 'http');
    const unit = (v, u) => isNum(v) ? [fmtMs(v), h('small', null, ' ' + u)] : DASH;
    const tip = 'Summary over the last 5 minutes';
    const days = isNum(s.cert_not_after) ? (s.cert_not_after - serverNow()) / 86400e3 : null;
    cardsEl.append(
      sumCard('E2E latency (median)', unit(s.e2e_rtt_ms, 'ms'), isNum(s.e2e_p95_ms) ? 'p95 ' + fmtMs(s.e2e_p95_ms) + ' ms' : (t.icmp_unresponsive ? 'via TCP probe' : 'median'), '', tip),
      sumCard('E2E loss', fmtPct(s.e2e_loss_pct), t.icmp_unresponsive ? 'TCP probe (no ping reply)' : 'destination', metricClass('loss', s.e2e_loss_pct), tip),
      sumCard('Jitter', unit(s.jitter_ms, 'ms'), 'mean |Δ RTT|', '', tip),
      sumCard('MOS', fmtMos(s.mos), mosLabel(s.mos) || 'estimated voice quality', metricClass('mos', s.mos), 'ITU-T G.107 simplified E-model, 1 to 4.5'),
      sumCard('HTTP total', hasHttp ? unit(s.http_total_ms, 'ms') : DASH, hasHttp ? 'success ' + fmtPct(s.http_success_pct) : 'no HTTP probe', '', tip),
      sumCard('HTTP success', hasHttp ? fmtPct(s.http_success_pct) : DASH, hasHttp ? 'last 5 min' : 'no HTTP probe', hasHttp ? metricClass('success', s.http_success_pct) : '', tip),
      sumCard('Certificate', days == null ? DASH : days < 0 ? 'expired' : [days.toFixed(0), h('small', null, ' days')], days == null ? 'no HTTPS probe' : 'expires ' + new Date(s.cert_not_after).toLocaleDateString(), days == null ? '' : days < 0 ? 'crit' : days < 14 ? 'warn' : ''),
      sumCard('Active alerts', String(s.active_alerts || 0), h('a', { href: '#/alerts' }, 'view alerts'), (s.active_alerts || 0) > 0 ? 'crit' : 'ok'));
    if (t.status === 'learning') cardsEl.append(sumCard('Baseline', 'Learning', 'latency alerts start after enough history', 'warn'));
  }

  function renderHopNote() {
    const t = D.target;
    if (t && t.icmp_unresponsive) { hopNote.hidden = false; hopNote.textContent = 'This destination does not answer ping. End-to-end figures use the TCP probe; the hop list ends at the last responding router.'; }
    else hopNote.hidden = true;
  }

  let hopRefs = new Map(); // ttl -> {tr, cur}
  function renderHops() {
    const d = D.hops;
    if (!d || !d.hops || !d.hops.length) {
      hopsP.showEmpty('No data yet. First results appear within a few seconds.', D.target && D.target.active === false ? 'This target is paused.' : null);
      hopRefs = new Map();
      return;
    }
    hopsP.showContent();
    renderHopNote();
    const hops = d.hops;
    const okRows = hops.filter((x) => x.classification !== 'no_reply' && x.classification !== 'rate_limited' && isNum(x.p95_ms));
    const p95s = okRows.map((x) => x.p95_ms).sort((a, b) => a - b);
    let barMax = (percentile(p95s, 1) || 0) * 1.15;
    if (!(barMax > 0)) barMax = Math.max(1, ...hops.map((x) => x.max_ms || 0));
    clear(hopTbody);
    hopRefs = new Map();
    for (const hp of hops) {
      const cls = hp.classification || 'ok';
      const noReply = cls === 'no_reply';
      const dest = hp.is_destination || cls === 'destination';
      const tr = h('tr', { class: [cls, dest ? 'dest' : '', isSelected(hp) ? 'selected' : ''].join(' '), dataset: { ttl: hp.ttl }, tabindex: noReply ? null : '0',
        onclick: () => { if (!noReply) selectTtl(hp.ttl, dest); },
        onkeydown: (e) => { if ((e.key === 'Enter' || e.key === ' ') && !noReply) { e.preventDefault(); selectTtl(hp.ttl, dest); } },
        'aria-selected': isSelected(hp) ? 'true' : null });
      const unresp = dest && noReply && !!(D.target && D.target.icmp_unresponsive);
      const lossCls = cls === 'rate_limited' || unresp ? '' : hp.loss_pct >= 5 ? 'loss-hi' : hp.loss_pct >= 1 ? 'loss-mid' : '';
      const alts = (hp.responders || 1) > 1 ? h('span', { class: 'badge-lb', title: 'Load-balanced hop. Also seen: ' + ((hp.alt_addresses || []).join(', ') || 'other addresses') }, '+' + (hp.responders - 1)) : null;
      const tags = [];
      if (cls === 'rate_limited') tags.push(h('span', { class: 'tagline rl', title: 'Loss/latency here is ICMP rate-limiting by the router; downstream hops are clean, so real traffic is unaffected.' }, 'ICMP rate-limited'));
      if (cls === 'degraded') tags.push(h('span', { class: 'tagline rl', title: 'Degradation here continues downstream' }, 'degraded'));
      if (dest) tags.push(h('span', { class: 'tagline', title: 'Destination' }, D.target && D.target.icmp_unresponsive && (noReply || !isNum(hp.avg_ms)) ? 'does not answer ping' : 'destination'));
      const asn = hp.asn ? 'AS' + hp.asn + (hp.as_name ? ' ' + hp.as_name : '') : null;
      const cur = h('td', { class: 'cur' }, noReply ? DASH : fmtMs(hp.cur_ms));
      tr.append(
        h('td', { class: 'ttl' }, String(hp.ttl)),
        h('td', null, fmtInt(hp.sent)),
        h('td', { class: 'ip mono', title: asn }, noReply && !hp.address ? '* * *' : [hp.address || DASH, alts]),
        h('td', { class: 'hostn host', title: [hp.hostname, asn].filter(Boolean).join(' · ') || null }, hp.hostname || '', tags),
        h('td', { class: lossCls, title: `${fmtInt(hp.lost)} lost of ${fmtInt(hp.sent)}` }, isNum(hp.loss_pct) && !unresp ? fmtPct(hp.loss_pct) : DASH),
        h('td', null, noReply ? DASH : fmtMs(hp.min_ms)),
        h('td', null, noReply ? DASH : fmtMs(hp.avg_ms)),
        cur,
        h('td', null, noReply ? DASH : fmtMs(hp.max_ms)),
        h('td', null, noReply ? DASH : fmtMs(hp.p95_ms)),
        h('td', null, noReply ? DASH : fmtMs(hp.jitter_ms)),
        h('td', { class: 'cell-lat' }, latBar(hp, barMax)));
      hopTbody.append(tr);
      hopRefs.set(hp.ttl, { tr, cur, hop: hp });
    }
  }
  function isSelected(hp) { return S.ttl != null ? hp.ttl === S.ttl : !!(hp.is_destination || hp.classification === 'destination'); }
  function markSelected() {
    if (!D.hops) return;
    for (const hp of D.hops.hops) {
      const r = hopRefs.get(hp.ttl);
      if (r) { const sel = isSelected(hp); r.tr.classList.toggle('selected', sel); if (sel) r.tr.setAttribute('aria-selected', 'true'); else r.tr.removeAttribute('aria-selected'); }
    }
  }
  function latBar(hp, max) {
    const pct = (v) => clamp((v / max) * 100, 0, 100);
    const bar = h('div', { class: 'latbar', title: isNum(hp.avg_ms) ? `avg ${fmtMs(hp.avg_ms)} ms, min ${fmtMs(hp.min_ms)}, max ${fmtMs(hp.max_ms)}${hp.loss_pct > 0 ? ', loss ' + fmtPct(hp.loss_pct) : ''}` : null });
    if (isNum(hp.loss_pct) && hp.loss_pct > 0) bar.append(h('div', { class: 'loss', style: { opacity: String(clamp(0.06 + hp.loss_pct / 55, 0.06, 0.85)) } }));
    if (isNum(hp.avg_ms)) {
      bar.append(h('div', { class: 'avg', style: { width: pct(hp.avg_ms) + '%' } }));
      if (isNum(hp.min_ms) && isNum(hp.max_ms)) {
        const a = pct(hp.min_ms), b = pct(hp.max_ms);
        bar.append(h('div', { class: 'wh', style: { left: a + '%', width: Math.max(0, b - a) + '%' } }), h('div', { class: 'cap', style: { left: a + '%' } }), h('div', { class: 'cap', style: { left: `calc(${b}% - 1px)` } }));
      }
    }
    return bar;
  }

  /** SSE round: update "Cur" immediately without refetching */
  function onRound(ev) {
    if (!D.hops || ev.target_id !== id) return;
    for (const r of ev.hops || []) {
      const ref = hopRefs.get(r.ttl);
      if (!ref || ref.hop.classification === 'no_reply' && r.rtt_ms == null) continue;
      ref.hop.cur_ms = isNum(r.rtt_ms) ? r.rtt_ms : null;
      ref.cur.textContent = isNum(r.rtt_ms) ? fmtMs(r.rtt_ms) : '*';
      ref.tr.classList.remove('flash'); void ref.tr.offsetWidth; ref.tr.classList.add('flash');
    }
  }

  function updateLegend() { legendMax.textContent = fmtMs(heat.scaleMax()) + ' ms'; }
  function renderHeat() {
    const tl = D.timeline;
    if (!tl || !tl.ttls || !tl.ttls.length) {
      heatP.showEmpty('No data yet. First results appear within a few seconds.', D.target && D.target.active === false ? 'This target is paused.' : 'The path timeline fills in as probe rounds complete.');
      return;
    }
    heatP.showContent();
    heat.setData(tl, axis, { selectedTtl: S.ttl });
    updateLegend();
  }

  function selectedLabel() {
    if (S.ttl == null) return 'destination';
    const hp = D.hops && D.hops.hops.find((x) => x.ttl === S.ttl);
    return 'hop ' + S.ttl + (hp && (hp.hostname || hp.address) ? ' (' + (hp.hostname || hp.address) + ')' : '');
  }
  function renderLatency() {
    const sr = D.series;
    if (!sr) return;
    let points = sr.points || [], tcpFallback = false;
    const hasData = points.some((p) => isNum(p[1]));
    if (!hasData && S.ttl == null && D.probes && D.probes.tcp && D.probes.tcp.length) {
      const tp = D.probes.tcp[0];
      if (tp.points.some((p) => isNum(p[1]))) { points = tp.points.map((p) => [p[0], p[1], p[1], p[1], p[2]]); tcpFallback = true; }
    }
    latP.head.querySelector('h2').textContent = 'Latency & loss — ' + (tcpFallback ? 'destination via TCP connect' : selectedLabel());
    if (!points.length || (!points.some((p) => isNum(p[1])) && !points.some((p) => isNum(p[4]) && p[4] > 0))) {
      latP.showEmpty(points.length ? 'No replies from this hop in the selected range.' : 'No data yet. First results appear within a few seconds.', S.ttl != null ? 'Select another hop, or click the destination row.' : null);
      return;
    }
    latP.showContent();
    latSub.textContent = tcpFallback ? 'Destination does not answer ping; showing TCP connect time.' : 'Average with min–max band; bars show loss % (right axis). Drag to zoom.';
    latency.load(points);
  }

  function renderProbes() {
    const p = D.probes;
    if (!p) return;
    const https = p.http || [], tcps = p.tcp || [];
    if (!https.length && !tcps.length) {
      phasesP.showEmpty('No HTTP or TCP probe on this target.', 'Add an HTTP URL or TCP port to see phase timing (DNS, TCP, TLS, TTFB, transfer).');
      return;
    }
    if (https.length > 1) {
      httpSel.hidden = false;
      if (!https.some((x) => x.probe_id === S.httpProbe)) S.httpProbe = https[0].probe_id;
      clear(httpSel).append(...https.map((x) => h('option', { value: x.probe_id, selected: x.probe_id === S.httpProbe }, x.label)));
    } else httpSel.hidden = true;
    const http = https.length ? (https.find((x) => x.probe_id === S.httpProbe) || https[0]) : null;
    const tcp = tcps[0] || null;
    const any = (http && http.points.length) || (tcp && tcp.points.length);
    if (!any) { phasesP.showEmpty('No data yet. First results appear within a few seconds.'); return; }
    phasesP.showContent();
    phaseLegend.hidden = !http;
    phases.load(http, tcp, D.timeline ? D.timeline.step_ms : (axis.to - axis.from) / 300);
  }

  function renderAlerts() {
    const list = D.alerts || [];
    if (!list.length) { alertsP.showEmpty('No alerts for this target.', 'Nothing has fired recently.'); return; }
    const now = serverNow();
    clear(alertsP.content).append(h('div', { class: 'table-scroll' }, h('table', { class: 'list-table stack' },
      h('tbody', null, list.map((a) => h('tr', null,
        h('td', null, alertPill(a)),
        h('td', null, h('strong', null, a.rule), a.message ? h('div', { class: 'alert-msg' }, a.message) : null),
        h('td', { title: fmtDateTime(a.started_at) }, fmtAgo(a.started_at, now), h('div', { class: 'muted' }, (a.ended_at ? 'lasted ' + fmtDuration(a.ended_at - a.started_at) : 'ongoing'))),
        h('td', null, a.deliveries && a.deliveries.length ? h('div', { class: 'deliv' }, a.deliveries.map(deliveryPill)) : null)))))));
    alertsP.showContent();
  }

  // ================= live wiring =================
  cleanups.push(onStream('round', (ev) => { if (ev.target_id !== id) return; if (S.live) { onRound(ev); scheduleLive(); } }));
  cleanups.push(onStream('probe', (ev) => { if (ev.target_id !== id) return; if (S.live) scheduleLive(); }));
  cleanups.push(onStream('alert', (ev) => { if (!ev || ev.target_id === id) loadAlerts(); }));
  cleanups.push(onStream('targets', () => loadTargets()));
  cleanups.push(onStreamState(() => updateLive()));
  // fallback polling (also keeps live mode moving if the stream is unavailable)
  const poll = setInterval(() => { if (S.live && getStreamState() !== 'open') scheduleLive(); }, 10000);
  const onResizeWin = () => { latency.onResize(); phases.onResize(); };
  window.addEventListener('resize', onResizeWin);

  applyRoute(ctx, true);

  return {
    update(c) { applyRoute(c, false); },
    destroy() {
      destroyed = true;
      clearInterval(poll); cancelLive(); abortAll();
      window.removeEventListener('resize', onResizeWin);
      cleanups.forEach((f) => f());
      heat.destroy(); latency.destroy(); phases.destroy();
    },
  };
}
