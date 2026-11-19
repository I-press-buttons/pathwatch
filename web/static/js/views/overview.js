// Overview: network verdict, one card per target, status strip, DNS probes, add/edit target.
// The page is made of sections the user can reorder and hide: the pencil at the top right turns on
// edit mode, where sections, target cards and DNS groups/cards are dragged into place; pressing it
// again saves the layout to the user's profile on the server (GET/PUT /api/profile).
import { h, svg, clear, isNum, fmtMs, fmtPct, fmtMos, clamp, lsGet, lsSet, DASH } from '../util.js';
import { api, onStream } from '../api.js';
import { getStatus, onStatus } from '../store.js';
import { statusPill, sparkline, confirmDialog, metricClass, WHERE } from '../ui.js';
import { dnsPanel } from './dns.js';
import { openTargetEditor } from './target-editor.js';
import { sortable, applyOrder } from '../sortable.js';

const RANGES = ['1h', '6h', '24h'];
const RANGE_MS = { '1h': 3600e3, '6h': 6 * 3600e3, '24h': 86400e3 };
const TARGETS_MS = 10000;   // /api/targets cadence
const SPARK_BUCKETS = 60;   // the sparkline overview is bucketed server side into this many steps
const SEG_STATE = { ok: 'fine', warn: 'problem', crit: 'failing', unknown: 'not measured' };
const SOON_MS = 300;        // SSE-triggered loads within this window collapse into one

const SECTIONS = { network: 'Network verdict', status: 'Status summary', targets: 'Targets', dns: 'DNS probes' };
function defaultLayout() {
  return { sections: Object.keys(SECTIONS).map((id) => ({ id, hidden: false })), target_order: [], dns: { group_by: 'server' } };
}
/** a complete copy of a layout from the server (or the default when there is none) */
function normLayout(l) {
  const d = defaultLayout();
  if (!l || typeof l !== 'object') return d;
  const seen = new Set();
  const secs = [];
  for (const x of l.sections || []) if (SECTIONS[x.id] && !seen.has(x.id)) { seen.add(x.id); secs.push({ id: x.id, hidden: !!x.hidden }); }
  for (const x of d.sections) if (!seen.has(x.id)) secs.push(x);
  const dns = l.dns || {};
  return {
    sections: secs,
    target_order: Array.isArray(l.target_order) ? l.target_order.slice() : [],
    dns: { group_by: dns.group_by || 'server', probe_order: (dns.probe_order || []).slice(), group_order: { ...(dns.group_order || {}) } },
  };
}
function pencilIcon() {
  return svg('svg', { viewBox: '0 0 24 24', width: 16, height: 16, 'aria-hidden': 'true' },
    svg('path', { d: 'M4 20h4L19 9l-4-4L4 16v4zM14 6l4 4', fill: 'none', stroke: 'currentColor', 'stroke-width': 2, 'stroke-linejoin': 'round', 'stroke-linecap': 'round' }));
}
function checkIcon() {
  return svg('svg', { viewBox: '0 0 24 24', width: 16, height: 16, 'aria-hidden': 'true' },
    svg('path', { d: 'M5 12l5 5L19 7', fill: 'none', stroke: 'currentColor', 'stroke-width': 2.4, 'stroke-linejoin': 'round', 'stroke-linecap': 'round' }));
}

export function mount(root, ctx) {
  let range = lsGet('pathwatch.overviewRange', '1h');
  if (!RANGES.includes(range)) range = '1h';
  let targets = null, net = null, netKey = '', spark = new Map(), loadedOnce = false, destroyed = false, timer = null, seq = 0;
  let busy = false, again = false, ctl = null, soon = null, sparkAt = 0, sparkRange = null;
  let saved = defaultLayout(), layout = defaultLayout(), editing = false, saving = false;

  const rangeSel = h('select', { 'aria-label': 'Sparkline range', onchange: () => { range = rangeSel.value; lsSet('pathwatch.overviewRange', range); load({ fresh: true }); } },
    RANGES.map((r) => h('option', { value: r, selected: r === range }, 'Last ' + r)));
  const addBtn = h('button', { class: 'btn primary', onclick: () => openAddDialog() }, '+ Add target');
  const editBtn = h('button', { type: 'button', class: 'btn icon-btn edit-toggle', onclick: () => (editing ? save() : startEdit()) });
  const cancelBtn = h('button', { type: 'button', class: 'btn edit-only', onclick: () => cancelEdit() }, 'Cancel');
  const resetBtn = h('button', { type: 'button', class: 'btn edit-only', onclick: () => { layout = defaultLayout(); applyLayout(); } }, 'Reset to default');
  const editHint = h('div', { class: 'edit-hint edit-only', role: 'note' },
    'Drag the ⠿ handles (or focus one and use the arrow keys) to arrange sections, target cards and DNS groups. Press ', checkIcon(), ' to save the layout to your profile.');
  const head = h('div', { class: 'page-head' }, h('h1', null, 'Overview'), h('div', { class: 'grow' }), rangeSel, addBtn, resetBtn, cancelBtn, editBtn);
  const netEl = h('section', { class: 'diag net-verdict', hidden: true, 'aria-live': 'polite' });
  const stripEl = h('div', { class: 'strip' });
  const gridEl = h('div', { class: 'target-grid' });
  const msgEl = h('div', { class: 'state-msg', hidden: true });
  const dns = dnsPanel({
    title: 'DNS probes', range: () => range,
    layout: () => layout.dns, editing: () => editing,
    onLayoutChange: (patch) => { Object.assign(layout.dns, patch); },
  });
  const wrap = h('div', { class: 'overview' });
  const sectionsEl = h('div', { class: 'ov-sections' });
  const secEls = {};
  const content = { network: [netEl], status: [stripEl], targets: [msgEl, gridEl], dns: [dns.el] };
  for (const id of Object.keys(SECTIONS)) {
    const hideBtn = h('button', { type: 'button', class: 'btn sm', onclick: () => toggleHidden(id) });
    secEls[id] = { hideBtn, el: h('div', { class: 'ov-section', dataset: { key: id } },
      h('div', { class: 'ov-edit-bar edit-only' },
        h('button', { type: 'button', class: 'drag-handle', 'aria-label': 'Move section ' + SECTIONS[id] + ' (arrow keys)', title: 'Drag to move' }, '⠿'),
        h('span', { class: 'ov-edit-title' }, SECTIONS[id]),
        id === 'network' ? h('span', { class: 'muted ov-edit-note' }, 'shown when something needs attention') : null,
        h('div', { class: 'grow' }), hideBtn),
      content[id]) };
    sectionsEl.append(secEls[id].el);
  }
  wrap.append(head, editHint, sectionsEl);
  root.append(wrap);
  const detach = [
    sortable(sectionsEl, { items: '.ov-section', handle: '.ov-edit-bar .drag-handle', enabled: () => editing,
      onChange: (order) => { const byId = new Map(layout.sections.map((x) => [x.id, x])); layout.sections = order.map((id) => byId.get(id)); } }),
    sortable(gridEl, { items: '.tcard', handle: '.drag-handle', enabled: () => editing,
      onChange: (order) => { layout.target_order = order.map(Number); } }),
  ];

  function shown(id) { const x = layout.sections.find((s) => s.id === id); return !x || !x.hidden; }
  function toggleHidden(id) {
    const x = layout.sections.find((s) => s.id === id);
    if (x) x.hidden = !x.hidden;
    applyLayout();
  }
  /** puts the sections in layout order, shows/hides them and re-renders the arranged lists */
  function applyLayout() {
    for (const x of layout.sections) {
      const s = secEls[x.id];
      sectionsEl.append(s.el);
      s.el.classList.toggle('is-hidden', !!x.hidden);
      s.hideBtn.textContent = x.hidden ? 'Show' : 'Hide';
      s.hideBtn.setAttribute('aria-label', (x.hidden ? 'Show ' : 'Hide ') + SECTIONS[x.id]);
    }
    wrap.classList.toggle('editing', editing);
    clear(editBtn).append(editing ? checkIcon() : pencilIcon(), h('span', { class: 'sr-only' }, editing ? 'Save layout' : 'Edit layout'));
    editBtn.title = editing ? 'Save layout' : 'Edit layout';
    editBtn.setAttribute('aria-pressed', editing ? 'true' : 'false');
    editBtn.classList.toggle('primary', editing);
    editBtn.disabled = saving;
    renderGrid(true);
    dns.render();
  }
  function startEdit() { layout = normLayout(saved); editing = true; applyLayout(); dns.load(); }
  function cancelEdit() { layout = normLayout(saved); editing = false; applyLayout(); dns.load(); }
  async function save() {
    saving = true; applyLayout();
    try {
      const r = await api.putOverviewLayout(layout);
      saved = normLayout(r && r.overview);
      layout = normLayout(saved);
      editing = false;
    } catch (e) {
      alert('Could not save the layout: ' + e.message);
    } finally {
      saving = false;
      applyLayout();
      if (!editing) { load(); dns.load(); }
    }
  }
  function onKey(e) { if (editing && e.key === 'Escape' && !document.querySelector('dialog[open]')) cancelEdit(); }
  document.addEventListener('keydown', onKey);
  async function loadProfile() {
    try {
      const p = await api.profile({ quiet: true });
      if (destroyed || editing) return;
      saved = normLayout(p && p.overview);
      layout = normLayout(saved);
      applyLayout();
    } catch (e) { /* keep the default layout */ }
  }

  function renderStrip() {
    const s = getStatus();
    clear(stripEl);
    const list = targets || [];
    const counts = { ok: 0, bad: 0, other: 0 };
    for (const t of list) { if (t.active === false) continue; if (t.status === 'ok') counts.ok++; else if (t.status === 'alerting' || t.status === 'degraded') counts.bad++; else counts.other++; }
    const local = s ? s.local_status : null;
    stripEl.append(
      stat('Local connectivity', local === 'ok' ? 'OK' : local === 'down' ? 'DOWN' : local ? 'Unknown' : DASH, local === 'ok' ? 'ok' : local === 'down' ? 'crit' : '', 'Gateway and first hops'),
      stat('Active alerts', s ? String(s.active_alerts) : DASH, s && s.active_alerts > 0 ? 'crit' : 'ok', h('a', { href: '#/alerts' }, 'View alerts')),
      stat('Targets', String(list.length), '', targets ? `${counts.ok} ok · ${counts.bad} need attention${counts.other ? ' · ' + counts.other + ' other' : ''}` : ''),
      s ? stat('ICMP mode', s.icmp_mode, s.icmp_mode === 'unavailable' ? 'crit' : '', s.icmp_mode === 'unavailable' ? 'Hop traces are disabled; HTTP/TCP probes still work' : 'v' + s.version) : null);
  }
  function stat(k, v, cls, sub) {
    return h('div', { class: 'card stat ' + (cls || '') }, h('div', { class: 'k' }, k), h('div', { class: 'v' }, v), h('div', { class: 's' }, sub || ' '));
  }

  function targetCard(t) {
    const sm = t.summary || {};
    const paused = t.active === false;
    const hasHttp = (t.probes || []).some((p) => p.type === 'http');
    const sp = spark.get(t.id);
    const act = h('div', { class: 'actions' });
    if (!t.removed) act.append(h('button', { class: 'btn sm', onclick: (e) => { e.stopPropagation(); openEdit(t); } }, 'Edit'));
    act.append(h('button', { class: 'btn sm', onclick: (e) => { e.stopPropagation(); togglePause(t); } }, paused ? 'Resume' : 'Pause'));
    if (t.source === 'ui') act.append(h('button', { class: 'btn sm danger', onclick: (e) => { e.stopPropagation(); removeTarget(t); } }, 'Delete'));
    act.append(h('span', { class: 'src', title: t.overridden ? 'Defined in the config file, with settings edited in the UI' : null },
      t.source === 'ui' ? 'added in UI' : t.overridden ? 'config · edited in UI' : 'from config'));
    const e2e = sm.e2e_rtt_ms;
    return h('article', { class: 'card tcard' + (paused ? ' paused' : ''), dataset: { id: t.id, key: String(t.id) } },
      h('div', { class: 'top' },
        h('button', { type: 'button', class: 'drag-handle edit-only', 'aria-label': 'Move ' + t.name + ' (arrow keys)', title: 'Drag to move' }, '⠿'),
        h('div', { class: 'grow' },
          h('div', { class: 'name' }, h('a', { href: '#/target/' + t.id }, t.name)),
          h('div', { class: 'host' }, t.host + (t.resolved_ip && t.resolved_ip !== t.host ? ' · ' + t.resolved_ip : ''))),
        statusPill(t.status, t.active)),
      diagLine(t.diagnosis),
      h('div', { class: 'bigline' },
        h('span', { class: 'big' }, isNum(e2e) ? fmtMs(e2e) : DASH, isNum(e2e) ? h('small', null, ' ms') : null),
        h('span', { class: 'muted' }, t.icmp_unresponsive ? 'e2e (TCP; no ping reply)' : 'end-to-end')),
      h('div', { class: 'metrics' },
        metric('Loss', fmtPct(sm.e2e_loss_pct), metricClass('loss', sm.e2e_loss_pct)),
        metric('MOS', fmtMos(sm.mos), metricClass('mos', sm.mos)),
        metric('HTTP ok', hasHttp ? fmtPct(sm.http_success_pct) : DASH, hasHttp ? metricClass('success', sm.http_success_pct) : ''),
        metric('Hops', isNum(sm.hop_count) ? String(sm.hop_count) : DASH, '')),
      h('div', { class: 'spark' }, sparkline(sp ? sp.points : null)),
      act);
  }
  /** one line saying what is wrong, only when something is (healthy cards stay quiet) */
  function diagLine(d) {
    if (!d || (d.severity !== 'warn' && d.severity !== 'crit')) return null;
    return h('div', { class: 'diag-line ' + d.severity }, d.where && WHERE[d.where] ? h('span', { class: 'diag-where' }, WHERE[d.where]) : null, d.headline);
  }
  /** the combined verdict: where along the path (your network → DNS → ISP → internet → destinations) the problem is */
  function renderNetwork() {
    if (!net) { netEl.hidden = true; netKey = ''; return; }
    const key = JSON.stringify(net);
    if (key === netKey) return; // unchanged: keep focus and selection
    netKey = key;
    const v = net;
    netEl.className = 'diag net-verdict ' + (v.severity || 'info');
    const chain = h('ol', { class: 'net-chain', 'aria-label': 'Network path, from this server outwards' },
      (v.segments || []).map((sg) => h('li', { class: 'net-seg ' + sg.state, title: sg.note || null },
        h('span', { class: 'net-dot', 'aria-hidden': 'true' }),
        h('span', { class: 'net-label' }, sg.label),
        h('span', { class: 'sr-only' }, ': ' + SEG_STATE[sg.state] + (sg.note ? ' (' + sg.note + ')' : '')))));
    const link = v.target_id != null
      ? h('a', { class: 'btn sm', href: '#/target/' + v.target_id + (v.hop != null ? '?ttl=' + v.hop : '') }, v.hop != null ? 'Show hop ' + v.hop : 'Open target')
      : null;
    clear(netEl).append(
      h('div', { class: 'diag-text' },
        h('div', { class: 'diag-head' }, v.where && WHERE[v.where] ? h('span', { class: 'diag-where' }, WHERE[v.where]) : null, h('strong', null, v.headline)),
        v.detail ? h('div', { class: 'diag-detail' }, v.detail) : null,
        chain,
        h('div', { class: 'diag-note' }, 'Whole network, based on the last 5 minutes')));
    if (link) netEl.append(link);
    netEl.hidden = false;
  }
  function metric(k, v, cls) { return h('div', { class: 'metric' }, h('div', { class: 'k' }, k), h('div', { class: 'v ' + (cls || '') }, v)); }

  function render() {
    renderNetwork();
    renderStrip();
    renderGrid(false);
  }
  /** target cards in the layout's order; while editing they are only rebuilt on a layout change, so a drag is never cut short */
  function renderGrid(layoutChanged) {
    if (editing && !layoutChanged && gridEl.childElementCount) return;
    clear(gridEl);
    if (!targets) return;
    msgEl.hidden = true;
    if (!targets.length) {
      msgEl.hidden = false; msgEl.className = 'empty-card'; clear(msgEl);
      msgEl.append(h('h3', null, 'No targets yet'), h('p', null, 'Add a host to start tracing the network path to it. First results appear within a few seconds.'), h('button', { class: 'btn primary', onclick: () => openAddDialog() }, '+ Add target'));
      return;
    }
    for (const t of applyOrder(targets, layout.target_order, (x) => x.id)) gridEl.append(targetCard(t));
  }

  // The sparkline only changes once per bucket (range / 60), so it is refetched at most every min(max(10 s, step), 60 s),
  // or at once when the range changes; /api/targets keeps its own cadence. Loads never overlap: a request that arrives while
  // one is in flight becomes a single follow-up, except a range change, which cancels the (now useless) in-flight load.
  const sparkEvery = () => clamp(RANGE_MS[range] / SPARK_BUCKETS, TARGETS_MS, 60000);
  async function load({ fresh = false } = {}) {
    if (destroyed) return;
    if (busy) { if (!fresh) { again = true; return; } ctl.abort(); }
    const my = ++seq;
    const signal = (ctl = new AbortController()).signal;
    busy = true; again = false;
    const started = Date.now(), rng = range;
    const wantSpark = sparkRange !== rng || started - sparkAt >= sparkEvery() - 500; // 500 ms: interval ticks are not exact
    if (!loadedOnce) { msgEl.hidden = false; msgEl.className = 'state-msg'; clear(msgEl).append(h('span', { class: 'spinner' }), 'Loading targets…'); }
    try {
      const [t, o, n] = await Promise.all([api.targets({ signal }),
        wantSpark ? api.overview({ range: rng }, { signal }).catch((e) => { if (e && e.name === 'AbortError') throw e; return null; }) : null,
        api.network({ signal, quiet: true }).catch((e) => { if (e && e.name === 'AbortError') throw e; return null; })]);
      if (my !== seq || destroyed) return;
      targets = t || [];
      net = n;
      if (o) { spark = new Map(o.map((x) => [x.target_id, x])); sparkAt = started; sparkRange = rng; }
      else if (wantSpark && sparkRange !== rng) spark = new Map(); // failed for a new range: don't show the old range's lines (retried next load)
      loadedOnce = true;
      render();
    } catch (e) {
      if (e.name === 'AbortError' || destroyed) return;
      if (!loadedOnce) { msgEl.hidden = false; msgEl.className = 'state-msg error'; clear(msgEl).append('Could not load targets. ', h('span', { class: 'sub' }, e.message + ' — retrying…')); }
    } finally {
      if (my === seq) { busy = false; if (again && !destroyed) { again = false; load(); } }
    }
  }
  /** SSE-triggered load: a burst of events collapses into one load */
  function loadSoon() { if (!soon) soon = setTimeout(() => { soon = null; load(); }, SOON_MS); }

  async function togglePause(t) {
    try { if (t.active === false) await api.resumeTarget(t.id); else await api.pauseTarget(t.id); } catch (e) { alert(e.message); }
    load();
  }
  async function removeTarget(t) {
    const ok = await confirmDialog({ title: 'Delete target?', message: `Delete "${t.name}" (${t.host}) and stop monitoring it? Its history is no longer shown.`, confirmLabel: 'Delete', danger: true });
    if (!ok) return;
    try { await api.deleteTarget(t.id); } catch (e) { alert(e.message); }
    load();
  }

  function openAddDialog() { openTargetEditor({ onSaved: () => load() }); }
  function openEdit(t) { openTargetEditor({ id: t.id, onSaved: () => load() }); }

  const offs = [
    onStatus(() => renderStrip()),
    onStream('targets', loadSoon),
    onStream('alert', loadSoon),
  ];
  applyLayout();
  loadProfile();
  load();
  dns.load();
  timer = setInterval(() => { load(); }, TARGETS_MS);
  const dnsTimer = setInterval(() => { if (editing || shown('dns')) dns.load(); }, 15000);

  return {
    destroy() {
      destroyed = true; clearInterval(timer); clearInterval(dnsTimer); clearTimeout(soon); if (ctl) ctl.abort();
      offs.forEach((f) => f()); detach.forEach((f) => f()); document.removeEventListener('keydown', onKey);
    },
  };
}
