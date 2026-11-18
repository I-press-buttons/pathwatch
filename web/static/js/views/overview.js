// Overview: one card per target, status strip, DNS probes, add/edit target.
import { h, clear, isNum, fmtMs, fmtPct, fmtMos, fmtAgo, clamp, lsGet, lsSet, DASH, plural } from '../util.js';
import { api, onStream, serverNow } from '../api.js';
import { getStatus, onStatus } from '../store.js';
import { statusPill, sparkline, panel, confirmDialog, metricClass, WHERE } from '../ui.js';
import { dnsPanel } from './dns.js';
import { openTargetEditor } from './target-editor.js';

const RANGES = ['1h', '6h', '24h'];
const RANGE_MS = { '1h': 3600e3, '6h': 6 * 3600e3, '24h': 86400e3 };
const TARGETS_MS = 10000;   // /api/targets cadence
const SPARK_BUCKETS = 60;   // the sparkline overview is bucketed server side into this many steps
const SOON_MS = 300;        // SSE-triggered loads within this window collapse into one

export function mount(root, ctx) {
  let range = lsGet('pathwatch.overviewRange', '1h');
  if (!RANGES.includes(range)) range = '1h';
  let targets = null, spark = new Map(), loadedOnce = false, destroyed = false, timer = null, seq = 0;
  let busy = false, again = false, ctl = null, soon = null, sparkAt = 0, sparkRange = null;

  const rangeSel = h('select', { 'aria-label': 'Sparkline range', onchange: () => { range = rangeSel.value; lsSet('pathwatch.overviewRange', range); load({ fresh: true }); } },
    RANGES.map((r) => h('option', { value: r, selected: r === range }, 'Last ' + r)));
  const addBtn = h('button', { class: 'btn primary', onclick: () => openAddDialog() }, '+ Add target');
  const head = h('div', { class: 'page-head' }, h('h1', null, 'Overview'), h('div', { class: 'grow' }), rangeSel, addBtn);
  const stripEl = h('div', { class: 'strip' });
  const gridEl = h('div', { class: 'target-grid' });
  const msgEl = h('div', { class: 'state-msg', hidden: true });
  const dns = dnsPanel({ title: 'DNS probes', range: () => range });
  root.append(head, stripEl, msgEl, gridEl, dns.el);

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
    return h('article', { class: 'card tcard' + (paused ? ' paused' : ''), dataset: { id: t.id } },
      h('div', { class: 'top' },
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
  function metric(k, v, cls) { return h('div', { class: 'metric' }, h('div', { class: 'k' }, k), h('div', { class: 'v ' + (cls || '') }, v)); }

  function render() {
    renderStrip();
    clear(gridEl);
    if (!targets) return;
    msgEl.hidden = true;
    if (!targets.length) {
      msgEl.hidden = false; msgEl.className = 'empty-card'; clear(msgEl);
      msgEl.append(h('h3', null, 'No targets yet'), h('p', null, 'Add a host to start tracing the network path to it. First results appear within a few seconds.'), h('button', { class: 'btn primary', onclick: () => openAddDialog() }, '+ Add target'));
      return;
    }
    for (const t of targets) gridEl.append(targetCard(t));
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
      const [t, o] = await Promise.all([api.targets({ signal }),
        wantSpark ? api.overview({ range: rng }, { signal }).catch((e) => { if (e && e.name === 'AbortError') throw e; return null; }) : null]);
      if (my !== seq || destroyed) return;
      targets = t || [];
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
  load();
  dns.load();
  timer = setInterval(() => { load(); }, TARGETS_MS);
  const dnsTimer = setInterval(() => dns.load(), 15000);

  return {
    destroy() { destroyed = true; clearInterval(timer); clearInterval(dnsTimer); clearTimeout(soon); if (ctl) ctl.abort(); offs.forEach((f) => f()); },
  };
}
