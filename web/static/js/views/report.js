// Printable report for one target and time range (#/target/{id}/report?from=&to=): summary,
// incidents with the hop where the degradation starts, probe impact, monitor gaps, path changes.
// Everything comes from GET /api/targets/{id}/report. The page is meant for print (see @media print).
import { h, clear, isNum, fmtMs, fmtPct, fmtMos, fmtInt, fmtDateTime, fmtDuration, DASH, plural } from '../util.js';
import { api, serverNow } from '../api.js';
import { metricClass } from '../ui.js';

const DAY = 86400e3;
const SEV_CLASS = { critical: 'crit', warning: 'warn', info: 'info' };

const KIND_LABEL = {
  final_hop_loss: 'Destination loss', path_degradation: 'Path degradation', http_failure: 'HTTP failure', http_latency: 'HTTP latency',
  tcp_failure: 'TCP failure', dns_failure: 'DNS failure', dns_latency: 'DNS latency', cert_expiry: 'Certificate expiry', route_change: 'Route change',
  degraded: 'Degraded path', icmp_unresponsive: 'Destination ignores ICMP', local_outage: 'Local network outage',
};

function range(query) {
  let from = Number(query.get('from')), to = Number(query.get('to'));
  if (!(from > 0 && to > from)) { to = Math.round(serverNow()); from = to - DAY; }
  return { from, to };
}

function metric(label, value, cls, sub) {
  return h('div', { class: 'card metric' }, h('div', { class: 'label' }, label), h('div', { class: 'value ' + (cls || '') }, value), sub ? h('div', { class: 'sub muted' }, sub) : null);
}

function hopLabel(o) {
  const parts = [h('strong', null, 'Hop ' + o.ttl)];
  if (o.address) parts.push(' ', h('span', { class: 'mono' }, o.address));
  if (o.hostname) parts.push(h('div', { class: 'mono muted wrap' }, o.hostname));
  if (o.asn) parts.push(h('div', { class: 'muted' }, 'AS' + o.asn + (o.as_name ? ' ' + o.as_name : '')));
  parts.push(h('div', { class: 'muted' }, o.reason === 'loss' ? `loss ${fmtPct(o.loss_pct)}` : `latency ${fmtMs(o.avg_ms)} ms` + (isNum(o.baseline_max_ms) ? ` (normal up to ${fmtMs(o.baseline_max_ms)} ms)` : '')));
  return parts;
}

function probeImpact(list) {
  const rows = (list || []).filter((p) => p.samples > 0);
  if (!rows.length) return h('span', { class: 'muted' }, 'No probe data');
  return h('div', null, rows.map((p) => h('div', null,
    h('span', { class: 'muted' }, p.type.toUpperCase() + ' '),
    h('span', { class: metricClass('success', p.success_pct) }, fmtPct(p.success_pct)),
    ` ok (${plural(p.errors, 'failure')} of ${p.samples})`)));
}

export function mount(root, ctx) {
  const id = Number(ctx.params.id);
  let destroyed = false, ac = null;
  let cur = range(ctx.query);

  const back = h('a', { class: 'btn sm', href: '#/target/' + id }, '← Target');
  const printBtn = h('button', { class: 'btn sm primary', type: 'button', onclick: () => window.print() }, 'Print / save as PDF');
  const csvLink = h('a', { class: 'btn sm', href: '#', download: '' }, 'Export CSV');
  const jsonLink = h('a', { class: 'btn sm', href: '#', download: '' }, 'Export JSON');
  const title = h('h1', null, 'Network path report');
  const sub = h('div', { class: 'sub muted' });
  const toolbar = h('div', { class: 'report-tools no-print' }, back, h('div', { class: 'grow' }), csvLink, jsonLink, printBtn);
  const head = h('header', { class: 'report-head' }, title, sub);
  const body = h('div', { class: 'report-body' });
  root.append(h('div', { class: 'report' }, toolbar, head, body));

  function links() {
    const q = (extra) => new URLSearchParams({ from: String(cur.from), to: String(cur.to), ...extra }).toString();
    csvLink.setAttribute('href', `/api/targets/${id}/export?` + q({ format: 'csv', kind: 'hops' }));
    jsonLink.setAttribute('href', `/api/targets/${id}/export?` + q({ format: 'json', kind: 'hops' }));
  }

  function section(titleText, ...content) {
    return h('section', { class: 'report-section' }, h('h2', null, titleText), ...content);
  }
  function table(cols, rows) {
    return h('div', { class: 'table-scroll' }, h('table', { class: 'grid report-table' },
      h('thead', null, h('tr', null, cols.map(([t, c]) => h('th', { class: c || '' }, t)))),
      h('tbody', null, rows)));
  }

  function render(d) {
    const s = d.summary;
    document.title = `pathwatch report: ${d.target.name}`;
    clear(title).append('Network path report: ', d.target.name);
    clear(sub).append(`${d.target.host} · ${fmtDateTime(d.from)} to ${fmtDateTime(d.to)} (${fmtDuration(d.to - d.from)}) · generated ${fmtDateTime(d.generated_at)}`);
    const srcNote = { icmp: 'destination, ICMP', tcp: 'TCP probe', last_hop: 'last responding hop', http: 'HTTP probe', none: 'no data' }[s.source] || s.source;
    const probeCards = [...s.http, ...s.tcp]
      .map((p) => metric((p.label || p.type) + ' success rate', fmtPct(p.success_pct), metricClass('success', p.success_pct), `${p.type.toUpperCase()}, ${fmtInt(p.samples)} samples${isNum(p.avg_ms) ? ', avg ' + fmtMs(p.avg_ms) + ' ms' : ''}`));
    const summary = section('Summary',
      s.samples ? null : h('p', { class: 'muted' }, 'No data was recorded for this target in the period.'),
      h('div', { class: 'cards metrics' },
        metric('Availability', fmtPct(s.availability_pct), metricClass('loss', s.loss_pct), 'Source: ' + srcNote),
        metric('Packet loss', fmtPct(s.loss_pct), metricClass('loss', s.loss_pct), `${fmtInt(s.samples)} probes`),
        metric('Latency avg', isNum(s.avg_ms) ? fmtMs(s.avg_ms) + ' ms' : DASH),
        metric('Latency p95', isNum(s.p95_ms) ? fmtMs(s.p95_ms) + ' ms' : DASH),
        metric('Jitter', isNum(s.jitter_ms) ? fmtMs(s.jitter_ms) + ' ms' : DASH),
        metric('MOS', fmtMos(s.mos), metricClass('mos', s.mos), 'Voice quality estimate, 1 to 4.5'),
        probeCards));

    const incRows = d.incidents.map((i) => h('tr', null,
      h('td', { class: 'l' }, fmtDateTime(i.started_at), h('div', { class: 'muted' }, i.ongoing ? 'ongoing at end of period' : 'until ' + fmtDateTime(i.ended_at))),
      h('td', null, fmtDuration(i.duration_ms)),
      h('td', { class: 'l' }, h('span', { class: 'pill ' + (SEV_CLASS[i.severity] || '') }, i.severity),
        h('div', null, KIND_LABEL[i.kind] || i.kind, i.rule ? h('span', { class: 'muted' }, ' · ' + i.rule) : null),
        i.message ? h('div', { class: 'muted wrap' }, i.message) : null),
      h('td', { class: 'l' }, i.origin ? hopLabel(i.origin) : h('span', { class: 'muted' }, i.source === 'event' && i.ttl ? 'Hop ' + i.ttl + ' (reported)' : 'Not attributed to a hop')),
      h('td', { class: 'l' }, probeImpact(i.probes))));
    const incidents = section('Incidents',
      d.incidents.length ? table([['Started', 'l'], ['Duration', ''], ['What', 'l'], ['Degradation starts at', 'l'], ['Probe impact during the incident', 'l']], incRows)
        : h('p', { class: 'muted' }, 'No alerts or degradation events in this period.'),
      d.truncated ? h('p', { class: 'muted' }, 'Only the first incidents are listed; narrow the period to see the rest.') : null,
      h('p', { class: 'hint' }, '"Degradation starts at" is the first hop that lost packets or slowed down while everything after it did too. A hop that degrades alone is rate-limiting ICMP and is not reported.'));

    const gaps = section('Monitor gaps (no data)',
      d.gaps.length ? table([['From', 'l'], ['To', 'l'], ['Duration', '']], d.gaps.map((g) => h('tr', null, h('td', { class: 'l' }, fmtDateTime(g.from)), h('td', { class: 'l' }, fmtDateTime(g.to)), h('td', null, fmtDuration(g.duration_ms)))))
        : h('p', { class: 'muted' }, 'None. pathwatch was probing throughout.'),
      h('p', { class: 'hint' }, 'While pathwatch was not running or the host was suspended nothing was measured. These periods are no data, not packet loss.'));

    const changes = section('Path changes',
      d.path_changes.length ? table([['When', 'l'], ['From', 'l'], ['To', 'l']], d.path_changes.map((c) => h('tr', null,
        h('td', { class: 'l' }, fmtDateTime(c.at)), h('td', { class: 'l mono' }, c.from_ip || DASH), h('td', { class: 'l mono' }, c.to_ip || c.resolved_ip || DASH))))
        : h('p', { class: 'muted' }, 'The path did not change.'));

    clear(body).append(summary, incidents, gaps, changes);
  }

  async function load() {
    if (ac) ac.abort();
    ac = new AbortController();
    const signal = ac.signal;
    links();
    clear(body).append(h('div', { class: 'state-msg' }, h('span', { class: 'spinner' }), 'Building the report…'));
    try {
      const d = await api.report(id, { from: cur.from, to: cur.to }, { signal });
      if (destroyed) return;
      render(d);
    } catch (e) {
      if (destroyed || (e && e.name === 'AbortError')) return;
      clear(body).append(h('div', { class: 'state-msg error' }, 'Could not build the report: ' + e.message));
    }
  }
  load();

  return {
    update(c) {
      const next = range(c.query);
      if (next.from === cur.from && next.to === cur.to) return;
      cur = next;
      load();
    },
    destroy() { destroyed = true; if (ac) ac.abort(); },
  };
}
