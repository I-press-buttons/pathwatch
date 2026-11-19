// DNS probe panel (used on Overview and Settings). On the overview the cards can be grouped by DNS
// server or by query target, and in edit mode the groups and cards can be reordered.
import { h, clear, isNum, fmtMs, fmtInt, DASH, plural } from '../util.js';
import { api } from '../api.js';
import { panel, sparkline } from '../ui.js';
import { sortable, applyOrder } from '../sortable.js';

export const DNS_GROUPINGS = [
  ['server', 'DNS server'],
  ['query', 'Query target'],
  ['none', 'No grouping'],
];

const queryLabel = (d) => d.query + (d.record && d.record !== 'A' ? ' ' + d.record : '');
const groupKey = (d, by) => (by === 'server' ? d.name || d.server : queryLabel(d));

/**
 * @param {object} o
 * @param {string} [o.title]
 * @param {string|(() => string)} [o.range]
 * @param {string} [o.emptyHint]
 * @param {() => object|null} [o.layout]   the DNS part of the overview layout ({group_by, probe_order, group_order})
 * @param {() => boolean} [o.editing]      edit mode: show handles and the grouping control, pause refreshes
 * @param {(patch: object) => void} [o.onLayoutChange]  called with the changed layout fields
 */
export function dnsPanel({ title = 'DNS probes', range, emptyHint, layout = () => null, editing = () => false, onLayoutChange = () => {} }) {
  const groupSel = h('select', { class: 'edit-only', 'aria-label': 'Group DNS probes by', onchange: () => { onLayoutChange({ group_by: groupSel.value }); render(); } },
    DNS_GROUPINGS.map(([v, l]) => h('option', { value: v }, 'Group by: ' + l)));
  const rangeNote = h('span', { class: 'dns-range' });
  const p = panel(title, { actions: [rangeNote, groupSel], cls: 'dns-panel' });
  let seq = 0, data = null, detach = [];
  const rangeText = () => 'last ' + (typeof range === 'function' ? range() : range || '1h');
  p.showLoading('Loading DNS probes…');

  async function load() {
    if (editing() && data) return; // keep the cards still while they are being arranged
    const my = ++seq;
    try {
      const d = await api.dns({ range: typeof range === 'function' ? range() : range || '1h', buckets: 60 });
      if (my !== seq) return;
      p.clearStale();
      data = d || [];
      render();
    } catch (e) {
      if (e.name === 'AbortError') return;
      p.showError(e.message);
    }
  }

  function render() {
    detach.forEach((f) => f()); detach = [];
    if (!data) return;
    const l = layout() || {};
    const by = DNS_GROUPINGS.some(([v]) => v === l.group_by) ? l.group_by : 'none';
    groupSel.value = by;
    rangeNote.textContent = 'Failures in the ' + rangeText();
    if (!data.length) {
      p.showEmpty('No DNS probes configured.', emptyHint || ['Add one under ', h('a', { href: '#/settings' }, 'Settings → DNS probe setup'), ' to monitor a resolver such as your router or Pi-hole.']);
      return;
    }
    const probes = applyOrder(data, l.probe_order, (d) => d.probe_id);
    const root = h('div', { class: 'dns-groups' });
    if (by === 'none') {
      root.append(cardGrid(probes, by));
    } else {
      const groups = new Map();
      for (const d of probes) {
        const k = groupKey(d, by);
        if (!groups.has(k)) groups.set(k, []);
        groups.get(k).push(d);
      }
      const keys = applyOrder([...groups.keys()], (l.group_order || {})[by], (k) => k);
      for (const k of keys) root.append(groupEl(k, groups.get(k), by));
      detach.push(sortable(root, {
        items: '.dns-group', handle: '.dns-group > header .drag-handle', enabled: editing,
        onChange: (order) => onLayoutChange({ group_order: { ...((layout() || {}).group_order || {}), [by]: order } }),
      }));
    }
    clear(p.content).append(root);
    p.showContent();

    function cardOrder() { return [...root.querySelectorAll('.dns-item')].map((x) => Number(x.dataset.key)); }
    function cardGrid(list, mode) {
      const grid = h('div', { class: 'dns-grid' }, list.map((d) => card(d, mode)));
      detach.push(sortable(grid, { items: '.dns-item', handle: '.drag-handle', enabled: editing, onChange: () => onLayoutChange({ probe_order: cardOrder() }) }));
      return grid;
    }
    function groupEl(k, list, mode) {
      const fails = list.reduce((a, d) => a + (d.failures || 0), 0);
      const samples = list.reduce((a, d) => a + (d.samples || 0), 0);
      const failingNow = list.filter(isFailingNow).length;
      const servers = [...new Set(list.map((d) => d.server))];
      const sub = mode === 'server' ? servers.join(', ') + ' · ' + plural(list.length, 'query', 'queries') : plural(list.length, 'DNS server');
      return h('section', { class: 'dns-group', dataset: { key: k } },
        h('header', null,
          h('button', { type: 'button', class: 'drag-handle edit-only', 'aria-label': 'Move group ' + k + ' (arrow keys)', title: 'Drag to move' }, '⠿'),
          h('div', { class: 'grow' },
            h('h3', null, k),
            h('div', { class: 'dns-group-sub' }, sub)),
          failingNow ? h('span', { class: 'pill crit' }, failingNow + ' failing now') : null,
          failBadge(fails, samples)),
        cardGrid(list, mode));
    }
  }

  function failBadge(fails, samples) {
    if (!samples) return h('span', { class: 'fail-count none', title: 'No queries in the ' + rangeText() }, 'no data');
    return h('span', { class: 'fail-count ' + (fails ? 'crit' : 'ok'), title: `${fmtInt(fails)} of ${fmtInt(samples)} queries failed in the ${rangeText()}` },
      fails ? plural(fails, 'failure') : 'No failures');
  }
  function isFailingNow(d) {
    const pts = d.points || [];
    const lastAny = pts[pts.length - 1];
    return !!lastAny && isNum(lastAny[2]) && lastAny[2] >= 50;
  }
  function card(d, mode) {
    const pts = d.points || [];
    const last = [...pts].reverse().find((x) => isNum(x[1]));
    const q = queryLabel(d);
    const titleText = mode === 'server' ? q : d.name;
    const meta = mode === 'server' ? d.server : mode === 'query' ? d.server : q + ' · ' + d.server;
    return h('div', { class: 'dns-item', dataset: { key: String(d.probe_id) } },
      h('button', { type: 'button', class: 'drag-handle edit-only', 'aria-label': 'Move ' + d.label + ' (arrow keys)', title: 'Drag to move' }, '⠿'),
      h('div', { class: 'grow' },
        h('div', { class: 't', title: titleText }, titleText),
        h('div', { class: 'm', title: `${q} · ${d.server}` }, meta),
        h('div', { class: 'fails' }, failBadge(d.failures || 0, d.samples || 0),
          d.samples ? h('span', { class: 'of' }, ' of ' + fmtInt(d.samples)) : null)),
      h('div', { class: 'spark' }, sparkline(pts)),
      h('div', { class: 'val' }, isFailingNow(d) ? h('span', { class: 'pill crit' }, 'failing') : (last ? fmtMs(last[1]) + ' ms' : DASH)));
  }

  return { el: p.el, load, render };
}
