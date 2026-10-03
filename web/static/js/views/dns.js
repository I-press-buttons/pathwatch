// DNS probe mini-panel (used on Overview and Settings).
import { h, clear, isNum, fmtMs, fmtPct, DASH } from '../util.js';
import { api } from '../api.js';
import { panel, sparkline } from '../ui.js';

export function dnsPanel({ title = 'DNS probes', range }) {
  const p = panel(title);
  let seq = 0;
  p.showLoading('Loading DNS probes…');
  async function load() {
    const my = ++seq;
    try {
      const data = await api.dns({ range: typeof range === 'function' ? range() : range || '1h', buckets: 60 });
      if (my !== seq) return;
      p.clearStale();
      if (!data || !data.length) {
        p.showEmpty('No DNS probes configured.', 'Add dns_probes to the config file to monitor a resolver such as your router or Pi-hole.');
        return;
      }
      const grid = h('div', { class: 'dns-grid' });
      for (const d of data) {
        const pts = d.points || [];
        const last = [...pts].reverse().find((x) => isNum(x[1]));
        const lastAny = pts[pts.length - 1];
        const failing = lastAny && isNum(lastAny[2]) && lastAny[2] >= 50;
        const totalFail = pts.filter((x) => isNum(x[2]));
        const avgFail = totalFail.length ? totalFail.reduce((a, x) => a + x[2], 0) / totalFail.length : null;
        grid.append(h('div', { class: 'dns-item' },
          h('div', { class: 'grow' },
            h('div', { class: 't' }, d.name),
            h('div', { class: 'm', title: `${d.server} · ${d.query}` }, `${d.server} · ${d.query}`),
            h('div', { class: 'm' }, isNum(avgFail) ? `${fmtPct(avgFail)} failed` : 'no data yet')),
          h('div', { class: 'spark' }, sparkline(pts)),
          h('div', { class: 'val' }, failing ? h('span', { class: 'pill crit' }, 'failing') : (last ? fmtMs(last[1]) + ' ms' : DASH))));
      }
      clear(p.content).append(grid);
      p.showContent();
    } catch (e) {
      if (e.name === 'AbortError') return;
      p.showError(e.message);
    }
  }
  return { el: p.el, load };
}
