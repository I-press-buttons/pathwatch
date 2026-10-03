// Shared UI components: pills, panels, dialogs, sparklines.
import { h, svg, clear, isNum, fmtMs, fmtPct, DASH } from './util.js';

export const STATUS = {
  ok: ['ok', 'OK'],
  degraded: ['warn', 'Degraded'],
  alerting: ['crit', 'Alerting'],
  silenced: ['info', 'Silenced'],
  nodata: ['', 'No data'],
  learning: ['info', 'Learning baseline'],
  paused: ['', 'Paused'],
};
export function statusPill(status, active = true) {
  const key = active === false ? 'paused' : status;
  const [cls, label] = STATUS[key] || ['', String(status || 'unknown')];
  return h('span', { class: 'pill ' + cls, title: 'Status: ' + label }, label);
}

export const ALERT_STATE = { firing: 'crit', resolved: 'ok', suppressed: 'info' };
export function alertPill(a) {
  const label = a.state === 'suppressed' && a.suppressed_reason ? `suppressed: ${a.suppressed_reason.replace('_', ' ')}` : a.state;
  return h('span', { class: 'pill ' + (ALERT_STATE[a.state] || '') }, label);
}
export const DELIVERY = { delivered: 'ok', queued: 'info', retrying: 'warn', failed: 'crit', expired: '' };
export function deliveryPill(d) {
  const tip = `${d.channel}: ${d.status}, ${d.attempts} attempt${d.attempts === 1 ? '' : 's'}` + (d.last_error ? `\n${d.last_error}` : '');
  return h('span', { class: 'pill ' + (DELIVERY[d.status] || ''), title: tip }, `${d.channel} · ${d.status}`);
}

/** A card-like panel with a header, stable content container and a message container (loading/empty/error). */
export function panel(title, { actions, cls, flush } = {}) {
  const content = h('div', { class: 'panel-content' });
  const msg = h('div', { class: 'state-msg', hidden: true });
  const body = h('div', { class: 'panel-body' + (flush ? ' flush' : '') }, content, msg);
  const head = h('header', null, h('h2', null, title), h('div', { class: 'grow' }), actions || null);
  const el = h('section', { class: 'panel ' + (cls || '') }, head, body);
  let hasData = false;
  const api = {
    el, head, body, content,
    showContent() { msg.hidden = true; content.hidden = false; hasData = true; el.classList.remove('refreshing'); },
    showLoading(text = 'Loading…') {
      if (hasData) { el.classList.add('refreshing'); return; }
      content.hidden = true; msg.hidden = false; msg.className = 'state-msg';
      clear(msg).append(h('span', { class: 'spinner' }), text);
    },
    showEmpty(text, sub) {
      hasData = false;
      content.hidden = true; msg.hidden = false; msg.className = 'state-msg'; clear(msg).append(text, sub ? h('span', { class: 'sub' }, sub) : null);
    },
    showError(text) {
      el.classList.remove('refreshing');
      if (hasData) { el.classList.add('stale'); return; } // keep last good data, banner explains
      content.hidden = true; msg.hidden = false; msg.className = 'state-msg error'; clear(msg).append('Could not load data. ', h('span', { class: 'sub' }, text || 'Retrying…'));
    },
    clearStale() { el.classList.remove('stale'); },
  };
  return api;
}

/** Inline SVG sparkline. points: [[ts, avg, loss%]]. Colours via CSS (follows theme automatically). */
export function sparkline(points, { loss = true, valueIdx = 1, lossIdx = 2 } = {}) {
  const W = 100, H = 40;
  const vals = (points || []).filter((p) => isNum(p[valueIdx]));
  const hasLoss = loss && (points || []).some((p) => isNum(p[lossIdx]) && p[lossIdx] > 0);
  if (!points || !points.length || (!vals.length && !hasLoss)) {
    return h('div', { class: 'spark-empty' }, points && points.length ? 'No replies in range' : 'No data yet');
  }
  const root = svg('svg', { viewBox: `0 0 ${W} ${H}`, preserveAspectRatio: 'none', role: 'img', 'aria-label': 'trend' });
  if (!vals.length) { addLoss(root, points, lossIdx, W, H); return root; }
  const sorted = vals.map((p) => p[valueIdx]).sort((a, b) => a - b);
  const max = sorted[sorted.length - 1];
  const med = sorted[Math.floor(sorted.length / 2)];
  const hi = Math.max(1, Math.min(max, med * 4 + 1)) * 1.08;
  const n = points.length;
  const x = (i) => (n === 1 ? W / 2 : (i / (n - 1)) * W);
  const y = (v) => H - 3 - (Math.min(v, hi) / hi) * (H - 8);
  let d = '', area = '', seg = [];
  const flush = () => {
    if (seg.length >= 2) {
      d += 'M' + seg.map(([i, v]) => `${x(i).toFixed(2)},${y(v).toFixed(2)}`).join('L');
      area += 'M' + x(seg[0][0]).toFixed(2) + ',' + H + 'L' + seg.map(([i, v]) => `${x(i).toFixed(2)},${y(v).toFixed(2)}`).join('L') + 'L' + x(seg[seg.length - 1][0]).toFixed(2) + ',' + H + 'Z';
    } else if (seg.length === 1) {
      const [i, v] = seg[0];
      d += `M${(x(i) - 0.4).toFixed(2)},${y(v).toFixed(2)}L${(x(i) + 0.4).toFixed(2)},${y(v).toFixed(2)}`;
    }
    seg = [];
  };
  points.forEach((p, i) => { if (isNum(p[valueIdx])) seg.push([i, p[valueIdx]]); else flush(); });
  flush();
  root.appendChild(svg('path', { d: area, class: 'area' }));
  root.appendChild(svg('path', { d, class: 'line' }));
  if (loss) addLoss(root, points, lossIdx, W, H);
  return root;
}
function addLoss(root, points, lossIdx, W, H) {
  const n = points.length;
  const bw = Math.max(0.8, W / Math.max(n, 1) * 0.9);
  points.forEach((p, i) => {
    const l = p[lossIdx];
    if (isNum(l) && l > 0) {
      const hgt = 3 + Math.min(1, l / 100) * 10;
      const cx = n === 1 ? W / 2 : (i / (n - 1)) * W;
      root.appendChild(svg('rect', { x: (cx - bw / 2).toFixed(2), y: H - hgt, width: bw.toFixed(2), height: hgt, class: 'lossbar' }));
    }
  });
}

// ---------- dialogs ----------
export function confirmDialog({ title, message, confirmLabel = 'Confirm', danger = false }) {
  return new Promise((resolve) => {
    const dlg = h('dialog', { 'aria-label': title });
    const form = h('form', { method: 'dialog' },
      h('h3', null, title), h('p', null, message),
      h('div', { class: 'actions' },
        h('button', { class: 'btn', type: 'button', onclick: () => dlg.close('cancel') }, 'Cancel'),
        h('button', { class: 'btn ' + (danger ? 'danger' : 'primary'), type: 'submit', value: 'ok' }, confirmLabel)));
    dlg.appendChild(form);
    dlg.addEventListener('close', () => { const ok = dlg.returnValue === 'ok'; dlg.remove(); resolve(ok); });
    document.body.appendChild(dlg);
    dlg.showModal();
  });
}

export function metricClass(kind, v) {
  if (!isNum(v)) return '';
  if (kind === 'loss') return v >= 5 ? 'crit' : v >= 1 ? 'warn' : '';
  if (kind === 'mos') return v < 3.1 ? 'crit' : v < 3.8 ? 'warn' : '';
  if (kind === 'success') return v < 90 ? 'crit' : v < 99.5 ? 'warn' : '';
  return '';
}
export { fmtMs, fmtPct, DASH };
