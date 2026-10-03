// Shared chart plumbing: layout constants, hover bus, time ticks (identical for heatmap and uPlot), uPlot option helpers.
import { getColors } from '../theme.js';
import { rgba, fmtDay, isNum } from '../util.js';

/** Width of the left uPlot axis. uPlot hosts are shifted right so their plot area starts at --gutter, like the heatmap. */
export const AX = 52;

export function readGutters(el) {
  const cs = getComputedStyle(el);
  const L = parseFloat(cs.getPropertyValue('--gutter')) || 250;
  const R = parseFloat(cs.getPropertyValue('--rgutter')) || 50;
  return { L, R };
}

/** Cross-panel hover time (ms). */
export const hoverBus = {
  subs: new Set(),
  emit(ts, src) { for (const fn of this.subs) fn(ts, src); },
  on(fn) { this.subs.add(fn); return () => this.subs.delete(fn); },
};

// ---------- time ticks in the local timezone ----------
const STEPS = [1e3, 2e3, 5e3, 10e3, 15e3, 30e3, 60e3, 2 * 60e3, 5 * 60e3, 10 * 60e3, 15 * 60e3, 30 * 60e3, 3600e3, 2 * 3600e3, 3 * 3600e3, 6 * 3600e3, 12 * 3600e3, 86400e3, 2 * 86400e3, 7 * 86400e3, 14 * 86400e3, 30 * 86400e3];
export function niceTicks(from, to, maxTicks) {
  const span = to - from;
  maxTicks = Math.max(2, maxTicks);
  let step = STEPS[STEPS.length - 1];
  for (const s of STEPS) if (span / s <= maxTicks) { step = s; break; }
  const ticks = [];
  const off0 = new Date(from).getTimezoneOffset() * 60000;
  let t = Math.floor((from - off0) / step) * step + off0;
  for (let i = 0; i < 1000 && t <= to; i++) {
    if (t >= from - 1) ticks.push(t);
    const prev = t;
    t += step;
    // keep alignment to local midnight across DST changes for day-sized steps
    if (step >= 86400e3) { const o = new Date(t).getTimezoneOffset() * 60000; t = Math.round((t - o) / 86400e3) * 86400e3 + o; if (t <= prev) t = prev + step; }
  }
  return { ticks, step, span };
}
const p2 = (n) => String(n).padStart(2, '0');
export function tickLabel(ts, step, span) {
  const d = new Date(ts);
  const hm = `${p2(d.getHours())}:${p2(d.getMinutes())}`;
  if (step >= 86400e3) return fmtDay(ts);
  if (d.getHours() === 0 && d.getMinutes() === 0 && d.getSeconds() === 0 && span > 3 * 3600e3) return fmtDay(ts);
  if (step < 60e3) return `${hm}:${p2(d.getSeconds())}`;
  if (span > 36 * 3600e3 && step >= 3600e3) return `${fmtDay(ts)} ${hm}`;
  return hm;
}

// ---------- uPlot helpers ----------
export function axisBase(c = getColors()) {
  return {
    stroke: rgba(c.axis), font: `11px ${c.font}`,
    grid: { stroke: rgba(c.grid), width: 1 },
    ticks: { stroke: rgba(c.grid), width: 1, size: 4 },
  };
}

/** Shared x axis: ticks identical to the heatmap and a fixed range from `axisRef` ({from,to} in ms). */
export function xAxis(axisRef, c = getColors()) {
  return {
    ...axisBase(c),
    size: 26,
    space: 80,
    splits: (u) => {
      const w = u.bbox.width / (window.devicePixelRatio || 1);
      return niceTicks(axisRef.from, axisRef.to, Math.floor(w / 90)).ticks.map((t) => t / 1000);
    },
    values: (u, splits) => {
      const w = u.bbox.width / (window.devicePixelRatio || 1);
      const { step, span } = niceTicks(axisRef.from, axisRef.to, Math.floor(w / 90));
      return splits.map((s) => tickLabel(s * 1000, step, span));
    },
  };
}
export function xScale(axisRef) {
  return { time: true, auto: false, range: () => [axisRef.from / 1000, axisRef.to / 1000] };
}

/** Drag-to-zoom: reports the selected [fromMs, toMs] and clears the selection box. */
export function zoomHooks(onZoom) {
  return {
    setSelect: [(u) => {
      const s = u.select;
      if (!s || s.width < 6) return;
      const a = u.posToVal(s.left, 'x') * 1000, b = u.posToVal(s.left + s.width, 'x') * 1000;
      u.setSelect({ left: 0, top: 0, width: 0, height: 0 }, false);
      if (isNum(a) && isNum(b) && b - a >= 1000) onZoom(Math.round(a), Math.round(b));
    }],
  };
}

/** Wire a uPlot instance into the shared hover bus (crosshair follows across panels). */
export function hookHoverBus(u, id) {
  const off = hoverBus.on((ts, src) => {
    if (src === id || !u.root.isConnected) return;
    if (ts == null) { u.setCursor({ left: -10, top: -10 }, false); return; }
    const left = u.valToPos(ts / 1000, 'x');
    if (left < 0 || left > u.bbox.width / (window.devicePixelRatio || 1)) { u.setCursor({ left: -10, top: -10 }, false); return; }
    u.setCursor({ left, top: 10 }, false);
  });
  return {
    hook: (uu) => {
      const l = uu.cursor.left;
      if (l == null || l < 0) hoverBus.emit(null, id);
      else hoverBus.emit(uu.posToVal(l, 'x') * 1000, id);
    },
    off,
  };
}
