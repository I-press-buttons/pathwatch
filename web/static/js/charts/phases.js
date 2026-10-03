// HTTP phases chart: stacked DNS/TCP/TLS/TTFB/transfer bars per bucket, TCP connect overlay line, failure markers.
import { isNum, fmtMs, fmtPct, rgba } from '../util.js';
import { getColors } from '../theme.js';
import { UChart } from './uchart.js';
import { AX, axisBase, xAxis, xScale, zoomHooks, readGutters } from './common.js';

const PHASES = [
  ['dns', 'DNS', 1], ['connect', 'TCP', 2], ['tls', 'TLS', 3], ['ttfb', 'TTFB', 4], ['transfer', 'Transfer', 5],
];

export class PhasesChart extends UChart {
  constructor(host, o) { super(host, { ...o, height: 230, id: 'phases' }); this.fail = []; this.stepSec = 60; }

  /** http: probe object {points:[[ts,dns,connect,tls,ttfb,transfer,total,success]]} or null; tcp: probe {points:[[ts,connect,fail]]} or null */
  load(http, tcp, stepMs) {
    const tsSet = new Set();
    (http ? http.points : []).forEach((p) => tsSet.add(p[0]));
    (tcp ? tcp.points : []).forEach((p) => tsSet.add(p[0]));
    const ts = [...tsSet].sort((a, b) => a - b);
    const idx = new Map(ts.map((t, i) => [t, i]));
    const n = ts.length;
    const x = ts.map((t) => t / 1000);
    this.stepSec = Math.max(1, (stepMs || 60000) / 1000);
    this.fail = new Array(n).fill(0);
    this.phaseVals = PHASES.map(() => new Array(n).fill(null));
    this.hasHttp = !!http; this.hasTcp = !!tcp;
    const data = [x];
    if (http) {
      const cum = PHASES.map(() => new Array(n).fill(null));
      for (const p of http.points) {
        const i = idx.get(p[0]);
        let run = 0, any = false;
        PHASES.forEach(([, , col], k) => {
          const v = p[col];
          if (isNum(v)) { run += v; any = true; this.phaseVals[k][i] = v; }
          cum[k][i] = any || k > 0 ? (any ? run : null) : null;
        });
        if (!any) PHASES.forEach((_, k) => { cum[k][i] = null; });
        if (isNum(p[7]) && p[7] < 100) this.fail[i] = Math.max(this.fail[i], 1 - p[7] / 100);
      }
      // draw largest (transfer cumulative) first so smaller stacks overlay it
      for (let k = PHASES.length - 1; k >= 0; k--) data.push(cum[k]);
    }
    if (tcp) {
      const line = new Array(n).fill(null);
      for (const p of tcp.points) {
        const i = idx.get(p[0]);
        if (isNum(p[1])) line[i] = p[1];
        if (isNum(p[2]) && p[2] > 0) this.fail[i] = Math.max(this.fail[i], p[2] / 100);
      }
      data.push(line);
    }
    this.setData(data, `ph:${!!http}:${!!tcp}`);
  }

  options(width) {
    const c = getColors();
    const { R } = readGutters(this.el);
    const ms = (v) => (v == null ? '–' : fmtMs(v) + ' ms');
    const series = [{}];
    if (this.hasHttp) {
      for (let k = PHASES.length - 1; k >= 0; k--) {
        const [key, label] = PHASES[k];
        const color = c.ph[key === 'connect' ? 'tcp' : key];
        series.push({
          label: label, scale: 'y', stroke: rgba(color), fill: rgba(color, 0.9), width: 0, points: { show: false },
          paths: window.uPlot.paths.bars({ size: [0.9, 60], align: 0 }),
          value: (u, v, si, i) => ms(i == null ? null : this.phaseVals[k][i]),
        });
      }
    }
    if (this.hasTcp) series.push({ label: 'TCP connect (probe)', scale: 'y', stroke: rgba(c.tcpLine), width: 2, points: { show: true, size: 4, fill: rgba(c.tcpLine) }, spanGaps: false, value: (u, v) => ms(v) });
    const self = this;
    return {
      width, height: this.height,
      padding: [10, R, 0, 0],
      scales: { x: xScale(this.axis), y: { range: (u, mn, mx) => [0, mx == null || !(mx > 0) ? 10 : mx * 1.12] } },
      axes: [
        xAxis(this.axis, c),
        { ...axisBase(c), scale: 'y', size: AX, values: (u, v) => v.map((q) => (q >= 10 ? q.toFixed(0) : q.toFixed(1))) },
      ],
      series,
      legend: { live: true },
      cursor: { x: true, y: false, points: { show: false }, drag: { x: true, y: false, setScale: false } },
      hooks: {
        ...zoomHooks(this.onZoom),
        draw: [(u) => {
          const ctx = u.ctx, b = u.bbox;
          const dpr = window.devicePixelRatio || 1;
          const xs = u.data[0];
          const pxPerSec = b.width / ((self.axis.to - self.axis.from) / 1000);
          const w = Math.max(3 * dpr, Math.min(pxPerSec * self.stepSec, 24 * dpr));
          ctx.save();
          ctx.beginPath(); ctx.rect(b.left, b.top, b.width, b.height); ctx.clip();
          for (let i = 0; i < xs.length; i++) {
            const f = self.fail[i];
            if (!f) continue;
            const cx = u.valToPos(xs[i], 'x', true);
            ctx.fillStyle = rgba(c.fail, 0.12 + 0.25 * f);
            ctx.fillRect(cx - w / 2, b.top, w, b.height);
            ctx.fillStyle = rgba(c.fail);
            ctx.beginPath(); const s = 6 * dpr;
            ctx.moveTo(cx - s, b.top); ctx.lineTo(cx + s, b.top); ctx.lineTo(cx, b.top + s * 1.4); ctx.closePath(); ctx.fill();
          }
          ctx.restore();
        }],
      },
    };
  }
}
