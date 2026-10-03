// Selected-hop latency graph: avg line, min/max band, loss % bars on a second axis.
import { isNum, fmtMs, fmtPct, rgba } from '../util.js';
import { getColors } from '../theme.js';
import { UChart } from './uchart.js';
import { AX, axisBase, xAxis, xScale, zoomHooks, readGutters } from './common.js';

export class LatencyChart extends UChart {
  constructor(host, o) { super(host, { ...o, height: 230, id: 'latency' }); }

  /** points: [[ts, avg, min, max, loss]] */
  load(points) {
    const n = points.length;
    const x = new Array(n), avg = new Array(n), min = new Array(n), max = new Array(n), loss = new Array(n);
    for (let i = 0; i < n; i++) {
      const p = points[i];
      x[i] = p[0] / 1000;
      avg[i] = isNum(p[1]) ? p[1] : null; min[i] = isNum(p[2]) ? p[2] : null; max[i] = isNum(p[3]) ? p[3] : null;
      loss[i] = isNum(p[4]) ? p[4] : null;
    }
    this.setData([x, loss, avg, min, max], 'latency');
  }

  options(width) {
    const c = getColors();
    const { R } = readGutters(this.el);
    const ms = (u, v) => (v == null ? '–' : fmtMs(v) + ' ms');
    const axisMs = (u, vals) => vals.map((v) => (v >= 100 ? v.toFixed(0) : v >= 10 ? v.toFixed(0) : v.toFixed(1)));
    return {
      width, height: this.height,
      padding: [10, 0, 0, 0],
      scales: {
        x: xScale(this.axis),
        y: { range: (u, mn, mx) => [0, mx == null || !(mx > 0) ? 10 : mx * 1.12] },
        loss: { range: (u, mn, mx) => [0, Math.max(10, (mx || 0) * 1.2)] },
      },
      axes: [
        xAxis(this.axis, c),
        { ...axisBase(c), scale: 'y', size: AX, values: axisMs },
        { ...axisBase(c), scale: 'loss', side: 1, size: R, grid: { show: false }, values: (u, v) => v.map((q) => q.toFixed(0) + '%') },
      ],
      series: [
        {},
        { label: 'Loss %', scale: 'loss', stroke: rgba(c.lossBar), fill: rgba(c.lossBar, 0.55), width: 1, points: { show: false }, paths: window.uPlot.paths.bars({ size: [0.8, 14], align: 0 }), value: (u, v) => (v == null ? '–' : fmtPct(v)) },
        { label: 'Avg', scale: 'y', stroke: rgba(c.line), width: 1.6, points: { show: false }, spanGaps: false, value: ms },
        { label: 'Min', scale: 'y', stroke: rgba(c.band, 0.45), width: 1, points: { show: false }, value: ms },
        { label: 'Max', scale: 'y', stroke: rgba(c.band, 0.45), width: 1, points: { show: false }, value: ms },
      ],
      bands: [{ series: [4, 3], fill: rgba(c.band, 0.16) }],
      legend: { live: true },
      cursor: { x: true, y: false, points: { show: false }, drag: { x: true, y: false, setScale: false } },
      hooks: zoomHooks(this.onZoom),
    };
  }
}
