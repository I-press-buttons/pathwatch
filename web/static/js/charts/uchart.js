// Lifecycle wrapper around uPlot: lazy creation (needs a visible width), resize, theme restyle, destroy.
import { h } from '../util.js';
import { onThemeChange } from '../theme.js';
import { hoverBus } from './common.js';

export class UChart {
  /** subclass implements options(width, colors) -> uPlot opts and data array */
  constructor(host, { axis, onZoom, height = 220, id }) {
    this.axis = axis; this.onZoom = onZoom; this.height = height; this.id = id || 'u' + Math.random().toString(36).slice(2);
    this.el = h('div', { class: 'uplot-host' });
    host.appendChild(this.el);
    this.u = null; this.data = null; this.sig = null; this.offBus = null;
    this.ro = new ResizeObserver(() => this.onResize());
    this.ro.observe(this.el);
    this.offTheme = onThemeChange(() => this.rebuild());
  }
  get width() { return Math.floor(this.el.clientWidth); }
  onResize() {
    const w = this.width;
    if (w < 40) return;
    if (!this.u) { this.rebuild(); return; }
    if (Math.abs(w - this.u.width) > 1) this.u.setSize({ width: w, height: this.height });
  }
  /** data: aligned arrays; sig: string describing series structure (rebuild when it changes) */
  setData(data, sig) {
    this.data = data;
    if (this.u && sig === this.sig) { this.u.setData(data, true); return; }
    this.sig = sig;
    this.rebuild();
  }
  /** Re-render with the current axis range (zoom / time passing) */
  redraw() { if (this.u && this.data) this.u.setData(this.data, true); }
  rebuild() {
    this.destroyPlot();
    if (!this.data || this.width < 40) return;
    const opts = this.options(this.width);
    const hover = { hook: null };
    // hover sync
    const id = this.id;
    opts.hooks = opts.hooks || {};
    opts.hooks.setCursor = (opts.hooks.setCursor || []).concat([(u) => {
      const l = u.cursor.left;
      if (l == null || l < 0) hoverBus.emit(null, id); else hoverBus.emit(u.posToVal(l, 'x') * 1000, id);
    }]);
    this.u = new window.uPlot(opts, this.data, this.el);
    this.offBus = hoverBus.on((ts, src) => {
      const u = this.u;
      if (!u || src === id) return;
      if (ts == null) { u.setCursor({ left: -10, top: -10 }, false); return; }
      const left = u.valToPos(ts / 1000, 'x');
      if (!(left >= 0) || left > u.bbox.width / (window.devicePixelRatio || 1)) { u.setCursor({ left: -10, top: -10 }, false); return; }
      u.setCursor({ left, top: 10 }, false);
    });
  }
  destroyPlot() {
    if (this.offBus) { this.offBus(); this.offBus = null; }
    if (this.u) { this.u.destroy(); this.u = null; }
  }
  destroy() { this.ro.disconnect(); this.offTheme(); this.destroyPlot(); this.el.remove(); }
}
