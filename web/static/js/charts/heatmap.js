// Canvas path-timeline heatmap: rows = TTL, columns = time buckets.
import { h, isNum, fmtMs, fmtPct, fmtDateTime, fmtTime, fmtDuration, rgba, gradient, lerpColor, percentile, clamp } from '../util.js';
import { getColors } from '../theme.js';
import { hoverBus, readGutters, niceTicks, tickLabel } from './common.js';

const STRIP = 28;   // event marker strip above the rows
const AXIS_H = 24;  // time axis below

export class Heatmap {
  /** opts: { onSelectTtl(ttl), onZoom(from,to) } */
  constructor(host, opts) {
    this.host = host; this.opts = opts;
    this.tl = null; this.axis = { from: 0, to: 1 };
    this.selectedTtl = null; this.scaleSetting = 'auto';
    this.hoverTs = null; this.hoverRow = -1;
    this.drag = null;
    this.raf = 0; this.pm = null; this.ovDirty = false; // pointer moves and bus updates are applied once per animation frame
    this.tipKey = null;                                 // what the tooltip currently shows (row:bucket or event)
    this.evHits = [];
    this.dpr = window.devicePixelRatio || 1;
    this.canvas = h('canvas', { role: 'img', 'aria-label': 'Path timeline heatmap' });
    this.overlay = h('canvas', { style: { position: 'absolute', left: 0, top: 0, touchAction: 'pan-y', cursor: 'crosshair' } });
    this.tt = h('div', { class: 'tt', hidden: true });
    this.wrap = h('div', { class: 'chart-wrap' }, this.canvas, this.overlay, this.tt);
    host.appendChild(this.wrap);
    this.ro = new ResizeObserver(() => this.layout());
    this.ro.observe(this.wrap);
    this.offBus = hoverBus.on((ts, src) => { if (src === 'heat') return; this.hoverTs = ts; this.ovDirty = true; this.schedule(); });
    const o = this.overlay;
    o.addEventListener('pointerdown', (e) => this.onDown(e));
    o.addEventListener('pointermove', (e) => this.onMove(e));
    o.addEventListener('pointerup', (e) => this.onUp(e));
    o.addEventListener('pointercancel', () => { this.drag = null; this.drawOverlay(); });
    o.addEventListener('pointerleave', () => this.onLeave());
    o.addEventListener('dblclick', () => { /* reserved */ });
  }

  destroy() { this.cancelFrame(); this.ro.disconnect(); this.offBus(); this.wrap.remove(); }

  setData(tl, axis, { selectedTtl = null } = {}) {
    this.tl = tl; this.axis = axis; this.selectedTtl = selectedTtl;
    this.tipKey = null; // new data: the tooltip is rebuilt on the next pointer move
    this.derive();
    this.layout();
  }
  setSelected(ttl) { this.selectedTtl = ttl; this.draw(); }
  setScale(v) { this.scaleSetting = v; this.draw(); }
  setAxis(axis) { this.axis = axis; this.draw(); }

  /** per-row averages and the auto (p99) colour scale */
  derive() {
    const tl = this.tl;
    this.rowAvg = []; this.autoMax = 1;
    if (!tl) return;
    const vals = [];
    (tl.rtt || []).forEach((row, i) => {
      let s = 0, n = 0;
      const cls = tl.labels && tl.labels[i] ? tl.labels[i].classification : 'ok';
      for (const v of row) if (isNum(v)) { s += v; n++; if (cls !== 'rate_limited' && cls !== 'no_reply') vals.push(v); }
      this.rowAvg[i] = n ? s / n : null;
    });
    vals.sort((a, b) => a - b);
    const p99 = percentile(vals, 0.99);
    this.autoMax = Math.max(5, p99 || 5);
  }
  scaleMax() { return this.scaleSetting === 'auto' ? this.autoMax : Number(this.scaleSetting); }

  metrics() {
    const rows = this.tl ? (this.tl.ttls || []).length : 0;
    const { L, R } = readGutters(this.host);
    const rowH = rows <= 16 ? 20 : rows <= 24 ? 16 : 13;
    const W = this.wrap.clientWidth;
    return { rows, L, R, rowH, W, top: STRIP, H: STRIP + Math.max(rows, 1) * rowH + AXIS_H, x0: L, pw: Math.max(10, W - L - R) };
  }

  layout() {
    const m = this.m = this.metrics();
    if (m.W < 20) return;
    this.dpr = window.devicePixelRatio || 1;
    for (const cv of [this.canvas, this.overlay]) {
      cv.width = Math.round(m.W * this.dpr); cv.height = Math.round(m.H * this.dpr);
      cv.style.width = m.W + 'px'; cv.style.height = m.H + 'px';
    }
    this.draw();
  }

  xOf(ts) { const m = this.m; return m.x0 + ((ts - this.axis.from) / (this.axis.to - this.axis.from)) * m.pw; }
  tsOf(x) { const m = this.m; return this.axis.from + ((x - m.x0) / m.pw) * (this.axis.to - this.axis.from); }

  draw() {
    const m = this.m;
    if (!m || m.W < 20) return;
    const tl = this.tl;
    const c = getColors();
    const ctx = this.canvas.getContext('2d');
    const dpr = this.dpr;
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, m.W, m.H);
    ctx.font = `11.5px ${c.font}`;
    ctx.textBaseline = 'middle';
    const plotY0 = m.top, plotH = m.rows * m.rowH;
    // plot background (no data)
    ctx.fillStyle = rgba(c.surface2);
    ctx.fillRect(m.x0, plotY0, m.pw, plotH);
    this.evHits = [];
    if (!tl || !m.rows) { this.drawAxis(ctx, c); return; }

    const x0 = m.x0, x1 = m.x0 + m.pw;
    // gaps: hatched "no data" columns
    const hatch = this.hatchPattern(ctx, c);
    for (const g of tl.gaps || []) {
      const a = clamp(this.xOf(g[0]), x0, x1), b = clamp(this.xOf(g[1]), x0, x1);
      if (b - a <= 0) continue;
      ctx.fillStyle = rgba(c.gapBg); ctx.fillRect(a, plotY0, b - a, plotH);
      if (hatch) { ctx.fillStyle = hatch; ctx.fillRect(a, plotY0, b - a, plotH); }
    }
    // cells
    const lut = new Array(256);
    for (let i = 0; i < 256; i++) lut[i] = rgba(gradient(c.lat, i / 255));
    const scale = this.scaleMax();
    const step = tl.step_ms, t0 = tl.from;
    const k = m.pw / (this.axis.to - this.axis.from);
    const snap = (v) => Math.round(v * dpr) / dpr;
    const nb = tl.rtt[0] ? tl.rtt[0].length : 0;
    for (let i = 0; i < m.rows; i++) {
      const rtt = tl.rtt[i] || [], loss = tl.loss[i] || [];
      const cls = tl.labels && tl.labels[i] ? tl.labels[i].classification : 'ok';
      const y = plotY0 + i * m.rowH, ch = m.rowH - 1;
      const dim = cls === 'rate_limited' ? 0.5 : 1;
      for (let j = 0; j < nb; j++) {
        const ts = t0 + j * step;
        let xa = x0 + (ts - this.axis.from) * k, xb = x0 + (ts + step - this.axis.from) * k;
        if (xb <= x0 || xa >= x1) continue;
        xa = snap(Math.max(xa, x0)); xb = snap(Math.min(xb, x1));
        const w = Math.max(xb - xa, 1 / dpr);
        const r = rtt[j], l = loss[j];
        if (!isNum(r) && !isNum(l)) continue; // no probes sent: leave empty (gap)
        if (cls === 'no_reply') {
          ctx.globalAlpha = 0.5; ctx.fillStyle = rgba(c.faint, 0.35); ctx.fillRect(xa, y + ch / 2 - 1, w, 2); ctx.globalAlpha = 1;
          continue;
        }
        ctx.globalAlpha = dim;
        if (!isNum(r)) {
          ctx.fillStyle = rgba(lerpColor(c.loss0, c.loss1, clamp((l || 100) / 60, 0.3, 1)));
        } else {
          ctx.fillStyle = lut[clamp(Math.round((r / scale) * 255), 0, 255)];
        }
        ctx.fillRect(xa, y, w, ch);
        if (isNum(r) && isNum(l) && l > 0) {
          ctx.fillStyle = rgba(lerpColor(c.loss0, c.loss1, clamp(l / 60, 0, 1)), clamp(0.3 + (l / 100) * 0.9, 0.3, 0.95));
          ctx.fillRect(xa, y, w, ch);
        }
        ctx.globalAlpha = 1;
      }
    }
    ctx.globalAlpha = 1;

    // route-change lines through the grid
    for (const ev of tl.events || []) {
      if (ev.kind !== 'route_change') continue;
      const x = this.xOf(ev.from);
      if (x < x0 || x > x1) continue;
      ctx.strokeStyle = rgba(c.evRoute, 0.85); ctx.lineWidth = 1; ctx.setLineDash([3, 3]);
      ctx.beginPath(); ctx.moveTo(Math.round(x) + 0.5, plotY0); ctx.lineTo(Math.round(x) + 0.5, plotY0 + plotH); ctx.stroke(); ctx.setLineDash([]);
    }
    // selected row outline
    const si = this.selectedIndex();
    if (si >= 0) {
      ctx.strokeStyle = rgba(c.accent); ctx.lineWidth = 2;
      ctx.strokeRect(x0 - 0.5, plotY0 + si * m.rowH + 0.5, m.pw + 1, m.rowH - 2);
    }
    this.drawLabels(ctx, c, si);
    this.drawEvents(ctx, c);
    this.drawAxis(ctx, c);
    this.drawOverlay();
  }

  selectedIndex() {
    if (!this.tl) return -1;
    const ttls = this.tl.ttls || [];
    if (this.selectedTtl == null) {
      // destination = last responding row
      const labels = this.tl.labels || [];
      for (let i = labels.length - 1; i >= 0; i--) if (labels[i].classification === 'destination') return i;
      return -1;
    }
    return ttls.indexOf(this.selectedTtl);
  }

  hatchPattern(ctx, c) {
    const p = document.createElement('canvas'); p.width = p.height = 8 * this.dpr;
    const pc = p.getContext('2d');
    pc.scale(this.dpr, this.dpr);
    pc.strokeStyle = rgba(c.gapHatch, 0.75); pc.lineWidth = 1;
    pc.beginPath(); pc.moveTo(-1, 9); pc.lineTo(9, -1); pc.moveTo(-1, 5); pc.lineTo(5, -1); pc.moveTo(3, 9); pc.lineTo(9, 3); pc.stroke();
    const pat = ctx.createPattern(p, 'repeat');
    if (pat && pat.setTransform && typeof DOMMatrix !== 'undefined') pat.setTransform(new DOMMatrix().scale(1 / this.dpr, 1 / this.dpr));
    return pat;
  }

  drawLabels(ctx, c, si) {
    const m = this.m, tl = this.tl;
    const L = m.L;
    const showAvg = L >= 190, showHost = L >= 100;
    const hostMax = L - 34 - (showAvg ? 52 : 6) - 6;
    ctx.save();
    ctx.beginPath(); ctx.rect(0, m.top, L - 4, m.rows * m.rowH); ctx.clip();
    for (let i = 0; i < m.rows; i++) {
      const lab = tl.labels && tl.labels[i] ? tl.labels[i] : {};
      const cls = lab.classification;
      const yc = m.top + i * m.rowH + m.rowH / 2;
      const faint = cls === 'rate_limited' || cls === 'no_reply';
      ctx.fillStyle = rgba(faint ? c.faint : c.muted);
      ctx.font = `600 11.5px ${c.font}`;
      ctx.textAlign = 'right';
      ctx.fillText(String(tl.ttls[i]), 24, yc);
      ctx.textAlign = 'left';
      ctx.font = `11.5px ${c.font}`;
      ctx.fillStyle = rgba(i === si ? c.text : faint ? c.faint : c.text);
      let txt = cls === 'no_reply' ? '* * *' : (lab.hostname || lab.address || '* * *');
      if (cls === 'destination') ctx.font = `600 11.5px ${c.font}`;
      let tagW = 0;
      if (cls === 'rate_limited' && hostMax > 110) tagW = 22;
      if (showHost) ctx.fillText(fit(ctx, txt, hostMax - tagW), 32, yc);
      if (tagW && showHost) {
        const tw = Math.min(hostMax - tagW, ctx.measureText(fit(ctx, txt, hostMax - tagW)).width);
        ctx.font = `700 9.5px ${c.font}`; ctx.fillStyle = rgba(c.warn);
        ctx.fillText('RL', 32 + tw + 5, yc);
      }
      if (showAvg) {
        ctx.font = `11.5px ${c.font}`; ctx.fillStyle = rgba(faint ? c.faint : c.muted);
        ctx.textAlign = 'right';
        const a = this.rowAvg[i];
        ctx.fillText(isNum(a) ? fmtMs(a) + ' ms' : '', L - 8, yc);
      }
    }
    ctx.restore();
    ctx.textAlign = 'left';
  }

  drawEvents(ctx, c) {
    const m = this.m, tl = this.tl;
    const x0 = m.x0, x1 = m.x0 + m.pw;
    ctx.fillStyle = rgba(c.muted); ctx.font = `10.5px ${c.font}`; ctx.textAlign = 'left'; ctx.textBaseline = 'middle';
    if (m.L >= 190) ctx.fillText('Events', 32, 12);
    ctx.strokeStyle = rgba(c.border); ctx.lineWidth = 1;
    ctx.beginPath(); ctx.moveTo(x0, STRIP - 3.5); ctx.lineTo(x1, STRIP - 3.5); ctx.stroke();
    for (const ev of tl.events || []) {
      const xa = this.xOf(ev.from);
      const hasEnd = isNum(ev.to) && ev.to > ev.from;
      const xb = hasEnd ? this.xOf(ev.to) : xa;
      if (xb < x0 || xa > x1) continue;
      const x = clamp(xa, x0 + 4, x1 - 4);
      let y = 14, r = 5;
      if (ev.kind === 'alert') {
        y = 9;
        if (hasEnd) { ctx.fillStyle = rgba(c.evAlert, 0.4); ctx.fillRect(clamp(xa, x0, x1), y - 3, Math.max(2, clamp(xb, x0, x1) - clamp(xa, x0, x1)), 6); }
        ctx.fillStyle = rgba(c.evAlert); ctx.beginPath(); ctx.arc(x, y, 4.5, 0, Math.PI * 2); ctx.fill();
        ctx.fillStyle = '#fff'; ctx.fillRect(x - 0.75, y - 2.5, 1.5, 3.5); ctx.fillRect(x - 0.75, y + 1.4, 1.5, 1.4);
      } else if (ev.kind === 'route_change') {
        y = 17; ctx.fillStyle = rgba(c.evRoute);
        ctx.beginPath(); ctx.moveTo(x, y - 6); ctx.lineTo(x + 5, y); ctx.lineTo(x, y + 6); ctx.lineTo(x - 5, y); ctx.closePath(); ctx.fill();
      } else if (ev.kind === 'rate_limited') {
        y = 17; r = 4; ctx.strokeStyle = rgba(c.evRl); ctx.lineWidth = 1.5;
        ctx.strokeRect(x - 4, y - 4, 8, 8);
      } else {
        y = 17; ctx.fillStyle = rgba(c.faint); ctx.beginPath(); ctx.arc(x, y, 3.5, 0, Math.PI * 2); ctx.fill();
      }
      this.evHits.push({ x, y, r: 8, ev });
    }
  }

  drawAxis(ctx, c) {
    const m = this.m;
    const y = m.top + Math.max(m.rows, 1) * m.rowH;
    ctx.strokeStyle = rgba(c.border); ctx.lineWidth = 1;
    ctx.beginPath(); ctx.moveTo(m.x0, y + 0.5); ctx.lineTo(m.x0 + m.pw, y + 0.5); ctx.stroke();
    const { ticks, step, span } = niceTicks(this.axis.from, this.axis.to, Math.floor(m.pw / 90));
    ctx.fillStyle = rgba(c.axis); ctx.font = `11px ${c.font}`; ctx.textAlign = 'center'; ctx.textBaseline = 'top';
    for (const t of ticks) {
      const x = Math.round(this.xOf(t)) + 0.5;
      ctx.strokeStyle = rgba(c.border); ctx.beginPath(); ctx.moveTo(x, y); ctx.lineTo(x, y + 4); ctx.stroke();
      ctx.fillText(tickLabel(t, step, span), x, y + 7);
    }
    ctx.textAlign = 'left'; ctx.textBaseline = 'middle';
  }

  // ---------- overlay: crosshair, selection ----------
  drawOverlay() {
    this.ovDirty = false;
    const m = this.m;
    if (!m || m.W < 20) return;
    const c = getColors();
    const ctx = this.overlay.getContext('2d');
    ctx.setTransform(this.dpr, 0, 0, this.dpr, 0, 0);
    ctx.clearRect(0, 0, m.W, m.H);
    const yEnd = m.top + m.rows * m.rowH;
    if (this.hoverTs != null) {
      const x = this.xOf(this.hoverTs);
      if (x >= m.x0 && x <= m.x0 + m.pw) {
        ctx.strokeStyle = rgba(c.text, 0.6); ctx.lineWidth = 1;
        ctx.beginPath(); ctx.moveTo(Math.round(x) + 0.5, m.top - 4); ctx.lineTo(Math.round(x) + 0.5, yEnd); ctx.stroke();
      }
    }
    if (this.hoverRow >= 0 && this.hoverRow < m.rows) {
      ctx.fillStyle = rgba(c.text, 0.08);
      ctx.fillRect(0, m.top + this.hoverRow * m.rowH, m.W - m.R + 2, m.rowH);
    }
    if (this.drag && this.drag.active) {
      const a = Math.min(this.drag.x0, this.drag.x), b = Math.max(this.drag.x0, this.drag.x);
      ctx.fillStyle = rgba(c.accent, 0.22); ctx.strokeStyle = rgba(c.accent, 0.8); ctx.lineWidth = 1;
      ctx.fillRect(a, m.top, b - a, m.rows * m.rowH); ctx.strokeRect(a + 0.5, m.top + 0.5, b - a, m.rows * m.rowH - 1);
    }
  }

  pos(e) { return this.posAt(e.clientX, e.clientY); }
  posAt(cx, cy) { const r = this.overlay.getBoundingClientRect(); return { x: cx - r.left, y: cy - r.top }; }
  rowAt(y) { const m = this.m; const i = Math.floor((y - m.top) / m.rowH); return i >= 0 && i < m.rows ? i : -1; }

  // ---------- frame coalescing ----------
  schedule() { if (!this.raf) this.raf = requestAnimationFrame(() => this.frame()); }
  cancelFrame() { if (this.raf) cancelAnimationFrame(this.raf); this.raf = 0; this.pm = null; this.ovDirty = false; }
  /** run the pending frame now (before pointer down/up read the drag state) */
  flushMove() { if (!this.raf) return; cancelAnimationFrame(this.raf); this.frame(); }
  frame() {
    this.raf = 0;
    const p = this.pm; this.pm = null;
    if (p && this.tl && this.m) { const { x, y } = this.posAt(p.cx, p.cy); this.move(x, y); }
    if (this.ovDirty) this.drawOverlay();
  }

  onDown(e) {
    if (e.button !== 0 || !this.tl) return;
    this.flushMove();
    const { x, y } = this.pos(e);
    this.drag = { x0: x, y0: y, x, active: false, inPlot: x >= this.m.x0 && x <= this.m.x0 + this.m.pw && y >= this.m.top };
    try { this.overlay.setPointerCapture(e.pointerId); } catch (err) { /* ignore */ }
  }
  onMove(e) {
    if (!this.tl || !this.m) return;
    this.pm = { cx: e.clientX, cy: e.clientY }; // only the latest position matters
    this.schedule();
  }
  move(x, y) {
    if (this.drag) {
      this.drag.x = clamp(x, this.m.x0, this.m.x0 + this.m.pw);
      if (this.drag.inPlot && Math.abs(x - this.drag.x0) > 5) this.drag.active = true;
      if (this.drag.active) { this.hideTip(); this.drawOverlay(); return; }
    }
    this.hover(x, y);
  }
  onLeave() {
    if (this.drag && this.drag.active) return;
    this.cancelFrame();
    this.hoverTs = null; this.hoverRow = -1; this.hideTip(); this.drawOverlay(); hoverBus.emit(null, 'heat');
  }
  onUp(e) {
    this.flushMove();
    const d = this.drag; this.drag = null;
    try { this.overlay.releasePointerCapture(e.pointerId); } catch (err) { /* ignore */ }
    if (!d) return;
    if (d.active) {
      const a = this.tsOf(Math.min(d.x0, d.x)), b = this.tsOf(Math.max(d.x0, d.x));
      this.drawOverlay();
      if (b - a >= 1000 && this.opts.onZoom) this.opts.onZoom(Math.round(a), Math.round(b));
      return;
    }
    const { x, y } = this.pos(e);
    if (Math.abs(x - d.x0) < 5 && Math.abs(y - d.y0) < 5) {
      const i = this.rowAt(y);
      if (i >= 0 && this.opts.onSelectTtl) {
        const lab = this.tl.labels && this.tl.labels[i];
        if (lab && lab.classification !== 'no_reply') this.opts.onSelectTtl(this.tl.ttls[i], lab.classification === 'destination');
      }
    }
  }

  hover(x, y) {
    const m = this.m, tl = this.tl;
    const inPlot = x >= m.x0 && x <= m.x0 + m.pw;
    this.hoverRow = this.rowAt(y);
    this.hoverTs = inPlot ? this.tsOf(x) : null;
    hoverBus.emit(this.hoverTs, 'heat');
    this.drawOverlay();
    // event marker tooltip
    if (y < m.top && inPlot) {
      let best = null, bd = 1e9;
      for (const hit of this.evHits) { const d = Math.hypot(hit.x - x, hit.y - y); if (d < hit.r && d < bd) { best = hit; bd = d; } }
      if (best) { this.showTip(x, y, best.ev, () => this.eventTip(best.ev)); return; }
      this.hideTip(); return;
    }
    if (this.hoverRow < 0) { this.hideTip(); return; }
    const i = this.hoverRow;
    // the tooltip only depends on (row, bucket): -1 = no bucket under the pointer
    let j = -1;
    if (inPlot) {
      const jj = Math.floor((this.hoverTs - tl.from) / tl.step_ms);
      if (jj >= 0 && jj < (tl.rtt[i] ? tl.rtt[i].length : 0)) j = jj;
    }
    this.showTip(x, y, i + ':' + j, () => this.cellTip(i, j));
  }

  cellTip(i, j) {
    const tl = this.tl;
    const lab = (tl.labels && tl.labels[i]) || {};
    const rows = [];
    rows.push(h('div', null, h('b', null, 'Hop ' + tl.ttls[i]), ' ', lab.hostname || lab.address || '* * *'));
    if (lab.hostname && lab.address) rows.push(h('div', { class: 'k' }, lab.address));
    if (lab.classification === 'rate_limited') rows.push(h('div', { class: 'k' }, 'ICMP rate-limited'));
    if (j >= 0) {
      const r = tl.rtt[i][j], l = tl.loss[i][j];
      const tsj = tl.from + j * tl.step_ms;
      rows.push(h('div', { class: 'k' }, fmtDateTime(tsj) + (tl.step_ms >= 60000 ? ' (' + fmtDuration(tl.step_ms) + ' bucket)' : '')));
      if (!isNum(r) && !isNum(l)) rows.push(h('div', null, 'No data (monitor gap)'));
      else rows.push(h('div', null, h('span', { class: 'k' }, 'avg '), isNum(r) ? fmtMs(r) + ' ms' : 'no reply', h('span', { class: 'k' }, '  loss '), isNum(l) ? fmtPct(l) : '–'));
    } else {
      rows.push(h('div', { class: 'k' }, 'avg ' + (isNum(this.rowAvg[i]) ? fmtMs(this.rowAvg[i]) + ' ms' : '–') + ' over range'));
    }
    return rows;
  }

  eventTip(ev) {
    const names = { route_change: 'Route change', alert: 'Alert', rate_limited: 'ICMP rate-limited', icmp_unresponsive: 'Destination does not answer ping', gap: 'Monitor gap', local_outage: 'Local outage' };
    const rows = [h('div', null, h('b', null, names[ev.kind] || ev.kind), ev.ttl != null ? ' (hop ' + ev.ttl + ')' : '')];
    rows.push(h('div', { class: 'k' }, fmtDateTime(ev.from) + (isNum(ev.to) ? ' → ' + fmtTime(ev.to) : ' → ongoing')));
    const d = ev.details || {};
    if (d.rule) rows.push(h('div', null, 'rule: ' + d.rule));
    for (const k of ['from_address', 'to_address', 'old', 'new']) if (d[k]) rows.push(h('div', { class: 'k' }, k.replace('_', ' ') + ': ' + d[k]));
    return rows;
  }

  hideTip() { this.tt.hidden = true; this.tipKey = null; }
  /** key identifies the hovered target; the content is only rebuilt when it changes, the position follows every frame */
  showTip(x, y, key, build) {
    const tt = this.tt;
    if (key !== this.tipKey || tt.hidden) { tt.replaceChildren(...build()); tt.hidden = false; this.tipKey = key; }
    const w = tt.offsetWidth, hh = tt.offsetHeight;
    let left = x + 14, top = y + 14;
    if (left + w > this.m.W - 4) left = x - w - 14;
    if (left < 4) left = 4;
    if (top + hh > this.m.H) top = Math.max(0, y - hh - 10);
    tt.style.left = left + 'px'; tt.style.top = top + 'px';
  }
}

function fit(ctx, text, maxW) {
  if (maxW <= 10) return '';
  if (ctx.measureText(text).width <= maxW) return text;
  let lo = 0, hi = text.length;
  while (lo < hi) { const mid = (lo + hi + 1) >> 1; if (ctx.measureText(text.slice(0, mid) + '…').width <= maxW) lo = mid; else hi = mid - 1; }
  return text.slice(0, lo) + '…';
}
