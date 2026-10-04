// Theme handling. A theme is a block of CSS custom properties in css/themes.css.
// "auto" resolves to light/dark through prefers-color-scheme; data-theme always holds the resolved id.
import { parseColor, lsGet, lsSet } from './util.js';

export const THEMES = [
  { id: 'auto', name: 'Auto', desc: 'Follows your system light/dark setting' },
  { id: 'light', name: 'Light', desc: 'Clean light UI, blue latency scale' },
  { id: 'dark', name: 'Dark', desc: 'Neutral dark UI, blue latency scale' },
  { id: 'midnight', name: 'Midnight', desc: 'Near-black navy, teal scale' },
  { id: 'nord', name: 'Nord', desc: 'Arctic blue-grey palette' },
  { id: 'solarized-light', name: 'Solarized Light', desc: 'Warm paper tones' },
  { id: 'solarized-dark', name: 'Solarized Dark', desc: 'Deep teal, low glare' },
  { id: 'high-contrast', name: 'High Contrast', desc: 'Maximum contrast, black and white' },
  { id: 'classic', name: 'Classic', desc: 'Green, yellow, red scale on a light UI' },
];
const KEY = 'pathwatch.theme';
const listeners = new Set();
let colorCache = null;
const mq = window.matchMedia ? window.matchMedia('(prefers-color-scheme: dark)') : null;

export function getPref() {
  const v = lsGet(KEY, 'auto');
  return THEMES.some((t) => t.id === v) ? v : 'auto';
}
export function resolved(pref = getPref()) {
  if (pref !== 'auto') return pref;
  return mq && mq.matches ? 'dark' : 'light';
}
export function applyTheme(pref = getPref()) {
  const root = document.documentElement;
  const id = resolved(pref);
  const changed = root.getAttribute('data-theme') !== id;
  root.setAttribute('data-theme', id);
  root.setAttribute('data-theme-pref', pref);
  colorCache = null;
  if (changed) for (const fn of listeners) { try { fn(id); } catch (e) { console.error(e); } }
}
export function setPref(pref) {
  lsSet(KEY, pref);
  applyTheme(pref);
  for (const fn of prefListeners) fn(pref);
}
const prefListeners = new Set();
export function onPrefChange(fn) { prefListeners.add(fn); return () => prefListeners.delete(fn); }
/** Subscribe to resolved-theme changes (used by canvas/uPlot code to redraw). */
export function onThemeChange(fn) { listeners.add(fn); return () => listeners.delete(fn); }

export function initTheme() {
  applyTheme();
  if (mq) {
    const onChange = () => { if (getPref() === 'auto') applyTheme('auto'); };
    if (mq.addEventListener) mq.addEventListener('change', onChange); else if (mq.addListener) mq.addListener(onChange);
  }
}

/** Theme colours parsed to [r,g,b,a]; cached until the theme changes. */
export function getColors() {
  if (colorCache) return colorCache;
  const cs = getComputedStyle(document.documentElement);
  const v = (name) => parseColor(cs.getPropertyValue(name));
  const raw = (name) => cs.getPropertyValue(name).trim();
  colorCache = {
    id: document.documentElement.getAttribute('data-theme'),
    raw,
    bg: v('--bg'), surface: v('--surface'), surface2: v('--surface-2'), border: v('--border'), borderStrong: v('--border-strong'),
    text: v('--text'), muted: v('--text-muted'), faint: v('--text-faint'), accent: v('--accent'),
    ok: v('--ok'), warn: v('--warn'), crit: v('--crit'), info: v('--info'),
    lat: [0, 1, 2, 3, 4].map((i) => v('--lat-' + i)),
    loss0: v('--loss-0'), loss1: v('--loss-1'),
    gapHatch: v('--gap-hatch'), gapBg: v('--gap-bg'),
    grid: v('--chart-grid'), axis: v('--chart-axis'),
    line: v('--series-line'), band: v('--series-band'), lossBar: v('--series-loss'),
    ph: { dns: v('--ph-dns'), tcp: v('--ph-tcp'), tls: v('--ph-tls'), ttfb: v('--ph-ttfb'), transfer: v('--ph-transfer') },
    tcpLine: v('--tcp-line'), fail: v('--fail'),
    evRoute: v('--ev-route'), evAlert: v('--ev-alert'), evRl: v('--ev-rl'),
    font: cs.getPropertyValue('--font').trim() || 'system-ui, sans-serif',
  };
  return colorCache;
}
