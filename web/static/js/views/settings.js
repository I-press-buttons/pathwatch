// Settings: server-side settings (probe defaults, status thresholds, alert rules, DNS probes),
// theme picker, about/status, DNS probe results.
import { h, clear, fmtDuration, fmtDateTime, DASH } from '../util.js';
import { THEMES, getPref, setPref, onPrefChange } from '../theme.js';
import { getStatus, onStatus, refreshStatus } from '../store.js';
import { getSkew } from '../api.js';
import { panel } from '../ui.js';
import { dnsPanel } from './dns.js';
import { channelsPanel } from './channels.js';
import { settingsEditors } from './settings-editors.js';

const ICMP_TEXT = {
  raw: 'Raw ICMP sockets (CAP_NET_RAW). Full per-hop tracing.',
  dgram: 'Unprivileged ICMP datagram sockets. Full per-hop tracing.',
  unavailable: 'ICMP is unavailable, so hop traces are disabled. Grant NET_RAW (cap_add: [NET_RAW]) or widen net.ipv4.ping_group_range. HTTP/TCP/DNS probes still work.',
};

export function mount(root) {
  const themeP = panel('Theme');
  const aboutP = panel('About this server');
  const dns = dnsPanel({ title: 'DNS probe results', range: '6h' });
  const channels = channelsPanel();
  const editors = settingsEditors({ onSaved: () => { refreshStatus(); dns.load(); } });
  root.append(
    h('div', { class: 'page-head' }, h('h1', null, 'Settings'),
      h('span', { class: 'sub' }, 'Monitoring settings are saved on the server and apply immediately; the theme is saved in this browser.')),
    ...editors.els, channels.el, dns.el, themeP.el, aboutP.el);

  function renderThemes() {
    const pref = getPref();
    const grid = h('div', { class: 'theme-grid', role: 'radiogroup', 'aria-label': 'Theme' });
    for (const t of THEMES) {
      const previewId = t.id === 'auto' ? null : t.id;
      const prev = h('div', { class: 'theme-preview prev', dataset: previewId ? { theme: previewId } : {} },
        h('div', { class: 'pb' }, h('div', { class: 'pt' }, t.id === 'auto' ? 'Follows system' : 'pathwatch'), h('div', { class: 'ps' }, 'latency 12.3 ms'),
          h('div', { class: 'scale' }, [0, 1, 2, 3, 4].map((i) => h('i', { style: { background: `var(--lat-${i})` } }))),
          h('div', { class: 'pills' }, ['ok', 'warn', 'crit', 'info'].map((k) => h('i', { style: { background: `var(--${k})` } })))));
      if (t.id === 'auto') {
        // Auto previews as a split of the light and dark themes.
        clear(prev).append(
          h('div', { style: { display: 'flex', gap: '4px' } },
            h('div', { class: 'theme-preview prev', dataset: { theme: 'light' }, style: { flex: 1, padding: '6px' } }, h('div', { class: 'pb' }, h('div', { class: 'pt' }, 'Light'), h('div', { class: 'scale' }, [0, 2, 4].map((i) => h('i', { style: { background: `var(--lat-${i})` } }))))),
            h('div', { class: 'theme-preview prev', dataset: { theme: 'dark' }, style: { flex: 1, padding: '6px' } }, h('div', { class: 'pb' }, h('div', { class: 'pt' }, 'Dark'), h('div', { class: 'scale' }, [0, 2, 4].map((i) => h('i', { style: { background: `var(--lat-${i})` } })))))));
        prev.style.padding = '4px'; prev.style.background = 'transparent';
      }
      grid.append(h('button', { class: 'theme-card', type: 'button', role: 'radio', 'aria-checked': String(pref === t.id), dataset: { theme: t.id }, onclick: () => setPref(t.id) },
        prev, h('div', { class: 'lbl' }, h('span', null, t.name, h('span', { class: 'desc' }, t.desc)), pref === t.id ? h('span', { class: 'pill ok nodot' }, 'selected') : null)));
    }
    clear(themeP.content).append(grid, h('p', { class: 'muted', style: { margin: '10px 0 0' } }, 'Each theme sets its own UI colours and latency/loss colour scale. Auto follows your operating system light/dark setting.'));
    themeP.showContent();
  }

  function renderAbout(s) {
    if (!s) { aboutP.showLoading(); return; }
    const dl = h('dl', { class: 'kv' });
    const add = (k, v) => dl.append(h('dt', null, k), h('dd', null, v));
    add('Version', s.version);
    add('Uptime', fmtDuration(s.uptime_s * 1000));
    add('ICMP mode', h('span', null, h('span', { class: 'pill ' + (s.icmp_mode === 'unavailable' ? 'crit' : 'ok') }, s.icmp_mode), ' ', h('span', { class: 'muted' }, ICMP_TEXT[s.icmp_mode] || '')));
    add('Local connectivity', s.local_status);
    add('Active alerts', String(s.active_alerts));
    add('Authentication', s.auth_enabled ? 'HTTP Basic auth enabled' : 'Disabled (loopback only)');
    add('Config', s.read_only_config ? 'Read-only (settings cannot be edited on this server)' : 'Config file, with settings edited in the UI layered on top');
    add('Server time', fmtDateTime(s.now));
    const skew = getSkew();
    if (Math.abs(skew) > 5000) add('Clock difference', h('span', { class: 'pill warn' }, `browser clock differs from the server by ${fmtDuration(Math.abs(skew))}`));
    clear(aboutP.content).append(dl);
    aboutP.showContent();
  }

  renderThemes();
  renderAbout(getStatus());
  const offs = [onPrefChange(renderThemes), onStatus(renderAbout)];
  refreshStatus();
  editors.load();
  channels.load();
  dns.load();
  const t = setInterval(() => dns.load(), 15000);
  return { destroy() { offs.forEach((f) => f()); clearInterval(t); } };
}
