// Boot + hash router.
import { h, clear, parseHash, buildHash } from './util.js';
import { THEMES, initTheme, getPref, setPref, onPrefChange } from './theme.js';
import { onHealth, startStream } from './api.js';
import { onStatus, startStatusPolling } from './store.js';
import * as overview from './views/overview.js';
import * as target from './views/target.js';
import * as alerts from './views/alerts.js';
import * as settings from './views/settings.js';

initTheme();

const viewEl = document.getElementById('view');
let current = null; // {name, key, instance}

function matchRoute(parts) {
  if (parts.length === 0) return { name: 'overview', mod: overview, params: {}, key: 'overview' };
  if (parts[0] === 'target' && parts[1]) return { name: 'target', mod: target, params: { id: parts[1] }, key: 'target/' + parts[1] };
  if (parts[0] === 'alerts') return { name: 'alerts', mod: alerts, params: {}, key: 'alerts' };
  if (parts[0] === 'settings') return { name: 'settings', mod: settings, params: {}, key: 'settings' };
  return null;
}

export function navigate(path, query, { replace = false } = {}) {
  const hash = buildHash(path, query);
  if (replace) history.replaceState(null, '', hash); else if (location.hash !== hash) location.hash = hash;
  if (replace) route(false);
}

function route(scroll = true) {
  const { parts, query } = parseHash();
  const r = matchRoute(parts);
  document.querySelectorAll('#nav a').forEach((a) => a.classList.toggle('active', !!r && a.dataset.nav === (r.name === 'target' ? 'overview' : r.name)));
  const ctx = { params: r ? r.params : {}, query, navigate };
  if (r && current && current.key === r.key && current.instance.update) {
    current.instance.update(ctx);
    return;
  }
  if (current) { try { current.instance.destroy && current.instance.destroy(); } catch (e) { console.error(e); } current = null; }
  clear(viewEl);
  if (!r) {
    viewEl.append(h('div', { class: 'empty-card' }, h('h3', null, 'Page not found'), h('a', { href: '#/' }, 'Back to overview')));
    return;
  }
  document.title = 'pathwatch';
  try {
    current = { name: r.name, key: r.key, instance: r.mod.mount(viewEl, ctx) };
  } catch (e) {
    console.error(e);
    viewEl.append(h('div', { class: 'state-msg error' }, 'This page failed to render: ' + e.message));
  }
  if (scroll) window.scrollTo(0, 0);
}

// ---------- header: theme picker ----------
function buildThemeSelect() {
  const sel = document.getElementById('theme-select');
  for (const t of THEMES) sel.append(h('option', { value: t.id }, t.name));
  sel.value = getPref();
  sel.addEventListener('change', () => setPref(sel.value));
  onPrefChange((p) => { sel.value = p; });
}

// ---------- header: status chips ----------
function buildChips() {
  const chips = document.getElementById('chips');
  onStatus((s) => {
    clear(chips);
    const local = s.local_status || 'unknown';
    const lcls = local === 'ok' ? 'ok' : local === 'down' ? 'down' : '';
    chips.append(
      h('span', { class: 'chip ' + lcls, title: 'Local connectivity (gateway reachability): ' + local },
        h('span', { class: 'dot' }), h('span', { class: 'chip-label' }, 'Local network '), local === 'ok' ? 'OK' : local === 'down' ? 'DOWN' : 'unknown'),
      h('a', { class: 'chip ' + (s.active_alerts > 0 ? 'crit' : ''), href: '#/alerts', title: 'Active alerts' },
        h('span', { class: 'dot' }), s.active_alerts, h('span', { class: 'chip-label' }, s.active_alerts === 1 ? ' active alert' : ' active alerts')));
  });
}

// ---------- banner ----------
function buildBanner() {
  const banner = document.getElementById('banner');
  onHealth((entries) => {
    if (!entries.length) { banner.hidden = true; clear(banner); return; }
    const unreachable = entries.some(([, m]) => /reach/i.test(m));
    clear(banner);
    banner.append(
      h('strong', null, unreachable ? 'Cannot reach the pathwatch server. ' : 'The server reported an error. '),
      unreachable ? 'Retrying automatically…' : entries[0][1] + '. Retrying automatically…');
    banner.hidden = false;
  });
}

window.addEventListener('hashchange', () => route(true));
buildThemeSelect();
buildChips();
buildBanner();
startStatusPolling();
startStream();
route(false);
