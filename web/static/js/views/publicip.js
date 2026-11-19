// Public IP: the Overview card (current IPv4/IPv6 address, network, last change) and its
// history dialog, plus turning monitoring on from the card.
import { h, clear, fmtAgo, fmtDateTime, fmtDay, DASH } from '../util.js';
import { api, serverNow } from '../api.js';

const RECENT_MS = 24 * 3600e3; // a change this recent is highlighted
const FAM = { ipv4: 'IPv4', ipv6: 'IPv6' };

function network(c) {
  if (c.asn) return 'AS' + c.asn + (c.as_name ? ' ' + c.as_name : '');
  return c.hostname || '';
}

/** Turns public IP monitoring on, keeping the other public_ip settings. */
export async function enablePublicIP() {
  const s = await api.settings();
  const v = Object.assign({}, (s.public_ip && s.public_ip.value) || {}, { enabled: true });
  await api.putSetting('public_ip', v);
}

/**
 * The Overview card. data is /api/public-ip (or null while loading); reload() refetches.
 * Returns an element for the status strip.
 */
export function publicIPCard(data, reload) {
  const card = h('div', { class: 'card stat pubip' });
  const k = h('div', { class: 'k' }, 'Public IP');
  if (!data) {
    card.append(k, h('div', { class: 'v' }, DASH), h('div', { class: 's' }, ' '));
    return card;
  }
  if (!data.available) {
    card.append(k, h('div', { class: 'v' }, DASH), h('div', { class: 's' }, 'Not available on this server'));
    return card;
  }
  if (!data.enabled) {
    const btn = h('button', { class: 'btn sm primary', onclick: async () => {
      btn.disabled = true;
      try { await enablePublicIP(); setTimeout(reload, 4000); reload(); } catch (e) { alert(e.message); btn.disabled = false; }
    } }, 'Turn on');
    card.append(k, h('div', { class: 'v muted-v' }, 'Off'),
      h('div', { class: 's' }, btn, ' ', h('span', { title: 'Checks your public address by asking OpenDNS (myip.opendns.com) every few minutes. The source can be changed in Settings.' }, 'Detects ISP renumbering and failovers')));
    return card;
  }
  const now = serverNow();
  const cur = data.current || [];
  const v4 = cur.find((c) => c.family === 'ipv4') || {};
  const v6 = cur.find((c) => c.family === 'ipv6') || {};
  const main = v4.addr ? v4 : v6.addr ? v6 : null;
  const hist = data.history || [];
  const lastChange = hist.find((x) => x.previous);
  const recent = lastChange && now - lastChange.from < RECENT_MS;
  const failing = main && main.last_error && main.last_ok && now - main.last_ok > 3 * (data.interval_ms || 300000);
  card.className = 'card stat pubip clickable' + (recent ? ' warn' : '');
  card.tabIndex = 0;
  card.setAttribute('role', 'button');
  card.title = 'Show public IP history';
  const open = () => openPublicIPDialog(data, reload);
  card.addEventListener('click', (e) => { if (!e.target.closest('button')) open(); });
  card.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); open(); } });

  let value, sub;
  if (!main) {
    const err = v4.last_error || v6.last_error;
    value = h('div', { class: 'v muted-v' }, err ? 'Unknown' : 'Checking…');
    sub = h('div', { class: 's' }, err ? 'Last check failed: ' + err : 'First check in a few seconds');
  } else {
    value = h('div', { class: 'v ip-v', title: main.addr }, main.addr);
    const lines = [];
    const net = network(main);
    if (net) lines.push(h('div', null, net));
    if (main === v4 && v6.addr) lines.push(h('div', { class: 'ip6', title: v6.addr }, v6.addr));
    if (recent) lines.push(h('div', { class: 'chg' }, 'Changed ' + fmtAgo(lastChange.from, now) + (lastChange.previous ? ' · was ' + lastChange.previous : '')));
    else if (main.since) lines.push(h('div', null, 'Since ' + fmtDay(main.since)));
    if (failing) lines.push(h('div', { class: 'chg' }, 'Checks failing: ' + main.last_error));
    if (main.pending) lines.push(h('div', { class: 'chg' }, 'Confirming a new address: ' + main.pending));
    sub = h('div', { class: 's' }, lines);
  }
  card.append(k, value, sub);
  return card;
}

/** History dialog: current addresses, then every change of the last 90 days. */
export function openPublicIPDialog(data, reload) {
  const dlg = h('dialog', { class: 'wide', 'aria-label': 'Public IP' });
  const body = h('div');
  const status = h('span', { class: 'muted small', 'aria-live': 'polite' });
  const check = h('button', { class: 'btn', type: 'button', onclick: async () => {
    check.disabled = true; status.textContent = 'Checking…';
    try { data = await api.checkPublicIP(); render(); status.textContent = 'Checked just now.'; if (reload) reload(); } catch (e) { status.textContent = e.message; } finally { check.disabled = false; }
  } }, 'Check now');
  function render() {
    const now = serverNow();
    const rows = (data.current || []).map((c) => h('tr', null,
      h('th', { scope: 'row' }, FAM[c.family] || c.family),
      h('td', { class: 'mono' }, c.addr || 'none', c.last_error ? h('span', { class: 'err' }, (c.addr ? 'Last check failed: ' : '') + c.last_error) : null),
      h('td', null, network(c) || DASH),
      h('td', null, c.since ? fmtDateTime(c.since) : DASH),
      h('td', null, c.last_checked ? fmtAgo(c.last_checked, now) : DASH)));
    const hist = (data.history || []);
    clear(body).append(
      h('table', { class: 'grid pubip-tbl' },
        h('thead', null, h('tr', null, h('th', null, ''), h('th', null, 'Address'), h('th', null, 'Network'), h('th', null, 'Since'), h('th', null, 'Last checked'))),
        h('tbody', null, rows)),
      h('h4', null, 'Changes (last 90 days)'),
      hist.length
        ? h('table', { class: 'grid pubip-tbl' },
          h('thead', null, h('tr', null, h('th', null, 'When'), h('th', null, ''), h('th', null, 'Address'), h('th', null, 'Previous'), h('th', null, 'Network'), h('th', null, 'Held for'))),
          h('tbody', null, hist.map((x) => h('tr', null,
            h('td', null, fmtDateTime(x.from)),
            h('td', null, FAM[x.family] || x.family),
            h('td', { class: 'mono' }, x.addr),
            h('td', { class: 'mono' }, x.previous || h('span', { class: 'muted' }, 'first seen')),
            h('td', null, x.asn ? 'AS' + x.asn + (x.as_name ? ' ' + x.as_name : '') : DASH),
            h('td', null, fmtAgo(x.from, x.to || now).replace(' ago', '') + (x.to ? '' : ' (current)'))))))
        : h('p', { class: 'muted' }, 'No changes recorded.'),
      h('p', { class: 'hint' }, 'A different address is recorded once two checks in a row agree. Add a "Public IP change" alert rule (Settings → Alert rules) to be notified.'));
  }
  render();
  dlg.append(h('form', { method: 'dialog' },
    h('div', { class: 'dlg-title' }, h('h3', null, 'Public IP')),
    body,
    h('div', { class: 'actions' }, h('a', { class: 'btn', href: '#/settings', onclick: () => dlg.close() }, 'Settings'), status, h('span', { class: 'grow' }), check,
      h('button', { class: 'btn primary', value: 'close' }, 'Close'))));
  dlg.addEventListener('close', () => dlg.remove());
  document.body.appendChild(dlg);
  dlg.showModal();
}
