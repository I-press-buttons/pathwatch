// Monitor health: the Overview card (pathwatch's own problems: disk, database, probing, clock)
// and a dialog with the details from /api/system.
import { h, clear, fmtAgo, fmtDuration, isNum, DASH } from '../util.js';
import { api, serverNow } from '../api.js';

const LABEL = { ok: 'OK', warn: 'Warning', crit: 'Problem' };

export function fmtBytes(n) {
  if (!isNum(n)) return DASH;
  const u = ['B', 'kB', 'MB', 'GB', 'TB'];
  let i = 0;
  while (n >= 1000 && i < u.length - 1) { n /= 1000; i++; }
  return (i ? n.toFixed(1) : String(n)) + ' ' + u[i];
}

/** The card for the status strip; sys is status.system ({state, issues}) or null. */
export function systemCard(sys) {
  const card = h('div', { class: 'card stat clickable' + (sys ? ' ' + sys.state : ''), tabIndex: 0, role: 'button', title: 'Show monitor health details' });
  const issues = (sys && sys.issues) || [];
  const v = !sys ? DASH : sys.state === 'ok' ? 'OK' : issues.length === 1 ? '1 problem' : issues.length + ' problems';
  const sub = !sys ? ' ' : issues.length ? issues[0].message : 'Disk, database, probing';
  card.append(h('div', { class: 'k' }, 'Monitor health'), h('div', { class: 'v' }, v), h('div', { class: 's clamp2', title: issues.map((i) => i.message).join('\n') || null }, sub));
  const open = () => openSystemDialog();
  card.addEventListener('click', open);
  card.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); open(); } });
  return card;
}

export function openSystemDialog() {
  const dlg = h('dialog', { class: 'wide', 'aria-label': 'Monitor health' });
  const body = h('div', null, h('span', { class: 'spinner' }), ' Loading…');
  dlg.append(h('form', { method: 'dialog' },
    h('div', { class: 'dlg-title' }, h('h3', null, 'Monitor health')),
    body,
    h('div', { class: 'actions' }, h('a', { class: 'btn', href: '#/settings', onclick: () => dlg.close() }, 'Settings'), h('span', { class: 'grow' }),
      h('button', { class: 'btn primary', value: 'close' }, 'Close'))));
  dlg.addEventListener('close', () => dlg.remove());
  document.body.appendChild(dlg);
  dlg.showModal();
  api.system().then((s) => render(body, s)).catch((e) => { clear(body).append(h('p', { class: 'form-error' }, e.message)); });
}

function render(body, s) {
  const now = serverNow();
  const row = (k, v, cls) => h('tr', null, h('th', { scope: 'row' }, k), h('td', { class: cls || null }, v));
  const d = s.disk || {}, db = s.database || {}, p = s.probing || {}, c = s.clock || {}, pr = s.process || {};
  const clockVal = !c.server ? 'Not checked (set an NTP server in Settings → Monitor health)'
    : c.error ? 'Check failed: ' + c.error
      : isNum(c.offset_ms) ? (Math.abs(c.offset_ms) < 1000 ? Math.round(c.offset_ms) + ' ms' : (c.offset_ms / 1000).toFixed(1) + ' s') + ' vs ' + c.server + (c.checked ? ' (' + fmtAgo(c.checked, now) + ')' : '')
        : 'Checking ' + c.server + '…';
  clear(body).append(
    s.issues && s.issues.length
      ? h('ul', { class: 'issue-list' }, s.issues.map((i) => h('li', { class: i.severity }, i.message)))
      : h('p', { class: 'ok-note' }, 'No problems: pathwatch is keeping up.'),
    h('table', { class: 'grid pubip-tbl' }, h('tbody', null,
      row('Data folder', d.dir || DASH),
      row('Free disk space', d.known ? fmtBytes(d.free_bytes) + ' of ' + fmtBytes(d.total_bytes) + ' (' + d.free_pct.toFixed(1) + '%)' : 'Unknown on this platform'),
      row('Database size', fmtBytes(db.size_bytes) + (db.wal_bytes ? ' (incl. ' + fmtBytes(db.wal_bytes) + ' write-ahead log)' : '')),
      row('Database writer', (db.writer_alive ? 'Committing' : 'Stalled') + ' · last transaction ' + (isNum(db.last_commit_ms) ? db.last_commit_ms.toFixed(1) + ' ms' : DASH)),
      row('Dropped / failed writes', (db.dropped_writes || 0) + ' / ' + (db.write_errors || 0) + ' since start'),
      row('ICMP rounds (10 min)', (p.rounds_10m || 0) + ' done · ' + (p.late_10m || 0) + ' late · ' + (p.discarded_10m || 0) + ' stalled · ' + (p.send_errors_10m || 0) + ' send errors'),
      row('Clock', clockVal),
      row('Process', 'up ' + fmtDuration((pr.uptime_s || 0) * 1000) + ' · ' + (pr.goroutines || 0) + ' goroutines · heap ' + fmtBytes(pr.heap_bytes) + (pr.version ? ' · v' + pr.version : '')))),
    h('p', { class: 'hint' }, 'Add a "Monitor health" alert rule (Settings → Alert rules) to be notified about these problems.'));
}
