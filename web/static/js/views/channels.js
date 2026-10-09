// Notification channels panel (Settings): what is configured, how the last alert notification
// went, and a "Send test" button per channel. Channels are configured in the config file only.
import { h, clear, fmtAgo, fmtDateTime, DASH } from '../util.js';
import { api, serverNow } from '../api.js';
import { panel, DELIVERY } from '../ui.js';

const LABEL = { webhook: 'Webhook', email: 'Email' };

export function channelsPanel() {
  const p = panel('Notification channels');
  const note = h('p', { class: 'muted small intro' },
    'Channels are set up in the config file (alerts.notify), with URLs and passwords in environment variables. ',
    'Send a test to check delivery end to end. A test is sent immediately, is not stored and is not retried.');
  let seq = 0, list = null;
  const busy = new Set();      // channels with a test in flight
  const errors = new Map();    // channel -> request error (429, 409, network)
  p.showLoading('Loading channels…');

  async function load() {
    const my = ++seq;
    try {
      const d = await api.channels();
      if (my !== seq) return;
      list = d || [];
      p.clearStale();
      render();
    } catch (e) {
      if (e.name !== 'AbortError') p.showError(e.message);
    }
  }

  async function test(name) {
    busy.add(name); errors.delete(name); render();
    try { await api.testChannel(name); } catch (e) {
      errors.set(name, e.message);
      setTimeout(() => { if (errors.get(name) === e.message) { errors.delete(name); render(); } }, 10000);
    }
    busy.delete(name);
    await load();
  }

  function outcome(ok, at, err, now) {
    return h('div', null,
      h('span', { class: 'pill ' + (ok ? 'ok' : 'crit') }, ok ? 'delivered' : 'failed'),
      ' ', h('span', { class: 'muted', title: fmtDateTime(at) }, fmtAgo(at, now)),
      err ? h('div', { class: 'alert-msg' }, err) : null);
  }

  function render() {
    if (!list) return;
    const now = serverNow();
    const rows = list.map((c) => {
      const state = !c.configured ? h('span', { class: 'pill nodot' }, 'not configured')
        : !c.active ? h('span', { class: 'pill crit' }, 'error')
          : c.warnings.length ? h('span', { class: 'pill warn' }, 'check setup') : h('span', { class: 'pill ok' }, 'ready');
      const d = c.last_delivery;
      const delivery = d ? h('div', null,
        h('span', { class: 'pill ' + (DELIVERY[d.status] || '') }, d.status),
        ' ', h('span', { class: 'muted', title: fmtDateTime(d.at) }, fmtAgo(d.at, now)),
        h('div', { class: 'muted' }, h('a', { href: '#/alerts' }, 'alert #' + d.alert_id), d.attempts > 1 ? ` · ${d.attempts} attempts` : ''),
        d.error ? h('div', { class: 'alert-msg' }, d.error) : null) : h('span', { class: 'muted' }, c.configured ? 'nothing sent yet' : DASH);
      const t = c.last_test;
      const sending = busy.has(c.name);
      const btn = h('button', { class: 'btn sm', type: 'button', disabled: !c.active || sending, title: c.active ? `Send a test notification over the ${c.name} channel now` : 'Configure this channel in the config file first',
        onclick: () => test(c.name) }, sending ? 'Sending…' : 'Send test');
      const reqErr = errors.get(c.name);
      return h('tr', null,
        h('td', { 'data-label': 'Channel' }, h('strong', null, LABEL[c.name] || c.name), c.summary ? h('div', { class: 'muted' }, c.summary) : null),
        h('td', { 'data-label': 'Status' }, state, c.warnings.map((w) => h('div', { class: 'alert-msg' }, w))),
        h('td', { 'data-label': 'Last alert' }, delivery),
        h('td', { 'data-label': 'Last test' }, t ? outcome(t.ok, t.at, t.error, now) : h('span', { class: 'muted' }, DASH)),
        h('td', { class: 'right' }, btn, reqErr ? h('div', { class: 'alert-msg', role: 'alert' }, reqErr) : null));
    });
    clear(p.content).append(note, h('div', { class: 'table-scroll' }, h('table', { class: 'list-table stack' },
      h('thead', null, h('tr', null, ['Channel', 'Status', 'Last alert notification', 'Last test', ''].map((x) => h('th', null, x)))),
      h('tbody', null, rows))));
    p.showContent();
  }

  return { el: p.el, load };
}
