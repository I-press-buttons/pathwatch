// Alerts page: feed, silences (create/end), maintenance windows (read-only).
import { h, clear, isNum, fmtMs, fmtDateTime, fmtDuration, fmtAgo, DASH } from '../util.js';
import { api, serverNow } from '../api.js';
import { alertPill, deliveryPill, panel, confirmDialog } from '../ui.js';

function fmtVal(ruleType, v) {
  if (!isNum(v)) return DASH;
  const t = ruleType || '';
  if (/latency|rtt|ttfb/.test(t)) return fmtMs(v) + ' ms';
  if (/loss|degrad/.test(t)) return v.toFixed(1) + '%';
  if (/expiry/.test(t)) return v.toFixed(0) + ' d';
  return Number.isInteger(v) ? String(v) : v.toFixed(1);
}

export function mount(root, ctx) {
  let destroyed = false, timer = null, seq = 0;
  let targets = [], alerts = null, silences = null;
  const filter = { target: '', state: '' };

  const targetSel = h('select', { 'aria-label': 'Filter by target', onchange: () => { filter.target = targetSel.value; loadAlerts(); } }, h('option', { value: '' }, 'All targets'));
  const stateSel = h('select', { 'aria-label': 'Filter by state', onchange: () => { filter.state = stateSel.value; renderFeed(); } },
    [['', 'All states'], ['firing', 'Firing'], ['resolved', 'Resolved'], ['suppressed', 'Suppressed']].map(([v, l]) => h('option', { value: v }, l)));
  const feed = panel('Alert feed', { actions: h('div', { class: 'row', style: { gap: '8px', alignItems: 'center' } }, targetSel, stateSel), flush: true });
  const sil = panel('Silences', { flush: true });
  const maint = panel('Maintenance windows (from config, read-only)', { flush: true });
  const formPanel = panel('Silence alerts');

  root.append(h('div', { class: 'page-head' }, h('h1', null, 'Alerts'), h('span', { class: 'sub' }, 'Alerts, silences and maintenance windows')), feed.el,
    h('div', { class: 'two-col' }, h('div', null, formPanel.el, maint.el), h('div', null, sil.el)));
  feed.showLoading(); sil.showLoading(); maint.showLoading();
  buildForm();

  function tname(id) { if (id == null) return 'All targets'; const t = targets.find((x) => x.id === id); return t ? t.name : '#' + id; }

  function renderFeed() {
    if (!alerts) return;
    let list = alerts;
    if (filter.state) list = list.filter((a) => a.state === filter.state);
    if (!list.length) { feed.showEmpty(alerts.length ? 'No alerts match this filter.' : 'No alerts yet.', alerts.length ? '' : 'Alerts appear here when a rule fires or is suppressed.'); return; }
    const now = serverNow();
    const rows = list.map((a) => {
      const ongoing = a.state === 'firing' || a.ended_at == null;
      const dur = (ongoing ? now : a.ended_at) - a.started_at;
      return h('tr', null,
        h('td', { 'data-label': 'State' }, alertPill(a)),
        h('td', { 'data-label': 'Alert' }, h('div', null, h('strong', null, a.rule), ' ', h('span', { class: 'muted' }, '· ', h('a', { href: '#/target/' + a.target_id }, a.target_name || tname(a.target_id)))),
          a.message ? h('div', { class: 'alert-msg' }, a.message) : null),
        h('td', { 'data-label': 'Started', title: fmtDateTime(a.started_at) }, fmtDateTime(a.started_at), h('div', { class: 'muted' }, fmtAgo(a.started_at, now))),
        h('td', { 'data-label': 'Duration' }, ongoing ? h('span', null, fmtDuration(dur), h('div', { class: 'muted' }, 'ongoing')) : fmtDuration(dur)),
        h('td', { class: 'cmp', 'data-label': 'Value' },
          h('div', null, fmtVal(a.rule_type, a.value), isNum(a.peak_value) && a.peak_value !== a.value ? h('span', { class: 'muted' }, ' (peak ' + fmtVal(a.rule_type, a.peak_value) + ')') : null),
          isNum(a.baseline) ? h('div', { class: 'base' }, 'baseline ' + fmtVal(a.rule_type, a.baseline)) : null),
        h('td', { 'data-label': 'Delivery' }, (a.deliveries && a.deliveries.length) ? h('div', { class: 'deliv' }, a.deliveries.map(deliveryPill)) : h('span', { class: 'muted' }, a.state === 'suppressed' ? 'not sent' : DASH)));
    });
    const table = h('div', { class: 'table-scroll' }, h('table', { class: 'list-table stack' },
      h('thead', null, h('tr', null, ['State', 'Alert', 'Started', 'Duration', 'Value', 'Delivery'].map((c) => h('th', null, c)))),
      h('tbody', null, rows)));
    clear(feed.content).append(table);
    feed.showContent();
  }

  function renderSilences() {
    if (!silences) return;
    const now = serverNow();
    const uis = silences.filter((s) => s.source !== 'maintenance');
    const ms = silences.filter((s) => s.source === 'maintenance');
    if (!uis.length) sil.showEmpty('No silences.', 'Create one to suppress notifications temporarily, e.g. during router maintenance.');
    else {
      const rows = uis.map((s) => {
        const upcoming = s.starts_at > now;
        return h('tr', null,
          h('td', { 'data-label': 'Scope' }, h('strong', null, tname(s.target_id)), h('div', { class: 'muted' }, s.rule ? 'rule: ' + s.rule : 'all rules')),
          h('td', { 'data-label': 'Window' }, upcoming ? h('span', { class: 'pill info nodot' }, 'upcoming') : h('span', { class: 'pill warn nodot' }, 'active'), h('div', { class: 'muted' }, fmtDateTime(s.starts_at) + ' → ' + fmtDateTime(s.ends_at)),
            h('div', { class: 'muted' }, upcoming ? 'starts ' + fmtAgo(s.starts_at, now) : 'ends ' + fmtAgo(s.ends_at, now))),
          h('td', { 'data-label': 'Reason' }, s.reason || h('span', { class: 'muted' }, DASH)),
          h('td', { class: 'right' }, h('button', { class: 'btn sm danger', onclick: () => endSilence(s) }, 'End')));
      });
      clear(sil.content).append(h('div', { class: 'table-scroll' }, h('table', { class: 'list-table stack' },
        h('thead', null, h('tr', null, ['Scope', 'Window', 'Reason', ''].map((c) => h('th', null, c)))), h('tbody', null, rows))));
      sil.showContent();
    }
    if (!ms.length) maint.showEmpty('No maintenance windows active.', 'Recurring windows are defined under alerts.maintenance_windows in the config file.');
    else {
      clear(maint.content).append(h('div', { class: 'table-scroll' }, h('table', { class: 'list-table stack' },
        h('thead', null, h('tr', null, ['Window', 'Scope', 'Active until'].map((c) => h('th', null, c)))),
        h('tbody', null, ms.map((s) => h('tr', null,
          h('td', { 'data-label': 'Window' }, h('strong', null, s.reason || 'maintenance'), h('div', { class: 'muted' }, fmtDateTime(s.starts_at) + ' → ' + fmtDateTime(s.ends_at))),
          h('td', { 'data-label': 'Scope' }, tname(s.target_id), s.rule ? ' · ' + s.rule : ''),
          h('td', { 'data-label': 'Until' }, fmtDateTime(s.ends_at))))))));
      maint.showContent();
    }
  }

  async function endSilence(s) {
    const ok = await confirmDialog({ title: 'End silence?', message: `Resume notifications for ${tname(s.target_id)}${s.rule ? ' (' + s.rule + ')' : ''}?`, confirmLabel: 'End silence' });
    if (!ok) return;
    try { await api.deleteSilence(s.id); } catch (e) { alert(e.message); }
    loadSilences();
  }

  function buildForm() {
    const scope = h('select', { id: 'sil-scope', name: 'target' }, h('option', { value: '' }, 'All targets'));
    const rule = h('input', { type: 'text', id: 'sil-rule', name: 'rule', list: 'sil-rules', placeholder: 'any rule', autocomplete: 'off' });
    const dl = h('datalist', { id: 'sil-rules' });
    const reason = h('input', { type: 'text', id: 'sil-reason', name: 'reason', placeholder: 'e.g. router firmware upgrade', maxlength: 200 });
    const err = h('div', { class: 'form-error', hidden: true, role: 'alert' });
    let preset = '1h';
    const customN = h('input', { type: 'number', min: 1, value: 2, style: { width: '70px' }, 'aria-label': 'Custom duration' });
    const customU = h('select', { 'aria-label': 'Custom duration unit' }, [['60000', 'minutes'], ['3600000', 'hours'], ['86400000', 'days']].map(([v, l], i) => h('option', { value: v, selected: i === 1 }, l)));
    const customBox = h('div', { class: 'row', style: { marginTop: '6px', alignItems: 'center' }, hidden: true }, customN, customU);
    const presetBtns = [['1h', '1 hour'], ['4h', '4 hours'], ['24h', '24 hours'], ['custom', 'Custom']].map(([k, l]) =>
      h('button', { type: 'button', class: 'btn sm', 'aria-pressed': String(k === preset), dataset: { k }, onclick: () => { preset = k; presetBtns.forEach((b) => b.setAttribute('aria-pressed', String(b.dataset.k === k))); customBox.hidden = k !== 'custom'; } }, l));
    const submit = h('button', { class: 'btn primary', type: 'submit' }, 'Create silence');
    const form = h('form', null,
      err,
      h('div', { class: 'field' }, h('label', { for: 'sil-scope' }, 'Target'), scope),
      h('div', { class: 'field' }, h('label', { for: 'sil-rule' }, 'Rule (optional)'), rule, dl),
      h('div', { class: 'field' }, h('span', { class: 'lbl' }, 'Duration'), h('div', { class: 'presets', role: 'group', 'aria-label': 'Duration' }, presetBtns), customBox),
      h('div', { class: 'field' }, h('label', { for: 'sil-reason' }, 'Reason'), reason),
      submit);
    form.addEventListener('submit', async (ev) => {
      ev.preventDefault(); err.hidden = true;
      let dur = { '1h': 3600000, '4h': 14400000, '24h': 86400000 }[preset];
      if (preset === 'custom') dur = Math.round(Number(customN.value) * Number(customU.value));
      if (!(dur > 0)) { err.textContent = 'Enter a positive duration.'; err.hidden = false; return; }
      submit.disabled = true;
      try {
        await api.createSilence({ target_id: scope.value ? Number(scope.value) : null, rule: rule.value.trim() || null, duration_ms: dur, reason: reason.value.trim() });
        reason.value = ''; rule.value = '';
        loadSilences();
      } catch (e) { err.textContent = e.message; err.hidden = false; }
      finally { submit.disabled = false; }
    });
    clear(formPanel.content).append(form);
    formPanel.showContent();
    formPanel.fill = (tg, rules) => {
      const cur = scope.value;
      clear(scope).append(h('option', { value: '' }, 'All targets'), ...tg.map((t) => h('option', { value: t.id }, t.name)));
      scope.value = cur;
      clear(dl).append(...rules.map((r) => h('option', { value: r })));
    };
  }

  async function loadAlerts() {
    try {
      const params = { limit: 100 }; if (filter.target) params.target_id = filter.target;
      const a = await api.alerts(params);
      if (destroyed) return;
      alerts = a || []; feed.clearStale(); renderFeed();
      formPanel.fill && formPanel.fill(targets, [...new Set(alerts.map((x) => x.rule))]);
    } catch (e) { if (!destroyed) feed.showError(e.message); }
  }
  async function loadSilences() {
    try { const s = await api.silences(); if (destroyed) return; silences = s || []; sil.clearStale(); renderSilences(); }
    catch (e) { if (!destroyed) { sil.showError(e.message); maint.showError(e.message); } }
  }
  async function loadTargets() {
    try {
      targets = (await api.targets()) || [];
      const cur = targetSel.value;
      clear(targetSel).append(h('option', { value: '' }, 'All targets'), ...targets.map((t) => h('option', { value: t.id }, t.name)));
      targetSel.value = cur;
      formPanel.fill && formPanel.fill(targets, alerts ? [...new Set(alerts.map((x) => x.rule))] : []);
      renderSilences();
    } catch (e) { /* banner handles it */ }
  }
  (async () => { await loadTargets(); loadAlerts(); loadSilences(); })();
  timer = setInterval(() => { loadAlerts(); loadSilences(); }, 10000);
  return { destroy() { destroyed = true; clearInterval(timer); } };
}
