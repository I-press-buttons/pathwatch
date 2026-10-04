// Settings page editors for the server-side settings: probe defaults, status thresholds,
// alert rules and DNS probes. Each section is saved on the server, applies immediately, and
// can be reverted to the config file.
import { h, clear } from '../util.js';
import { api } from '../api.js';
import { panel, confirmDialog } from '../ui.js';
import {
  durField, numField, textField, selectField, checkField, errorList, setOrDelete, sourceBadge,
  RULE_TYPES, paramField, ruleTypeLabel,
} from '../forms.js';

const clone = (o) => JSON.parse(JSON.stringify(o));

/**
 * One editable section: a panel with its source badge, Save and Revert. build(settings) returns
 * {body: Node, collect(): {value, errs}}. onChange(settings) gets the server's new settings.
 */
function section({ key, title, intro, build, onChange }) {
  const p = panel(title);
  const badge = h('span');
  const err = h('div', { class: 'form-error', hidden: true, role: 'alert' });
  const ok = h('span', { class: 'saved-note', 'aria-live': 'polite' });
  const save = h('button', { class: 'btn sm primary', type: 'submit' }, 'Save');
  const revert = h('button', { class: 'btn sm', type: 'button' }, 'Revert to config file');
  p.head.append(badge);
  let current = null;
  let form = null;

  function showErr(list) {
    clear(err).append(list.length === 1 ? list[0] : h('ul', null, list.map((m) => h('li', null, m))));
    err.hidden = false;
  }
  async function submit(ev) {
    ev.preventDefault();
    err.hidden = true; ok.textContent = '';
    const { value, errs } = current.collect();
    if (errs.length) return showErr(errs);
    save.disabled = true;
    try {
      const s = await api.putSetting(key, value);
      self.render(s);
      ok.textContent = 'Saved and applied.';
      onChange(s);
    } catch (e) { showErr([e.message]); } finally { save.disabled = false; }
  }
  revert.addEventListener('click', async () => {
    const yes = await confirmDialog({ title: 'Revert to config file?', message: `Discard the ${title.toLowerCase()} edited here and use the config file's again?`, confirmLabel: 'Revert' });
    if (!yes) return;
    try {
      const s = await api.revertSetting(key);
      self.render(s);
      onChange(s);
    } catch (e) { showErr([e.message]); }
  });

  const self = {
    el: p.el,
    render(settings) {
      const sec = settings[key];
      clear(badge).append(sourceBadge(sec.source));
      revert.hidden = sec.source !== 'ui';
      current = build(settings);
      err.hidden = true;
      form = h('form', { novalidate: true, onsubmit: submit, class: 'settings-form' },
        intro ? h('p', { class: 'muted small intro' }, intro) : null, err, current.body,
        h('div', { class: 'actions' }, revert, h('span', { class: 'grow' }), ok, save));
      clear(p.content).append(form);
      p.showContent();
    },
    error(msg) { p.showError(msg); },
    loading() { p.showLoading(); },
  };
  return self;
}

// ---------------------------------------------------------------------------

function defaultsSection(onChange) {
  return section({
    key: 'defaults', title: 'Probe defaults', onChange,
    intro: 'Used by every target and DNS probe that does not set its own value. Changes apply to running probes right away.',
    build(settings) {
      const v = settings.defaults.value;
      const max = settings.max_retries || 10;
      const f = {
        icmp_interval_ms: durField('Interval', { value: v.icmp_interval_ms, unit: 's', min: 500 }),
        icmp_timeout_ms: durField('Timeout', { value: v.icmp_timeout_ms, unit: 's', hint: 'Capped at the interval.' }),
        max_hops: numField('Max hops', { value: v.max_hops, min: 1, max: 64, integer: true }),
        path_rediscovery_ms: durField('Re-resolve and rediscover every', { value: v.path_rediscovery_ms, unit: 'min', hint: 'Hostnames are looked up again this often.' }),
        http_interval_ms: durField('Interval', { value: v.http_interval_ms, unit: 's', min: 1000 }),
        http_timeout_ms: durField('Timeout', { value: v.http_timeout_ms, unit: 's' }),
        tcp_interval_ms: durField('Interval', { value: v.tcp_interval_ms, unit: 's', min: 1000 }),
        tcp_timeout_ms: durField('Timeout', { value: v.tcp_timeout_ms, unit: 's' }),
        dns_interval_ms: durField('Interval', { value: v.dns_interval_ms, unit: 's', min: 1000 }),
        dns_timeout_ms: durField('Timeout', { value: v.dns_timeout_ms, unit: 's' }),
        retries: numField('Retries', { value: v.retries, min: 0, max, integer: true, hint: `0–${max}` }),
      };
      const group = (label, ...fs) => h('fieldset', { class: 'section' }, h('legend', null, label), h('div', { class: 'grid-fields' }, fs.map((x) => x.el)));
      const body = h('div', null,
        group('Hop trace (ICMP)', f.icmp_interval_ms, f.icmp_timeout_ms, f.max_hops, f.path_rediscovery_ms),
        group('HTTP probes', f.http_interval_ms, f.http_timeout_ms),
        group('TCP probes', f.tcp_interval_ms, f.tcp_timeout_ms),
        group('DNS probes', f.dns_interval_ms, f.dns_timeout_ms),
        h('fieldset', { class: 'section' }, h('legend', null, 'Retries'),
          h('div', { class: 'grid-fields' }, f.retries.el,
            h('p', { class: 'hint span3' }, 'A failed HTTP, TCP or DNS probe is retried, while time remains before the next one is due, before the failure is recorded. Hop probes are never retried: an unanswered probe is the loss being measured.'))),
        h('p', { class: 'hint' }, 'Leave a field blank for the built-in default.'));
      return {
        body,
        collect() {
          const E = errorList();
          const out = clone(v);
          for (const [k, fld] of Object.entries(f)) { const x = E.num(fld); out[k] = x == null ? 0 : x; }
          return { value: out, errs: E.errs };
        },
      };
    },
  });
}

function statusSection(onChange) {
  return section({
    key: 'status', title: 'Status thresholds', onChange,
    intro: 'When a target is shown as degraded (yellow), judged over the last 5 minutes. Alerts are configured separately below.',
    build(settings) {
      const v = settings.status.value;
      const loss = numField('Degraded above end-to-end loss of', { value: v.degraded_loss_pct, min: 0.1, max: 100, step: 0.1, unit: '%' });
      const http = numField('Degraded below HTTP success of', { value: v.degraded_http_success_pct, min: 0.1, max: 100, step: 0.1, unit: '%' });
      return {
        body: h('div', { class: 'grid-fields' }, loss.el, http.el),
        collect() {
          const E = errorList();
          const out = clone(v);
          out.degraded_loss_pct = E.num(loss) || 0;
          out.degraded_http_success_pct = E.num(http) || 0;
          return { value: out, errs: E.errs };
        },
      };
    },
  });
}

function alertsSection(onChange) {
  return section({
    key: 'alerts', title: 'Alert rules', onChange,
    intro: 'Rules apply to every target that has the probes they need. Targets can turn rules off or change thresholds in their own editor (Edit target → Alert thresholds).',
    build(settings) {
      const v = settings.alerts.value;
      const channels = settings.channels || {};
      const list = h('div', { class: 'rule-list' });
      const items = [];
      const cooldown = durField('Cooldown', { value: v.cooldown_ms, unit: 'min', hint: 'After an alert resolves, the same alert cannot fire again for this long.' });
      const clearRatio = numField('Clear ratio', { value: v.clear_ratio, min: 0.05, max: 0.95, step: 0.05, hint: 'Hysteresis: clears below this × the trigger level.' });

      function addRule(r, focus) {
        const meta = RULE_TYPES[r.type] || { params: [], label: r.type };
        const name = textField('Name', { value: r.name, required: true, maxlength: 63 });
        const enabled = checkField('Enabled', { checked: r.enabled !== false });
        const notify = new Set(r.notify || []);
        const chans = ['webhook', 'email'].map((c) => ({ c, f: checkField(c === 'webhook' ? 'Webhook' : 'Email', { checked: notify.has(c), hint: channels[c] ? '' : ' (not configured)' }) }));
        const params = meta.params.map((k) => ({ k, f: paramField(k, { value: r[k] }) }));
        const item = { r };
        item.row = h('div', { class: 'rule-card' },
          h('div', { class: 'probe-head' },
            h('strong', null, ruleTypeLabel(r.type)), h('span', { class: 'muted small' }, ' · ' + (meta.desc || '')), h('span', { class: 'grow' }),
            h('button', { class: 'btn sm danger', type: 'button', onclick: () => { items.splice(items.indexOf(item), 1); item.row.remove(); } }, 'Remove')),
          h('div', { class: 'grid-fields' }, name.el, params.map((x) => x.f.el)),
          h('div', { class: 'checks' }, enabled.el,
            h('span', { class: 'muted small' }, 'Notify:'), chans.map((x) => x.f.el),
            h('span', { class: 'hint' }, 'none ticked = every configured channel')));
        item.collect = (E) => {
          const o = clone(r);
          o.name = name.get();
          if (!o.name) E.add(`${ruleTypeLabel(r.type)} rule: name is required.`);
          if (enabled.get()) delete o.enabled; else o.enabled = false;
          const n = chans.filter((x) => x.f.get()).map((x) => x.c);
          if (n.length) o.notify = n; else delete o.notify;
          for (const { k, f } of params) setOrDelete(o, k, E.num(f));
          return o;
        };
        items.push(item);
        list.append(item.row);
        if (focus) name.input.focus();
      }
      for (const r of v.rules || []) addRule(r);

      const types = settings.rule_types || Object.keys(RULE_TYPES);
      const typeSel = selectField('Add a rule', types.map((t) => [t, ruleTypeLabel(t)]));
      const addBtn = h('button', { class: 'btn sm', type: 'button', onclick: () => {
        const t = typeSel.get();
        const taken = new Set(items.map((i) => i.r.name));
        let n = t.replace(/_/g, '-'), i = 2;
        while (taken.has(n)) n = t.replace(/_/g, '-') + '-' + i++;
        addRule({ name: n, type: t }, true);
      } }, '+ Add');
      return {
        body: h('div', null, list,
          h('div', { class: 'row add-row' }, typeSel.el, addBtn),
          h('fieldset', { class: 'section' }, h('legend', null, 'Noise control'), h('div', { class: 'grid-fields' }, cooldown.el, clearRatio.el))),
        collect() {
          const E = errorList();
          const out = clone(v);
          out.rules = items.map((i) => i.collect(E));
          const seen = new Set();
          for (const r of out.rules) { if (seen.has(r.name)) E.add(`Two rules are named "${r.name}".`); seen.add(r.name); }
          out.cooldown_ms = E.num(cooldown) || 0;
          out.clear_ratio = E.num(clearRatio) || 0;
          return { value: out, errs: E.errs };
        },
      };
    },
  });
}

function dnsSection(onChange) {
  return section({
    key: 'dns_probes', title: 'DNS probe setup', onChange,
    intro: 'Query a resolver directly (your router, Pi-hole or ISP resolver) to catch slow or failing DNS independently of any target.',
    build(settings) {
      const D = settings.defaults.value;
      const list = h('div', { class: 'probe-list' });
      const items = [];
      const empty = h('p', { class: 'muted small' }, 'No DNS probes.');
      function addProbe(p, focus) {
        const name = textField('Name', { value: p.name, required: true, maxlength: 63, placeholder: 'home-resolver' });
        const server = textField('Server', { value: p.server, required: true, placeholder: '192.168.1.1 or dns.example:53' });
        const query = textField('Query', { value: p.query, required: true, placeholder: 'example.com' });
        const record = selectField('Record', [['A', 'A (IPv4)'], ['AAAA', 'AAAA (IPv6)']], { value: (p.record || 'A').toUpperCase() });
        const interval = durField('Interval', { value: p.interval_ms, unit: 's', inherit: D.dns_interval_ms, min: 1000 });
        const timeout = durField('Timeout', { value: p.timeout_ms, unit: 's', inherit: D.dns_timeout_ms });
        const retries = numField('Retries', { value: p.retries, inherit: D.retries, min: 0, max: settings.max_retries || 10, integer: true });
        const item = {};
        item.row = h('div', { class: 'probe-row' },
          h('div', { class: 'probe-head' }, h('strong', null, 'DNS probe'), h('span', { class: 'grow' }),
            h('button', { class: 'btn sm danger', type: 'button', onclick: () => { items.splice(items.indexOf(item), 1); item.row.remove(); empty.hidden = items.length > 0; } }, 'Remove')),
          h('div', { class: 'grid-fields' }, name.el, server.el, query.el, record.el, interval.el, timeout.el, retries.el));
        item.collect = (E) => {
          const o = clone(p);
          o.name = name.get(); o.server = server.get(); o.query = query.get(); o.record = record.get();
          if (!o.name || !o.server || !o.query) E.add('DNS probe: name, server and query are required.');
          setOrDelete(o, 'interval_ms', E.num(interval));
          setOrDelete(o, 'timeout_ms', E.num(timeout));
          setOrDelete(o, 'retries', E.num(retries));
          return o;
        };
        items.push(item);
        list.append(item.row);
        empty.hidden = true;
        if (focus) name.input.focus();
      }
      for (const p of settings.dns_probes.value || []) addProbe(p);
      empty.hidden = items.length > 0;
      return {
        body: h('div', null, empty, list,
          h('button', { class: 'btn sm', type: 'button', onclick: () => addProbe({ record: 'A' }, true) }, '+ Add DNS probe'),
          h('p', { class: 'hint' }, 'Blank interval, timeout and retries follow the probe defaults. Renaming a probe starts a new history.')),
        collect() {
          const E = errorList();
          return { value: items.map((i) => i.collect(E)), errs: E.errs };
        },
      };
    },
  });
}

/** Builds the four editors; returns {els, load()}. onSaved(settings) runs after a save or revert. */
export function settingsEditors({ onSaved } = {}) {
  const changed = (s) => { onSaved && onSaved(s); };
  const sections = [defaultsSection(changed), statusSection(changed), alertsSection(changed), dnsSection(changed)];
  return {
    els: sections.map((s) => s.el),
    async load() {
      sections.forEach((s) => s.loading());
      try {
        const s = await api.settings();
        sections.forEach((x) => x.render(s));
      } catch (e) {
        sections.forEach((x) => x.error(e.status === 503 ? 'Settings cannot be edited on this server.' : e.message));
      }
    },
  };
}
