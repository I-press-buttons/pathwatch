// Settings page editors for the server-side settings: probe defaults, status thresholds,
// alert rules, notifications, maintenance windows, the heartbeat, DNS probes, data retention
// and hop enrichment. Each section is saved on the server, applies immediately, and can be
// reverted to the config file.
import { h, clear } from '../util.js';
import { api } from '../api.js';
import { panel, confirmDialog } from '../ui.js';
import {
  field, durField, numField, textField, selectField, checkField, errorList, setOrDelete, sourceBadge,
  RULE_TYPES, paramField, ruleTypeLabel,
} from '../forms.js';

const clone = (o) => JSON.parse(JSON.stringify(o));
// What the server sends instead of a saved secret; sending it back keeps the saved value.
const SECRET = '********';
const DAYS = [['mon', 'Mon'], ['tue', 'Tue'], ['wed', 'Wed'], ['thu', 'Thu'], ['fri', 'Fri'], ['sat', 'Sat'], ['sun', 'Sun']];

/** A password-style input for a secret. A saved secret shows as a placeholder; blank keeps it. */
function secretField(label, { saved, placeholder, hint } = {}) {
  const has = saved === SECRET;
  const f = textField(label, { value: has ? '' : saved, placeholder: has ? 'Saved (leave blank to keep)' : placeholder, hint });
  if (!saved || has) { f.input.type = 'password'; f.input.autocomplete = 'new-password'; } // a visible value (an env reference) stays visible
  return { ...f, saved: has, get: () => f.input.value.trim() || (has ? SECRET : '') };
}

function textArea(label, { value, placeholder, hint, rows = 4 } = {}) {
  const el = h('textarea', { class: 'code', rows, placeholder, spellcheck: 'false', autocapitalize: 'off' });
  if (value) el.value = value;
  return { el: field(label, el, hint, { cls: 'span3' }), input: el, label, get: () => el.value, set: (v) => { el.value = v || ''; } };
}

const toggle = (fs, on) => { fs.classList.toggle('disabled', !on); fs.querySelectorAll('input,select,textarea,button').forEach((x) => { x.disabled = !on; }); };

/**
 * One editable section: a panel with its source badge, Save and Revert. build(settings) returns
 * {body: Node, collect(): {value, errs}}. onChange(settings) gets the server's new settings.
 */
function section({ key, title, intro, build, onChange, beforeSave, revertWarning }) {
  const p = panel(title);
  const badge = h('span');
  const err = h('div', { class: 'form-error', hidden: true, role: 'alert' });
  const ok = h('span', { class: 'saved-note', 'aria-live': 'polite' });
  const save = h('button', { class: 'btn sm primary', type: 'submit' }, 'Save');
  const revert = h('button', { class: 'btn sm', type: 'button' }, 'Revert to config file');
  p.head.append(badge);
  let current = null;
  let form = null;
  let lastSettings = null;

  function showErr(list) {
    clear(err).append(list.length === 1 ? list[0] : h('ul', null, list.map((m) => h('li', null, m))));
    err.hidden = false;
  }
  async function submit(ev) {
    ev.preventDefault();
    err.hidden = true; ok.textContent = '';
    const { value, errs } = current.collect();
    if (errs.length) return showErr(errs);
    if (beforeSave && !(await beforeSave(value, lastSettings))) return;
    save.disabled = true;
    try {
      const s = await api.putSetting(key, value);
      self.render(s);
      ok.textContent = 'Saved and applied.';
      onChange(s, key);
    } catch (e) { showErr([e.message]); } finally { save.disabled = false; }
  }
  revert.addEventListener('click', async () => {
    const warn = revertWarning && lastSettings ? revertWarning(lastSettings) : '';
    const yes = await confirmDialog({ title: 'Revert to config file?', message: `Discard the ${title.toLowerCase()} edited here and use the config file's again?${warn ? ' ' + warn : ''}`, confirmLabel: 'Revert', danger: !!warn });
    if (!yes) return;
    try {
      const s = await api.revertSetting(key);
      self.render(s);
      onChange(s, key);
    } catch (e) { showErr([e.message]); }
  });

  const self = {
    el: p.el,
    render(settings) {
      lastSettings = settings;
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

function notifySection(onChange) {
  return section({
    key: 'notify', title: 'Notifications', onChange,
    intro: 'Where alert notifications go. A rule sends to every channel set up here unless it picks specific ones. URLs and passwords entered here are stored on the server and never shown again.',
    build(settings) {
      const v = settings.notify.value || {};
      const prefix = settings.notify_env_prefix || 'PATHWATCH_NOTIFY_';
      const envHint = `A variable starting with ${prefix}, or one the config file already uses for this destination.`;

      // ---- webhook
      const w = v.webhook || { preset: 'generic' };
      const wOn = checkField('Send alerts to a webhook', { checked: !!v.webhook });
      const preset = selectField('Format', [['generic', 'Generic JSON'], ['discord', 'Discord'], ['slack', 'Slack'], ['ntfy', 'ntfy']], { value: w.preset || 'generic' });
      const urlMode = selectField('URL source', [['url', 'Entered here'], ['env', 'Environment variable']], { value: w.url_env ? 'env' : 'url' });
      const url = secretField('Webhook URL', { saved: w.url, placeholder: 'https://…' });
      const urlEnv = textField('Variable name', { value: w.url_env, placeholder: prefix + 'WEBHOOK_URL', hint: envHint });
      const showUrl = () => { url.el.hidden = urlMode.get() !== 'url'; urlEnv.el.hidden = urlMode.get() !== 'env'; };
      urlMode.input.addEventListener('change', showUrl);
      showUrl();
      const hdrList = h('div', { class: 'probe-list' });
      const hdrs = [];
      function addHeader(k, val, focus) {
        const name = textField('Header name', { value: k, placeholder: 'Authorization' });
        const value = secretField('Value', { saved: val, placeholder: 'Bearer …', hint: `\${${prefix}NAME} reads an environment variable.` });
        const item = { name, value };
        item.row = h('div', { class: 'probe-row' }, h('div', { class: 'grid-fields' }, name.el, value.el,
          h('div', { class: 'field' }, h('span', { class: 'lbl' }, ' '),
            h('button', { class: 'btn sm danger', type: 'button', onclick: () => { hdrs.splice(hdrs.indexOf(item), 1); item.row.remove(); } }, 'Remove'))));
        hdrs.push(item);
        hdrList.append(item.row);
        if (focus) name.input.focus();
      }
      for (const [k, val] of Object.entries(w.headers || {})) addHeader(k, val);
      const tmpl = textArea('Body template (optional)', { value: w.body_template, placeholder: '{"text": {{json .Title}}}',
        hint: 'A Go text/template that replaces the format’s body. Fields: .Title .State .Target .Rule .Message .Value .Link …' });
      const wFs = h('div', null,
        h('div', { class: 'grid-fields' }, preset.el, urlMode.el, url.el, urlEnv.el),
        h('details', { class: 'section' }, h('summary', null, 'Custom headers and body'),
          hdrList, h('button', { class: 'btn sm', type: 'button', onclick: () => addHeader('', '', true) }, '+ Add header'),
          h('div', { class: 'grid-fields', style: { marginTop: '8px' } }, tmpl.el)));
      wOn.input.addEventListener('change', () => toggle(wFs, wOn.get()));
      toggle(wFs, wOn.get());

      // ---- email
      const e = v.email || { tls: 'starttls', to: [] };
      const eOn = checkField('Send alerts by email', { checked: !!v.email });
      const host = textField('SMTP server', { value: e.smtp_host, placeholder: 'smtp.example.com' });
      const tls = selectField('Encryption', [['starttls', 'STARTTLS'], ['tls', 'TLS (implicit)'], ['none', 'None']], { value: e.tls || 'starttls' });
      const port = numField('Port', { value: e.smtp_port || null, min: 1, max: 65535, integer: true });
      const portHint = () => { port.input.placeholder = { starttls: '587', tls: '465', none: '25' }[tls.get()] || ''; };
      tls.input.addEventListener('change', portHint);
      portHint();
      const from = textField('From', { value: e.from, placeholder: 'pathwatch <alerts@example.com>' });
      const to = textField('To', { value: (e.to || []).join(', '), placeholder: 'me@example.com, you@example.com', hint: 'Separate addresses with commas. "Name <address>" works too.' });
      const credMode = selectField('Login', [['none', 'No login'], ['here', 'Entered here'], ['env', 'Environment variables']],
        { value: e.username_env || e.password_env ? 'env' : (e.username || e.password ? 'here' : 'none') });
      const user = textField('Username', { value: e.username });
      const pass = secretField('Password', { saved: e.password });
      const userEnv = textField('Username variable', { value: e.username_env, placeholder: prefix + 'SMTP_USER', hint: envHint });
      const passEnv = textField('Password variable', { value: e.password_env, placeholder: prefix + 'SMTP_PASS' });
      const showCred = () => {
        const m = credMode.get();
        user.el.hidden = pass.el.hidden = m !== 'here';
        userEnv.el.hidden = passEnv.el.hidden = m !== 'env';
      };
      credMode.input.addEventListener('change', showCred);
      showCred();
      const eFs = h('div', { class: 'grid-fields' }, host.el, tls.el, port.el, from.el, to.el, credMode.el, user.el, pass.el, userEnv.el, passEnv.el);
      eOn.input.addEventListener('change', () => toggle(eFs, eOn.get()));
      toggle(eFs, eOn.get());

      const maxAge = durField('Keep retrying undelivered notifications for', { value: v.outbox_max_age_ms, unit: 'h', inherit: 86400000 });

      return {
        body: h('div', null,
          h('fieldset', { class: 'section' }, h('legend', null, 'Webhook'), wOn.el, wFs),
          h('fieldset', { class: 'section' }, h('legend', null, 'Email'), eOn.el, eFs),
          h('fieldset', { class: 'section' }, h('legend', null, 'Delivery'), h('div', { class: 'grid-fields' }, maxAge.el))),
        collect() {
          const E = errorList();
          const out = { webhook: null, email: null };
          const age = E.num(maxAge);
          out.outbox_max_age_ms = age || 0;
          if (wOn.get()) {
            const o = { preset: preset.get() };
            if (urlMode.get() === 'env') { o.url_env = urlEnv.get(); if (!o.url_env) E.add('Webhook: enter the variable that holds the URL.'); }
            else { o.url = url.get(); if (!o.url) E.add('Webhook: enter the URL.'); }
            const hs = {};
            for (const it of hdrs) {
              const k = it.name.get(), val = it.value.get();
              if (!k && !val) continue;
              if (!k || !val) { E.add('Webhook header: enter both a name and a value.'); continue; }
              if (Object.keys(hs).some((x) => x.toLowerCase() === k.toLowerCase())) E.add(`Webhook header "${k}" is listed twice.`);
              hs[k] = val;
            }
            if (Object.keys(hs).length) o.headers = hs;
            if (tmpl.get().trim()) o.body_template = tmpl.get();
            out.webhook = o;
          }
          if (eOn.get()) {
            const o = { smtp_host: host.get(), tls: tls.get(), from: from.get(), to: to.get().split(/[,;\n]+/).map((x) => x.trim()).filter(Boolean) };
            const p = E.num(port);
            if (p) o.smtp_port = p;
            if (!o.smtp_host || !o.from || !o.to.length) E.add('Email: SMTP server, From and To are required.');
            if (credMode.get() === 'here') {
              o.username = user.get(); o.password = pass.get();
              if (!o.username) E.add('Email: enter the username (or choose No login).');
            } else if (credMode.get() === 'env') {
              o.username_env = userEnv.get(); o.password_env = passEnv.get();
              if (!o.username_env) E.add('Email: enter the username variable (or choose No login).');
            }
            out.email = o;
          }
          return { value: out, errs: E.errs };
        },
      };
    },
  });
}

function maintenanceSection(onChange) {
  return section({
    key: 'maintenance_windows', title: 'Maintenance windows', onChange,
    intro: 'Recurring times when alerts are suppressed, for example a nightly router reboot. For a one-off pause, create a silence on the Alerts page instead.',
    build(settings) {
      const list = h('div', { class: 'probe-list' });
      const items = [];
      const empty = h('p', { class: 'muted small' }, 'No maintenance windows.');
      function addWindow(w, focus) {
        const name = textField('Name', { value: w.name, required: true, maxlength: 63, placeholder: 'nightly-reboot' });
        const start = textField('Start', { value: w.start });
        const end = textField('End', { value: w.end, hint: 'An end at or before the start runs past midnight.' });
        start.input.type = end.input.type = 'time';
        const tz = textField('Time zone', { value: w.timezone, placeholder: 'UTC', hint: 'e.g. America/New_York' });
        const sel = new Set((w.days || []).map((d) => String(d).slice(0, 3).toLowerCase()));
        const days = DAYS.map(([d, l]) => ({ d, f: checkField(l, { checked: sel.has(d) }) }));
        const item = {};
        item.row = h('div', { class: 'probe-row' },
          h('div', { class: 'probe-head' }, h('strong', null, 'Window'), h('span', { class: 'grow' }),
            h('button', { class: 'btn sm danger', type: 'button', onclick: () => { items.splice(items.indexOf(item), 1); item.row.remove(); empty.hidden = items.length > 0; } }, 'Remove')),
          h('div', { class: 'grid-fields' }, name.el, start.el, end.el, tz.el),
          h('div', { class: 'checks' }, h('span', { class: 'muted small' }, 'Days:'), days.map((x) => x.f.el)));
        item.collect = (E) => {
          const o = { name: name.get(), start: start.get(), end: end.get(), days: days.filter((x) => x.f.get()).map((x) => x.d) };
          if (tz.get()) o.timezone = tz.get();
          if (!o.name) E.add('Maintenance window: name is required.');
          if (!o.start || !o.end) E.add(`Maintenance window ${o.name || ''}: start and end are required.`);
          if (!o.days.length) E.add(`Maintenance window ${o.name || ''}: pick at least one day.`);
          return o;
        };
        items.push(item);
        list.append(item.row);
        empty.hidden = true;
        if (focus) name.input.focus();
      }
      for (const w of settings.maintenance_windows.value || []) addWindow(w);
      empty.hidden = items.length > 0;
      return {
        body: h('div', null, empty, list,
          h('button', { class: 'btn sm', type: 'button', onclick: () => addWindow({ days: DAYS.map((d) => d[0]), start: '03:00', end: '04:00' }, true) }, '+ Add window')),
        collect() {
          const E = errorList();
          const out = items.map((i) => i.collect(E));
          const seen = new Set();
          for (const w of out) { if (seen.has(w.name)) E.add(`Two windows are named "${w.name}".`); seen.add(w.name); }
          return { value: out, errs: E.errs };
        },
      };
    },
  });
}

function heartbeatSection(onChange) {
  return section({
    key: 'heartbeat', title: 'Heartbeat', onChange,
    intro: 'A dead man’s switch: while pathwatch is healthy it requests this URL regularly, so a service such as Healthchecks.io or Uptime Kuma can alert you when pathwatch itself stops.',
    build(settings) {
      const v = settings.heartbeat.value || {};
      const url = textField('Heartbeat URL', { value: v.url, placeholder: 'https://hc-ping.com/…', hint: 'Leave blank to turn the heartbeat off.' });
      const interval = durField('Every', { value: v.interval_ms, unit: 'min', inherit: 300000, min: 1000 });
      return {
        body: h('div', { class: 'grid-fields' }, h('div', { class: 'span2' }, url.el), interval.el),
        collect() {
          const E = errorList();
          const out = { url: url.get(), interval_ms: E.num(interval) || 0 };
          if (out.url && !/^https?:\/\/[^/]/i.test(out.url)) E.add('Heartbeat URL must start with http:// or https://.');
          return { value: out, errs: E.errs };
        },
      };
    },
  });
}

function retentionSection(onChange) {
  const keys = ['raw_retention_ms', 'rollup_1m_retention_ms', 'rollup_1h_retention_ms'];
  const shortens = (next, old) => keys.some((k) => next[k] > 0 && (!(old[k] > 0) || next[k] < old[k]));
  return section({
    key: 'retention', title: 'Data retention', onChange,
    intro: 'How long measurements are kept. Older data is deleted by an hourly cleanup. Leave a field blank to keep that data forever.',
    revertWarning(settings) {
      const r = settings.retention || {};
      return shortens(r.file || {}, r.value || {}) ? 'The config file keeps data for less time: older measurements will be permanently deleted at the next hourly cleanup.' : '';
    },
    async beforeSave(value, settings) {
      const old = (settings && settings.retention && settings.retention.value) || {};
      if (!shortens(value, old)) return true;
      return confirmDialog({ title: 'Shorten data retention?', danger: true, confirmLabel: 'Shorten and delete',
        message: 'Measurements older than the new periods will be permanently deleted at the next hourly cleanup. This cannot be undone.' });
    },
    build(settings) {
      const v = settings.retention.value || {};
      const raw = durField('Individual results', { value: v.raw_retention_ms, unit: 'd', min: 3600000, hint: 'Every probe result and hop trace. At least 1 hour.' });
      const m1 = durField('Per-minute summaries', { value: v.rollup_1m_retention_ms, unit: 'd', hint: 'Also how long alert history and path changes are kept.' });
      const h1 = durField('Per-hour summaries', { value: v.rollup_1h_retention_ms, unit: 'd' });
      return {
        body: h('div', { class: 'grid-fields' }, raw.el, m1.el, h1.el),
        collect() {
          const E = errorList();
          const out = { raw_retention_ms: E.num(raw) || 0, rollup_1m_retention_ms: E.num(m1) || 0, rollup_1h_retention_ms: E.num(h1) || 0 };
          if (out.raw_retention_ms > 0 && out.raw_retention_ms < 3600000) E.add('Individual results must be kept for at least 1 hour (or leave it blank to keep them forever).');
          return { value: out, errs: E.errs };
        },
      };
    },
  });
}

function enrichSection(onChange) {
  return section({
    key: 'enrich', title: 'Hop details', onChange,
    intro: 'Extra information shown for the routers along each path.',
    build(settings) {
      const v = settings.enrich.value || {};
      const rdns = checkField('Look up hop names (reverse DNS)', { checked: v.reverse_dns, hint: ' — sends a PTR query for each new hop address to your DNS resolver.' });
      return {
        body: h('div', null, rdns.el),
        collect() { return { value: { reverse_dns: rdns.get() }, errs: [] }; },
      };
    },
  });
}

/** Builds the editors; returns {els, load()}. onSaved(settings) runs after a save or revert. */
export function settingsEditors({ onSaved } = {}) {
  let alerts = null;
  let channelsSeen = '';
  const changed = (s, key) => {
    // the rule editor lists the configured channels: refresh it when they change
    const ch = JSON.stringify(s.channels || {});
    if (key === 'notify' && ch !== channelsSeen && alerts) alerts.render(s);
    channelsSeen = ch;
    onSaved && onSaved(s);
  };
  alerts = alertsSection(changed);
  const sections = [defaultsSection(changed), statusSection(changed), alerts, notifySection(changed), maintenanceSection(changed),
    heartbeatSection(changed), dnsSection(changed), retentionSection(changed), enrichSection(changed)];
  return {
    els: sections.map((s) => s.el),
    async load() {
      sections.forEach((s) => s.loading());
      try {
        const s = await api.settings();
        channelsSeen = JSON.stringify(s.channels || {});
        sections.forEach((x) => x.render(s));
      } catch (e) {
        sections.forEach((x) => x.error(e.status === 503 ? 'Settings cannot be edited on this server.' : e.message));
      }
    },
  };
}
