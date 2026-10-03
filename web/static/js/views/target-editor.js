// Target editor: create or edit a target: host (FQDN, IPv4 or IPv6), hop trace, HTTP and TCP
// probes with their intervals, timeouts and retries, and per-target alert thresholds.
// Config-file targets are edited in place: the edits are stored on the server and override the
// file until reverted.
import { h, clear } from '../util.js';
import { api } from '../api.js';
import { confirmDialog } from '../ui.js';
import {
  durField, numField, textField, selectField, checkField, errorList, setOrDelete,
  sourceBadge, RULE_TYPES, paramField, ruleTypeLabel,
} from '../forms.js';

const IPV4 = /^\d{1,3}(\.\d{1,3}){3}$/;

/** Instant client-side guess of what the host is (the server has the final word). */
export function hostKind(s) {
  s = (s || '').trim();
  if (!s) return null;
  if (/:\/\//.test(s)) return 'url';
  if (IPV4.test(s)) return 'ipv4';
  // hostnames never contain ':'; one colon is host:port (the server explains), two or more is IPv6
  if ((s.match(/:/g) || []).length > 1) return 'ipv6';
  return 'hostname';
}
export const KIND_LABEL = { ipv4: 'IPv4 address', ipv6: 'IPv6 address', hostname: 'Hostname (FQDN)', url: 'URL' };

const clone = (o) => JSON.parse(JSON.stringify(o));

/**
 * Opens the editor. id = null creates a target. onSaved(target) runs after a successful save
 * (target = the API target object, or null after a revert).
 */
export function openTargetEditor({ id = null, onSaved } = {}) {
  const dlg = h('dialog', { class: 'wide', 'aria-label': id ? 'Edit target' : 'Add target' });
  const body = h('div', { class: 'dlg-body' }, h('div', { class: 'state-msg' }, h('span', { class: 'spinner' }), 'Loading…'));
  dlg.append(body);
  dlg.addEventListener('close', () => dlg.remove());
  document.body.appendChild(dlg);
  dlg.showModal();
  Promise.all([api.settings({ quiet: true }), id ? api.targetConfig(id) : null])
    .then(([settings, cfg]) => build(dlg, body, settings, cfg, id, onSaved))
    .catch((e) => {
      clear(body).append(h('div', { class: 'form-error' }, 'Could not load the target settings: ' + e.message),
        h('div', { class: 'actions' }, h('button', { class: 'btn', type: 'button', onclick: () => dlg.close() }, 'Close')));
    });
  return dlg;
}

function build(dlg, body, settings, cfg, id, onSaved) {
  const D = settings.defaults.value;
  const maxRetries = settings.max_retries || 10;
  const isConfig = cfg && cfg.source === 'config';
  const def = cfg ? clone(cfg.target) : { name: '', host: '', probes: [{ type: 'icmp-trace' }], alerts: {} };
  def.probes = def.probes || [];
  const rules = (settings.alerts.value.rules || []);

  const err = h('div', { class: 'form-error', hidden: true, role: 'alert' });

  // ---------- target ----------
  const name = textField('Name', { value: def.name, required: true, maxlength: 63, placeholder: 'my-isp',
    hint: isConfig ? 'Defined in the config file; rename it there.' : 'Renaming keeps the history.' });
  if (isConfig) name.input.disabled = true;
  const host = textField('Host', { value: def.host, required: true, placeholder: 'example.com, 203.0.113.7 or 2001:db8::7' });
  const kindEl = h('span', { class: 'host-kind' });
  const checkOut = h('div', { class: 'check-out', 'aria-live': 'polite' });
  const checkBtn = h('button', { class: 'btn sm', type: 'button', onclick: () => checkHost() }, 'Check');
  host.input.after(kindEl);
  host.el.append(h('div', { class: 'host-tools' }, checkBtn, checkOut));
  function renderKind() {
    const k = hostKind(host.input.value);
    clear(kindEl);
    if (!k) return;
    kindEl.append(h('span', { class: 'pill nodot ' + (k === 'url' ? 'crit' : 'info') }, k === 'url' ? 'Enter only the host, not a URL' : KIND_LABEL[k]));
    if (k === 'ipv6') kindEl.append(h('span', { class: 'hint' }, ' Hop tracing is IPv4-only for now; HTTP and TCP probes work over IPv6.'));
  }
  async function checkHost() {
    const v = host.input.value.trim();
    clear(checkOut);
    if (!v) return;
    checkBtn.disabled = true;
    try {
      const r = await api.resolve(v);
      if (!r.valid) { checkOut.append(h('span', { class: 'bad' }, r.error)); return; }
      if (r.host !== v) host.input.value = r.host;
      if (r.resolve_error) { checkOut.append(h('span', { class: 'bad' }, `Does not resolve: ${r.resolve_error}`)); return; }
      const v4 = r.addresses.some((a) => !a.includes(':'));
      checkOut.append(h('span', { class: 'good' }, r.kind === 'hostname' ? `Resolves to ${r.addresses.join(', ')}` : `${KIND_LABEL[r.kind]} OK`));
      if (r.kind === 'hostname' && !v4) checkOut.append(h('span', { class: 'hint' }, ' No IPv4 address: hop tracing will not run (HTTP and TCP probes will).'));
      if (r.kind === 'hostname') checkOut.append(h('span', { class: 'hint' }, ` Re-resolved every ${Math.round((def.path_rediscovery_ms || D.path_rediscovery_ms) / 60000)} min; the IPv4 address is preferred.`));
    } catch (e) {
      checkOut.append(h('span', { class: 'bad' }, e.message));
    } finally { checkBtn.disabled = false; }
  }
  host.input.addEventListener('input', () => { renderKind(); clear(checkOut); });
  renderKind();

  // ---------- hop trace ----------
  const icmpOrig = def.probes.find((p) => p.type === 'icmp-trace');
  const icmpOn = checkField('Trace the path (ICMP, mtr-style)', { checked: !cfg || !!icmpOrig });
  const icmpInterval = durField('Interval', { value: icmpOrig && icmpOrig.interval_ms, unit: 's', inherit: D.icmp_interval_ms, min: 500 });
  const icmpTimeout = durField('Timeout', { value: icmpOrig && icmpOrig.timeout_ms, unit: 's', inherit: D.icmp_timeout_ms, hint: 'Capped at the interval.' });
  const maxHops = numField('Max hops', { value: def.max_hops, inherit: D.max_hops, min: 1, max: 64, integer: true });
  const rediscovery = durField('Re-resolve and rediscover every', { value: def.path_rediscovery_ms, unit: 'min', inherit: D.path_rediscovery_ms });
  const icmpBox = h('div', { class: 'grid-fields' }, icmpInterval.el, icmpTimeout.el, maxHops.el, rediscovery.el);
  const syncIcmp = () => { icmpBox.classList.toggle('disabled', !icmpOn.get()); icmpBox.querySelectorAll('input').forEach((i) => { i.disabled = !icmpOn.get(); }); };
  icmpOn.input.addEventListener('change', syncIcmp);
  syncIcmp();

  // ---------- HTTP / TCP probes ----------
  const httpList = h('div', { class: 'probe-list' });
  const tcpList = h('div', { class: 'probe-list' });
  const probes = []; // {type, orig, row, collect()}

  function retriesField(p) {
    return numField('Retries', { value: p.retries, inherit: D.retries, min: 0, max: maxRetries, integer: true, hint: 'Before a failure is recorded' });
  }
  function removeBtn(item) {
    return h('button', { class: 'btn sm danger', type: 'button', title: 'Remove this probe', onclick: () => { probes.splice(probes.indexOf(item), 1); item.row.remove(); emptyNotes(); } }, 'Remove');
  }
  function addHTTP(p = { type: 'http' }) {
    const url = textField('URL', { value: p.url, required: true, placeholder: 'https://example.com/' });
    url.input.setAttribute('inputmode', 'url');
    const method = selectField('Method', [['GET', 'GET'], ['HEAD', 'HEAD']], { value: (p.method || 'GET').toUpperCase() });
    const expect = textField('Expected status', { value: (p.expect_status || []).join(', '), placeholder: 'any 1xx–3xx', hint: 'Comma-separated, e.g. 200, 301' });
    const interval = durField('Interval', { value: p.interval_ms, unit: 's', inherit: D.http_interval_ms, min: 1000 });
    const timeout = durField('Timeout', { value: p.timeout_ms, unit: 's', inherit: D.http_timeout_ms });
    const retries = retriesField(p);
    const follow = checkField('Follow redirects', { checked: p.follow_redirects });
    const insecure = checkField('Skip TLS verification', { checked: p.insecure_skip_verify, hint: ' (self-signed internal hosts)' });
    const item = { type: 'http', orig: p };
    item.row = h('div', { class: 'probe-row' },
      h('div', { class: 'probe-head' }, h('strong', null, 'HTTP probe'), h('span', { class: 'grow' }), removeBtn(item)),
      h('div', { class: 'grid-fields' }, h('div', { class: 'span2' }, url.el), method.el, expect.el, interval.el, timeout.el, retries.el),
      h('div', { class: 'checks' }, follow.el, insecure.el));
    item.collect = (E) => {
      const o = clone(p);
      o.type = 'http';
      o.url = url.get();
      if (!o.url) E.add('HTTP probe: URL is required.');
      o.method = method.get();
      const ex = expect.get();
      if (ex) {
        const codes = ex.split(/[\s,;]+/).filter(Boolean).map(Number);
        if (codes.some((c) => !Number.isInteger(c))) E.add('HTTP probe: expected status must be numbers such as 200, 301.');
        o.expect_status = codes;
      } else delete o.expect_status;
      setOrDelete(o, 'interval_ms', E.num(interval));
      setOrDelete(o, 'timeout_ms', E.num(timeout));
      setOrDelete(o, 'retries', E.num(retries));
      setOrDelete(o, 'follow_redirects', follow.get() || null);
      setOrDelete(o, 'insecure_skip_verify', insecure.get() || null);
      return o;
    };
    probes.push(item);
    httpList.append(item.row);
    emptyNotes();
    return item;
  }
  function addTCP(p = { type: 'tcp' }) {
    const port = numField('Port', { value: p.port, inherit: 443, min: 1, max: 65535, integer: true });
    const interval = durField('Interval', { value: p.interval_ms, unit: 's', inherit: D.tcp_interval_ms, min: 1000 });
    const timeout = durField('Timeout', { value: p.timeout_ms, unit: 's', inherit: D.tcp_timeout_ms });
    const retries = retriesField(p);
    const item = { type: 'tcp', orig: p };
    item.row = h('div', { class: 'probe-row' },
      h('div', { class: 'probe-head' }, h('strong', null, 'TCP connect'), h('span', { class: 'grow' }), removeBtn(item)),
      h('div', { class: 'grid-fields' }, port.el, interval.el, timeout.el, retries.el));
    item.collect = (E) => {
      const o = clone(p);
      o.type = 'tcp';
      setOrDelete(o, 'port', E.num(port));
      setOrDelete(o, 'interval_ms', E.num(interval));
      setOrDelete(o, 'timeout_ms', E.num(timeout));
      setOrDelete(o, 'retries', E.num(retries));
      return o;
    };
    probes.push(item);
    tcpList.append(item.row);
    emptyNotes();
    return item;
  }
  const httpEmpty = h('p', { class: 'muted small' }, 'No HTTP probe. Add one to measure DNS, connect, TLS and time-to-first-byte of real requests.');
  const tcpEmpty = h('p', { class: 'muted small' }, 'No TCP probe. Add one for destinations that do not answer ping.');
  function emptyNotes() {
    httpEmpty.hidden = probes.some((p) => p.type === 'http');
    tcpEmpty.hidden = probes.some((p) => p.type === 'tcp');
  }
  for (const p of def.probes) {
    if (p.type === 'http') addHTTP(p);
    else if (p.type === 'tcp') addTCP(p);
  }
  emptyNotes();

  // ---------- per-target alert thresholds ----------
  const alerts = def.alerts || {};
  const disabled = new Set(alerts.disable || []);
  const overrides = alerts.override || {};
  const ruleRows = [];
  const alertBox = h('div', { class: 'rule-overrides' });
  if (!rules.length) alertBox.append(h('p', { class: 'muted small' }, 'No alert rules are configured. Add rules on the Settings page.'));
  for (const r of rules) {
    const meta = RULE_TYPES[r.type] || { params: [] };
    const on = checkField(r.name, { checked: !disabled.has(r.name) && r.enabled !== false, hint: ` · ${ruleTypeLabel(r.type)}` });
    if (r.enabled === false) { on.input.disabled = true; on.el.title = 'Disabled for all targets (Settings → Alert rules)'; }
    const o = overrides[r.name] || {};
    const fields = meta.params.map((k) => ({ k, f: paramField(k, { value: o[k], inherit: r[k] }) }));
    const grid = h('div', { class: 'grid-fields' }, fields.map((x) => x.f.el));
    const row = h('div', { class: 'rule-row' }, on.el, fields.length ? grid : null);
    const sync = () => grid.querySelectorAll('input,select').forEach((i) => { i.disabled = !on.get(); });
    on.input.addEventListener('change', sync);
    sync();
    ruleRows.push({ r, on, fields, orig: o });
    alertBox.append(row);
  }
  const alertDetails = h('details', { class: 'section', open: Object.keys(overrides).length > 0 || disabled.size > 0 },
    h('summary', null, 'Alert thresholds for this target', h('span', { class: 'muted small' }, ' — blank = the rule\'s global value')),
    alertBox);

  // ---------- layout ----------
  const title = h('div', { class: 'dlg-title' }, h('h3', null, id ? 'Edit target' : 'Add target'),
    isConfig ? sourceBadge(cfg.overridden ? 'ui' : 'file') : null);
  const intro = isConfig ? h('p', { class: 'muted small' }, 'This target is defined in the config file. Changes are saved in pathwatch and override the file for this target until you revert them.') : null;
  const save = h('button', { class: 'btn primary', type: 'submit' }, id ? 'Save' : 'Add target');
  const revert = isConfig && cfg.overridden ? h('button', { class: 'btn', type: 'button', onclick: doRevert }, 'Revert to config file') : null;
  const form = h('form', { method: 'dialog', novalidate: true },
    title, intro, err,
    h('fieldset', { class: 'section' }, h('legend', null, 'Target'), h('div', { class: 'grid-fields' }, name.el, h('div', { class: 'span2' }, host.el))),
    h('fieldset', { class: 'section' }, h('legend', null, 'Hop trace'), icmpOn.el, icmpBox,
      h('p', { class: 'hint' }, 'Hop probes are never retried: an unanswered probe is the packet loss being measured.')),
    h('fieldset', { class: 'section' }, h('legend', null, 'HTTP probes'), httpEmpty, httpList,
      h('button', { class: 'btn sm', type: 'button', onclick: () => addHTTP({ type: 'http', url: suggestURL() }).row.querySelector('input').focus() }, '+ Add HTTP probe')),
    h('fieldset', { class: 'section' }, h('legend', null, 'TCP probes'), tcpEmpty, tcpList,
      h('button', { class: 'btn sm', type: 'button', onclick: () => addTCP().row.querySelector('input').focus() }, '+ Add TCP probe')),
    alertDetails,
    h('div', { class: 'actions sticky' }, revert, h('span', { class: 'grow' }), h('button', { class: 'btn', type: 'button', onclick: () => dlg.close() }, 'Cancel'), save));
  clear(body).append(form);
  if (!id) name.input.focus();

  function suggestURL() {
    const k = hostKind(host.input.value);
    // brackets off for the check; an FQDN's trailing dot does not belong in a URL (TLS names)
    const hv = host.input.value.trim().replace(/^\[|\]$/g, '').replace(/\.$/, '');
    if (!hv || k === 'url') return '';
    return 'https://' + (k === 'ipv6' ? `[${hv}]` : hv) + '/';
  }

  function collect() {
    const E = errorList();
    const out = clone(def);
    out.name = name.get();
    out.host = host.get();
    if (!out.name) E.add('Name is required.');
    if (!out.host) E.add('Host is required.');
    if (hostKind(out.host) === 'url') E.add('Host: enter only the host name or IP address; put the URL in an HTTP probe.');
    setOrDelete(out, 'max_hops', E.num(maxHops));
    setOrDelete(out, 'path_rediscovery_ms', E.num(rediscovery));
    const list = [];
    if (icmpOn.get()) {
      const ic = clone(icmpOrig || {});
      ic.type = 'icmp-trace';
      setOrDelete(ic, 'interval_ms', E.num(icmpInterval));
      setOrDelete(ic, 'timeout_ms', E.num(icmpTimeout));
      list.push(ic);
    }
    for (const p of probes) list.push(p.collect(E));
    // keep probe types this editor does not know about
    for (const p of def.probes) if (!['icmp-trace', 'http', 'tcp'].includes(p.type)) list.push(p);
    if (!list.length) E.add('Enable the hop trace or add an HTTP or TCP probe.');
    out.probes = list;
    // rebuilt from the current rules, so settings for rules that no longer exist are dropped
    const dis = [];
    const ov = {};
    for (const { r, on, fields } of ruleRows) {
      if (!on.get() && r.enabled !== false) { dis.push(r.name); continue; }
      const o = {};
      for (const { k, f } of fields) setOrDelete(o, k, E.num(f));
      if (Object.keys(o).length) ov[r.name] = o;
    }
    out.alerts = {};
    if (dis.length) out.alerts.disable = dis;
    if (Object.keys(ov).length) out.alerts.override = ov;
    return { out, errs: E.errs };
  }

  form.addEventListener('submit', async (ev) => {
    ev.preventDefault();
    err.hidden = true;
    const { out, errs } = collect();
    if (errs.length) return showErr(errs);
    save.disabled = true;
    try {
      const t = id ? await api.updateTarget(id, out) : await api.createTarget(out);
      dlg.close();
      onSaved && onSaved(t);
    } catch (e) {
      showErr([e.message || 'Could not save the target.']);
    } finally { save.disabled = false; }
  });
  async function doRevert() {
    const ok = await confirmDialog({ title: 'Revert to config file?', message: `Discard the changes made in the UI to "${def.name}" and use its definition from the config file again?`, confirmLabel: 'Revert' });
    if (!ok) return;
    try {
      await api.revertTarget(id);
      dlg.close();
      onSaved && onSaved(null);
    } catch (e) { showErr([e.message]); }
  }
  function showErr(list) {
    clear(err).append(list.length === 1 ? list[0] : h('ul', null, list.map((m) => h('li', null, m))));
    err.hidden = false;
    err.scrollIntoView({ block: 'nearest' });
  }
}
