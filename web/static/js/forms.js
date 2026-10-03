// Form building blocks for the settings editors. The API speaks milliseconds; inputs show a
// friendlier unit. A blank input means "inherit": its placeholder shows the inherited value.
import { h } from './util.js';

export const UNITS = { ms: 1, s: 1000, min: 60000, h: 3600000, d: 86400000 };

/** ms -> number in unit, without float noise ("2.5", not "2.4999999"). */
export function inUnit(ms, unit) {
  if (ms == null || ms === '' || !Number.isFinite(Number(ms))) return '';
  return String(Number((Number(ms) / UNITS[unit]).toFixed(3)));
}

let uid = 0;
const nextId = () => 'fld-' + (++uid);

/** A labelled field around an input (or any control). */
export function field(label, control, hint, { cls } = {}) {
  const input = control.matches && control.matches('input,select,textarea') ? control : control.querySelector && control.querySelector('input,select,textarea');
  if (input && !input.id) input.id = nextId();
  return h('div', { class: 'field' + (cls ? ' ' + cls : '') },
    h('label', { for: input ? input.id : null }, label), control, hint ? h('span', { class: 'hint' }, hint) : null);
}

function withUnit(input, unit) {
  return h('div', { class: 'unit-input' }, input, h('span', { class: 'unit' }, unit));
}

/**
 * Number input in a display unit, backed by milliseconds.
 * get(): ms, null when blank (inherit), NaN when not a number.
 */
export function durField(label, { value, unit = 's', inherit, min, hint, required } = {}) {
  const el = h('input', { type: 'number', min: min != null ? min / UNITS[unit] : 0, step: 'any', inputmode: 'decimal', required: !!required,
    placeholder: inherit != null ? inUnit(inherit, unit) : '' });
  if (value) el.value = inUnit(value, unit);
  const wrap = field(label, withUnit(el, unit), hint);
  return {
    el: wrap, input: el, label,
    get() {
      const v = el.value.trim();
      if (v === '') return null;
      const n = Number(v);
      return Number.isFinite(n) && n >= 0 ? Math.round(n * UNITS[unit]) : NaN;
    },
    set(ms) { el.value = ms ? inUnit(ms, unit) : ''; },
  };
}

/** Plain number input. get(): number, null when blank, NaN when invalid. */
export function numField(label, { value, inherit, min, max, step = 'any', unit, hint, integer } = {}) {
  const el = h('input', { type: 'number', min, max, step: integer ? 1 : step, inputmode: integer ? 'numeric' : 'decimal',
    placeholder: inherit != null ? String(inherit) : '' });
  if (value != null && value !== '') el.value = String(value);
  const wrap = field(label, unit ? withUnit(el, unit) : el, hint);
  return {
    el: wrap, input: el, label,
    get() {
      const v = el.value.trim();
      if (v === '') return null;
      const n = Number(v);
      if (!Number.isFinite(n) || (integer && !Number.isInteger(n))) return NaN;
      return n;
    },
    set(v) { el.value = v == null ? '' : String(v); },
  };
}

export function textField(label, { value, placeholder, hint, required, maxlength } = {}) {
  const el = h('input', { type: 'text', placeholder, required: !!required, maxlength, autocomplete: 'off', autocapitalize: 'off', spellcheck: 'false' });
  if (value) el.value = value;
  return { el: field(label, el, hint), input: el, label, get: () => el.value.trim(), set: (v) => { el.value = v || ''; } };
}

export function selectField(label, options, { value, hint } = {}) {
  const el = h('select', null, options.map(([v, l]) => h('option', { value: v, selected: v === value }, l)));
  return { el: field(label, el, hint), input: el, label, get: () => el.value, set: (v) => { el.value = v; } };
}

export function checkField(label, { checked, hint } = {}) {
  const el = h('input', { type: 'checkbox', checked: !!checked });
  const wrap = h('label', { class: 'check' }, el, h('span', null, label, hint ? h('span', { class: 'hint' }, hint) : null));
  return { el: wrap, input: el, label, get: () => el.checked, set: (v) => { el.checked = !!v; } };
}

/** Where a setting comes from. */
export function sourceBadge(source) {
  return source === 'ui'
    ? h('span', { class: 'pill info nodot', title: 'Saved in pathwatch\'s database. It takes precedence over the config file until reverted.' }, 'Edited in UI · overrides config file')
    : h('span', { class: 'pill nodot', title: 'As set in the config file (or the built-in default).' }, 'From config file');
}

/** Collects field errors: check(f, value) records NaN values as "<label> must be a number". */
export function errorList() {
  const errs = [];
  return {
    errs,
    num(f, v = f.get()) { if (Number.isNaN(v)) errs.push(`${f.label}: enter a number (or leave it blank to inherit).`); return v; },
    add(m) { errs.push(m); },
  };
}

/** Sets key on obj to v, or deletes it when v is null (inherit). */
export function setOrDelete(obj, key, v) {
  if (v == null || Number.isNaN(v)) delete obj[key]; else obj[key] = v;
}

// ---------- alert rules ----------

export const RULE_TYPES = {
  http_failure: { label: 'HTTP failure', desc: 'HTTP probes fail several times in a row', params: ['consecutive'] },
  http_latency: { label: 'HTTP latency', desc: 'HTTP response time well above its baseline', params: ['metric', 'multiplier', 'min_delta_ms', 'sustain_ms', 'baseline_window_ms', 'min_baseline_ms'] },
  final_hop_loss: { label: 'End-to-end loss', desc: 'Packet loss to the destination above a threshold', params: ['threshold_pct', 'window_ms'] },
  path_degradation: { label: 'Path degradation', desc: 'A hop and everything after it degraded (not just ICMP rate limiting)', params: ['sustain_ms'] },
  tcp_failure: { label: 'TCP failure', desc: 'TCP connects fail several times in a row', params: ['consecutive'] },
  dns_failure: { label: 'DNS failure', desc: 'DNS probes fail several times in a row', params: ['consecutive'] },
  dns_latency: { label: 'DNS latency', desc: 'DNS response time well above its baseline', params: ['multiplier', 'min_delta_ms', 'sustain_ms', 'baseline_window_ms', 'min_baseline_ms'] },
  cert_expiry: { label: 'Certificate expiry', desc: 'An HTTPS certificate expires soon', params: ['warn_before_ms'] },
  route_change: { label: 'Route change', desc: 'The network path changed (one notification per change)', params: [] },
};

export const RULE_PARAMS = {
  consecutive: { label: 'Consecutive failures', kind: 'int', min: 1, max: 10000, hint: 'Failures in a row before it fires; as many successes clear it.' },
  metric: { label: 'Metric', kind: 'select', options: [['total', 'Total time'], ['ttfb', 'Time to first byte']] },
  multiplier: { label: 'Multiplier', kind: 'num', min: 1.01, step: 0.1, unit: '× baseline' },
  min_delta_ms: { label: 'Minimum increase', kind: 'dur', unit: 'ms', hint: 'Must also exceed the baseline by this much.' },
  sustain_ms: { label: 'Sustained for', kind: 'dur', unit: 'min' },
  baseline_window_ms: { label: 'Baseline window', kind: 'dur', unit: 'h' },
  min_baseline_ms: { label: 'Learning period', kind: 'dur', unit: 'h', hint: 'Inactive until this much history exists.' },
  threshold_pct: { label: 'Loss threshold', kind: 'num', min: 0.1, max: 100, step: 0.1, unit: '%' },
  window_ms: { label: 'Over a window of', kind: 'dur', unit: 'min' },
  warn_before_ms: { label: 'Warn before expiry', kind: 'dur', unit: 'd' },
};

/** A field for one rule parameter. inherit: value shown as placeholder (blank = inherit). */
export function paramField(key, { value, inherit, required } = {}) {
  const m = RULE_PARAMS[key];
  if (m.kind === 'select') {
    const opts = inherit != null ? [['', `Inherit (${(m.options.find((o) => o[0] === inherit) || [, inherit])[1]})`], ...m.options] : m.options;
    const f = selectField(m.label, opts, { value: value != null ? value : (inherit != null ? '' : m.options[0][0]) });
    return { ...f, get: () => f.input.value || null };
  }
  if (m.kind === 'dur') return durField(m.label, { value, unit: m.unit, inherit, hint: m.hint, required });
  return numField(m.label, { value, inherit, min: m.min, max: m.max, step: m.step, unit: m.unit, hint: m.hint, integer: m.kind === 'int' });
}

export function ruleTypeLabel(t) { return (RULE_TYPES[t] && RULE_TYPES[t].label) || t; }
