// "Silence" dialog opened from a target or an alert: the scope is prefilled (target, optionally one
// rule), the user picks a duration and an optional reason. Silenced alerts are still evaluated and
// shown in the feed, only their notifications are held back (docs/SPEC.md, Silences).
import { h } from '../util.js';
import { api } from '../api.js';

const PRESETS = [['1h', '1 hour', 3600000], ['4h', '4 hours', 14400000], ['24h', '24 hours', 86400000], ['custom', 'Custom', 0]];
let seq = 0;

/** opts: { targetId, targetName, rule (optional), onDone(silence) } */
export function openSilenceDialog({ targetId = null, targetName = null, rule = null, onDone } = {}) {
  const n = ++seq;
  const dlg = h('dialog', { 'aria-label': 'Silence notifications' });
  const err = h('div', { class: 'form-error', hidden: true, role: 'alert' });
  const ruleOnly = rule ? h('input', { type: 'checkbox', id: `sd-rule-${n}`, checked: true }) : null;
  const reason = h('input', { type: 'text', id: `sd-reason-${n}`, placeholder: 'e.g. ISP is working on it', maxlength: 200 });
  const customN = h('input', { type: 'number', min: 1, value: 2, style: { width: '70px' }, 'aria-label': 'Custom duration' });
  const customU = h('select', { 'aria-label': 'Custom duration unit' }, [['60000', 'minutes'], ['3600000', 'hours'], ['86400000', 'days']].map(([v, l], i) => h('option', { value: v, selected: i === 1 }, l)));
  const customBox = h('div', { class: 'row', style: { marginTop: '6px', alignItems: 'center' }, hidden: true }, customN, customU);
  let preset = '1h';
  const presetBtns = PRESETS.map(([k, l]) => h('button', { type: 'button', class: 'btn sm', 'aria-pressed': String(k === preset), dataset: { k },
    onclick: () => { preset = k; presetBtns.forEach((b) => b.setAttribute('aria-pressed', String(b.dataset.k === k))); customBox.hidden = k !== 'custom'; } }, l));
  const submit = h('button', { class: 'btn primary', type: 'submit' }, 'Silence');
  const scope = targetId == null ? 'every target' : (targetName || 'target #' + targetId);
  const form = h('form', null,
    h('h3', null, 'Silence notifications'),
    h('p', { class: 'muted small' }, `Alerts for ${scope} are still evaluated and listed, but not sent. A firing alert keeps its "resolved" notification.`),
    err,
    rule ? h('div', { class: 'field' }, h('label', { for: `sd-rule-${n}` }, ruleOnly, ' Only the ', h('strong', null, rule), ' rule'),
      h('span', { class: 'hint' }, 'Untick to silence every rule for ' + scope + '.')) : null,
    h('div', { class: 'field' }, h('span', { class: 'lbl' }, 'Duration'), h('div', { class: 'presets', role: 'group', 'aria-label': 'Duration' }, presetBtns), customBox),
    h('div', { class: 'field' }, h('label', { for: `sd-reason-${n}` }, 'Reason (optional)'), reason),
    h('div', { class: 'actions' },
      h('button', { class: 'btn', type: 'button', onclick: () => dlg.close() }, 'Cancel'),
      submit));
  form.addEventListener('submit', async (ev) => {
    ev.preventDefault(); err.hidden = true;
    let dur = (PRESETS.find(([k]) => k === preset) || [])[2];
    if (preset === 'custom') dur = Math.round(Number(customN.value) * Number(customU.value));
    if (!(dur > 0)) { err.textContent = 'Enter a positive duration.'; err.hidden = false; return; }
    submit.disabled = true;
    try {
      const s = await api.createSilence({ target_id: targetId, rule: ruleOnly && ruleOnly.checked ? rule : null, duration_ms: dur, reason: reason.value.trim() });
      dlg.close();
      if (onDone) onDone(s);
    } catch (e) { err.textContent = e.message; err.hidden = false; submit.disabled = false; }
  });
  dlg.append(form);
  dlg.addEventListener('close', () => dlg.remove());
  document.body.append(dlg);
  dlg.showModal();
  reason.focus();
}
