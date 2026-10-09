import { add, clear, h, icon } from './dom.js';
import { get } from './api.js';

const VERDICT_TITLE = {
  ALLOW: 'Weir allowed this call: no rule held or blocked it.',
  HOLD: 'Weir held this call (verdict APPROVE): a person can approve this exact call once.',
  DENY: 'Weir blocked this call (verdict DENY): an approval cannot override a deny.',
};

export function verdictBadge(v) {
  const k = String(v || '').toLowerCase();
  return h('span', { class: `vb vb-${k}`, title: VERDICT_TITLE[v] || '' }, icon(k === 'hold' ? 'hold' : k === 'deny' ? 'deny' : 'allow', 14), h('span', null, v));
}

export function sourceBadge(src) {
  if (!src) return null;
  const cls = src.kind === 'live-local' ? (src.live ? 'sb-live' : 'sb-idle') : `sb-${src.kind}`;
  return h('span', { class: `sb ${cls}`, title: src.detail, dataset: { source: src.kind } }, h('i'), src.label);
}

export function labelChip(l, grew = false) {
  if (!l) return h('span', { class: 'muted' }, '–');
  return h('span', { class: `lbl${grew ? ' grew' : ''}`, role: 'img', 'aria-label': `label ${l.conf}, ${l.integ}` },
    h('span', { class: 'c', 'data-r': l.rank[0] }, l.conf), h('span', { class: 'i', 'data-r': l.rank[1] }, l.integ));
}

export function chip(text, kind = '') { return h('span', { class: `chip ${kind ? 'chip-' + kind : ''}` }, text); }

export function argList(args) {
  if (!args || !args.length) return h('p', { class: 'muted small' }, 'no arguments recorded');
  return h('dl', { class: 'args' }, args.map((a) => h('div', { class: 'arg' }, h('dt', null, a.name),
    h('dd', null, a.kind === 'digest'
      ? h('span', { class: 'dg', title: 'The gateway stores content arguments only as length and digest', 'aria-label': `content not stored: ${a.len} characters, digest ${a.sha256}` }, `‹${a.len} chars · sha256 ${String(a.sha256).slice(0, 12)}›`)
      : a.text))));
}

export function ruleChip(hit, call) {
  const k = hit.verdict === 'DENY' ? 'deny' : hit.verdict === 'HOLD' ? 'hold' : '';
  return h('button', { type: 'button', class: `rc ${k}`, title: `${hit.title}. Open the rule inspector.`, onclick: (e) => openRule(hit.code, hit, call, e.currentTarget) },
    hit.code);
}

export function empty(title, text, code) {
  return h('div', { class: 'empty' }, h('b', null, title), text ? h('p', null, text) : null, code ? h('code', null, code) : null);
}

export function banner(kind, ...kids) {
  return h('div', { class: `banner banner-${kind}`, role: kind === 'bad' ? 'alert' : 'note' }, icon(kind === 'bad' ? 'deny' : kind === 'demo' ? 'demo' : 'info', 16), h('div', null, ...kids));
}

export function pageHead(title, sub, ...right) {
  return h('div', { class: 'page-head' }, h('div', null, h('h2', null, title), sub ? h('p', null, sub) : null), right.length ? h('div', { class: 'head-actions' }, ...right) : null);
}

// ------------------------------------------------------------------ sheet (modal side panel)
const sheet = () => document.getElementById('sheet');
let opener = null;

export function openSheet(title, body, from) {
  const d = sheet();
  opener = from || document.activeElement;
  document.getElementById('sheet-title').textContent = title;
  const b = clear(document.getElementById('sheet-body'));
  add(b, [body]);
  if (!d.open) d.showModal();
  d.querySelector('#sheet-close').focus();
}

export function initSheet() {
  const d = sheet();
  document.getElementById('sheet-close').addEventListener('click', () => d.close());
  d.addEventListener('click', (e) => { if (e.target === d) d.close(); });
  d.addEventListener('close', () => { if (opener && document.contains(opener)) opener.focus(); opener = null; });
}

let toastTimer = 0;
export function toast(text) {
  document.querySelectorAll('.toast').forEach((n) => n.remove());
  const t = h('div', { class: 'toast', role: 'status' }, text);
  document.body.append(t);
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.remove(), 5000);
}

export function announce(text) { document.getElementById('announce').textContent = text; }

// ------------------------------------------------------------------ rule inspector
let rulesCache = null;
export async function loadRules(force = false) {
  if (!rulesCache || force) rulesCache = await get('rules');
  return rulesCache;
}
export function invalidateRules() { rulesCache = null; }

export async function openRule(code, hit, call, from) {
  let data;
  try { data = await loadRules(true); } catch (e) { toast(`Could not load rules: ${e.message}`); return; }
  const r = data.rules.find((x) => x.code === code);
  const wrap = h('div', { class: 'sheet-b' });
  if (!r) { add(wrap, [h('p', null, 'Unknown rule.')]); openSheet(code, wrap, from); return; }
  const approvable = r.configured.some((c) => c.action === 'HOLD');
  const hardOnly = r.configured.length > 0 && r.configured.every((c) => c.action === 'DENY');
  add(wrap, [
    h('section', null, h('h3', null, 'What it does'), h('p', null, r.text), h('p', { class: 'muted small' }, `${r.title} · tier: ${r.tier}`)),
    h('section', null, h('h3', null, `Configured action (${r.configured_from})`),
      r.configured.length ? h('dl', { class: 'kv' }, r.configured.flatMap((c) => [h('dt', null, c.key), h('dd', null, h('span', { class: `vb vb-${c.action.toLowerCase() === 'off' ? 'allow' : c.action.toLowerCase()}` }, c.action === 'OFF' ? 'OFF' : c.action))])) : h('p', { class: 'muted' }, 'Not configurable.'),
      r.limit != null ? h('p', { class: 'small muted' }, `External-call limit per session: ${r.limit}`) : null,
      (r.overrides || []).length ? h('p', { class: 'small' }, 'Per-tool overrides: ', r.overrides.map((o) => `${o.tool} → ${o.rule || o.key} ${o.action}`).join('; ')) : null),
    h('section', null, h('h3', null, 'Can a person approve past it?'),
      h('p', null, hardOnly ? 'No. This rule denies and an approval cannot override a deny.' : approvable ? 'Only when its configured action is HOLD: a person can approve that exact call once. If another rule on the same call denies, the call is still blocked.' : 'Only if its configured action is HOLD.')),
    h('section', null, h('h3', null, 'Evidence it looks at'), h('p', null, r.evidence || '–')),
    h('section', null, h('h3', null, 'Seen in this database'),
      r.fired_total ? h('p', null, Object.entries(r.fired).map(([k, v]) => `${v} × ${k}`).join(' · ')) : h('p', { class: 'muted' }, 'Not recorded in any decision here.')),
  ]);
  if (hit) {
    add(wrap, [h('section', null, h('h3', null, `Why it fired${call ? ' on ' + call.call : ''}`), h('p', null, hit.message + '.'),
      hit.sources && hit.sources.length ? h('ul', { class: 'prov' }, hit.sources.map((s) => h('li', { class: 'src' },
        'Matched content from ', h('b', { class: 'mono' }, s.call), ` (${s.tool}, `, labelChip(s.label_obj), `) · ${s.kind} / ${s.via} · ${s.hits} hit${s.hits === 1 ? '' : 's'}`)))
        : h('p', { class: 'muted small' }, 'This rule reads the session state, not matched content, so there is no source call.')) ]);
  }
  openSheet(`${r.code}`, wrap, from);
}
