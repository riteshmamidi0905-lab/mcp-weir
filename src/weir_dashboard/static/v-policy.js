import { get } from './api.js';
import { h, icon } from './dom.js';
import { banner, chip, empty, labelChip, openRule, pageHead } from './ui.js';

const actionChip = (a) => h('span', { class: `vb vb-${a === 'OFF' ? 'allow' : a.toLowerCase()}`, title: a === 'HOLD' ? 'policy action: approve (hold for a person)' : a === 'DENY' ? 'policy action: deny' : 'rule is off' },
  a === 'OFF' ? h('span', null, 'OFF') : [icon(a === 'HOLD' ? 'hold' : 'deny', 13), h('span', null, a)]);

const parseLabel = (t) => { const [conf, integ] = String(t).split('/'); const R = { public: 0, internal: 1, secret: 2, trusted: 0, untrusted: 1 }; return { conf, integ, rank: [R[conf] ?? 0, R[integ] ?? 0] }; };

function settings(p, d) {
  const pol = p.policy;
  const rec = p.recorded_policies.map((r, i) => h('li', null, h('span', { class: 'mono' }, `${r.name || '–'} ${r.digest}`), ' ', p.matches_recorded?.[i] ? chip('MATCHES THIS FILE', 'ok') : chip('DIFFERS FROM THIS FILE', 'warn')));
  return h('div', { class: 'prov' },
    h('div', { class: 'card' }, h('div', { class: 'card-h' }, h('h3', null, 'Policy file')), h('div', { class: 'card-b' }, h('dl', { class: 'kv' },
      h('dt', null, 'Name'), h('dd', null, pol.name), h('dt', null, 'Digest'), h('dd', { class: 'mono', title: pol.digest_full }, pol.digest),
      h('dt', null, 'Internal domains'), h('dd', null, pol.internal_domains.join(', ') || '–'),
      h('dt', null, 'Approval lifetime'), h('dd', null, `${pol.approval_ttl_seconds} s`),
      h('dt', null, 'Argument size limit'), h('dd', null, `${pol.max_arg_bytes} bytes`),
      h('dt', null, 'Recorded in this database'), h('dd', null, rec.length ? h('ul', null, rec) : 'no sessions yet')),
      h('p', { class: 'muted small' }, 'A session records the digest of the policy it ran under. If a digest differs, this file is not the one that session ran with, and the settings below may not describe it.'))),
    h('div', { class: 'card' }, h('div', { class: 'card-h' }, h('h3', null, 'Rule actions (global)')), h('div', { class: 'tw' }, h('table', null, h('tbody',
      pol.rules.map((r) => h('tr', null, h('td', { class: 'mono' }, r.key), h('td', null, typeof r.action === 'number' ? String(r.action) : actionChip(r.action)))))))),
    h('div', { class: 'card' }, h('div', { class: 'card-h' }, h('h3', null, 'Tracker')), h('div', { class: 'card-b' }, h('dl', { class: 'kv' },
      Object.entries(pol.tracker).flatMap(([k, v]) => [h('dt', null, k), h('dd', null, String(v))])))),
    h('div', { class: 'card' }, h('div', { class: 'card-h' }, h('h3', null, 'Upstream servers')), h('div', { class: 'card-b' },
      pol.upstreams.length ? h('ul', { class: 'prov' }, pol.upstreams.map((u) => h('li', null, h('b', { class: 'mono' }, u.name), ` · program ${u.program}, ${u.args} argument${u.args === 1 ? '' : 's'}`, u.env_names.length ? ` · environment variables: ${u.env_names.join(', ')} (values are never shown)` : ''))) : 'none',
      h('p', { class: 'muted small' }, 'Command lines and environment values are not displayed: they can contain credentials.'))));
}

function tools(p) {
  return h('div', { class: 'prov' }, p.policy.tools.map((t) => h('article', { class: 'card' },
    h('div', { class: 'card-h' }, h('h3', { class: 'mono' }, t.name), h('span', { class: 'rules' }, chip(t.effect.toUpperCase(), t.effect === 'egress' ? 'warn' : ''), labelChip(parseLabel(t.result)))),
    h('div', { class: 'card-b' }, h('dl', { class: 'kv' },
      h('dt', null, 'Server'), h('dd', null, t.server),
      h('dt', null, 'Targets'), h('dd', null, t.targets.length ? t.targets.map((x) => `${x.arg} (${x.kind})`).join(', ') : 'none'),
      h('dt', null, 'Content arguments'), h('dd', null, t.content.length ? t.content.join(', ') : 'none'),
      h('dt', null, 'Result label rules'), h('dd', null, t.result_rules.length ? h('ul', null, t.result_rules.map((r) => h('li', { class: 'mono small' }, `${r.arg} ${r.glob ? 'matches ' + r.glob : r.equals ? '= ' + r.equals : ''} → ${r.label}${r.lowers ? ' (lowers)' : ''}`))) : 'none'),
      h('dt', null, 'Rule overrides'), h('dd', null, t.overrides.length ? t.overrides.map((o) => `${o.rule}: ${o.action}`).join(', ') : 'none'))))));
}

async function rulesTab(p) {
  const r = await get('rules');
  const rows = r.rules.map((x) => h('tr', { class: 'row', onclick: (e) => openRule(x.code, null, null, e.currentTarget) },
    h('td', null, h('button', { type: 'button', class: 'rc', onclick: (e) => { e.stopPropagation(); openRule(x.code, null, null, e.currentTarget); } }, x.code)),
    h('td', null, x.title), h('td', null, x.tier),
    h('td', null, h('span', { class: 'rules' }, x.configured.map((c) => actionChip(c.action)))),
    h('td', { class: 'num' }, x.fired_total ? String(x.fired_total) : '–')));
  return h('div', { class: 'card tw' }, h('table', null, h('thead', null, h('tr', null, ['Rule', 'What it is', 'Tier', 'Configured action', 'Fired here'].map((t, i) => h('th', { class: i === 4 ? 'num' : '' }, t)))), h('tbody', rows)),
    h('p', { class: 'muted small' }, `Actions: ${r.configured_from}.`));
}

function pinning(p) {
  const l = p.lock;
  const page = h('div', { class: 'prov' });
  if (!l.supplied) {
    page.append(banner('note', h('b', null, 'No lock file was given to the dashboard. '), 'Start it with --lock tools.lock.json to see which tool definitions that file pins. The audit log does not record whether the gateway ran with a lock file.'));
  } else if (!l.ok) {
    page.append(banner('bad', h('b', null, 'The lock file could not be read. '), l.error));
  } else {
    const missing = l.declared_not_pinned || [];
    page.append(h('div', { class: 'card' }, h('div', { class: 'card-b' },
      h('div', { class: 'big-status' }, missing.length ? icon('hold', 24) : icon('allow', 24), missing.length ? 'LOCK FILE IS INCOMPLETE' : 'TOOL DEFINITIONS PINNED ✓'),
      h('p', { class: 'muted' }, `${l.pinned.length} definitions are pinned in ${l.name}. This is what that file says; the audit log does not record which lock file the gateway ran with. A pin detects a definition that changed after review; it does not show the reviewed definition was harmless.`),
      missing.length ? banner('warn', 'Declared in the policy but not in the lock file (the gateway would deny them with R-PIN): ', missing.join(', ')) : null)));
    page.append(h('details', { class: 'card' }, h('summary', { class: 'card-h' }, h('h3', null, 'Advanced: pinned digests')), h('div', { class: 'tw' }, h('table', null, h('tbody', l.pinned.map((x) => h('tr', null, h('td', { class: 'mono' }, x.tool), h('td', { class: 'hashes wrap' }, x.digest))))))));
  }
  page.append(h('div', { class: 'card' }, h('div', { class: 'card-b' }, h('b', null, `${p.pin_mismatch_events} `), 'pin.mismatch event(s) recorded in this database.')));
  return page;
}

export const policyView = {
  title: () => 'Policy',
  async load(route) {
    const p = await get('policy');
    const tab = route.tab || 'settings';
    if (tab === 'rules') p.rules_node = await rulesTab(p);
    return p;
  },
  render(p, route) {
    const tab = route.tab || 'settings';
    const page = h('div', { class: 'page' }, pageHead('Policy', 'Read-only. Edit the policy file and restart the gateway to change anything; this page cannot.'));
    page.append(h('nav', { class: 'tabs', 'aria-label': 'Policy views' }, [['settings', 'Settings'], ['tools', 'Tools'], ['rules', 'Rules'], ['pinning', 'Tool pinning']].map(([k, l]) => h('a', { href: `#/policy/${k}`, 'aria-current': tab === k ? 'page' : null }, l))));
    if (p.error) page.append(banner('bad', h('b', null, 'The policy file could not be loaded. '), p.error));
    if (tab === 'rules') { page.append(p.rules_node); return page; }
    if (tab === 'pinning') { page.append(pinning(p)); return page; }
    if (!p.loaded) {
      page.append(h('div', { class: 'card' }, empty('No policy file was given', 'Start the dashboard with the policy the gateway runs with to see its tools, labels and rule actions.', 'weir-dashboard --db weir.db --policy examples/policies/workspace.toml')));
      return page;
    }
    page.append(tab === 'tools' ? tools(p) : settings(p));
    return page;
  },
};
