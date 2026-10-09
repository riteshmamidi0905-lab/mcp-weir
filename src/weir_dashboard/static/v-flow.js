import { get } from './api.js';
import { s, h, icon, fmtClock, fmtDateTime, ago } from './dom.js';
import { announce, argList, banner, chip, empty, labelChip, ruleChip, sourceBadge, verdictBadge } from './ui.js';
import { approvalCard, openDetails } from './v-approvals.js';

const STATUS_TEXT = {
  ALLOWED: 'ALLOWED', BLOCKED: 'BLOCKED', HELD: 'HELD', EXECUTED_AFTER_APPROVAL: 'RAN AFTER APPROVAL',
};

function toolState(c) {
  if (c.forwarded) return h('span', { class: 'tstate' }, 'FORWARDED');
  const ap = c.approval;
  if (c.status === 'HELD' && ap && ap.state === 'pending') return h('span', { class: 'tstate no' }, 'NOT FORWARDED · WAITING FOR APPROVAL');
  if (c.status === 'HELD' && ap && ap.consumed_by_call) return h('span', { class: 'tstate no' }, `NOT FORWARDED · REPEATED AS ${ap.consumed_by_call}`);
  return h('span', { class: 'tstate no' }, 'NOT FORWARDED');
}

function callRow(c, sid, base, isNew, focusCall) {
  const kind = c.verdict.toLowerCase();
  const wb = [];
  wb.push(h('div', { class: 'rules' }, verdictBadge(c.verdict), c.status === 'EXECUTED_AFTER_APPROVAL' ? chip('RAN AFTER APPROVAL', 'ok') : null));
  wb.push(h('p', { class: 'why' }, c.explain));
  if (c.rules.length) wb.push(h('div', { class: 'rules' }, c.rules.map((r) => ruleChip(r, c))));
  if (c.status === 'HELD' && c.approval && c.approval.state === 'pending') {
    wb.push(h('a', { class: 'btn btn-quiet', href: `#/approvals/${c.approval.id}` }, icon('hold', 14), 'Approval required: review and decide', icon('arrow', 14)));
  }
  if (c.verdict === 'DENY') wb.push(h('p', { class: 'ctxline' }, icon('lock', 14), 'Blocked. No approval can override this.'));
  const tool = [toolState(c)];
  if (c.forwarded) {
    tool.push(h('div', { class: 'ctxline' }, 'result ', labelChip(c.result_label)));
    tool.push(h('div', { class: 'ctxline' }, 'context ', labelChip(c.ctx_before), icon('arrow', 12), labelChip(c.ctx_after, c.ctx_before && c.ctx_after && c.ctx_before.text !== c.ctx_after.text)));
    if (c.is_error) tool.push(chip('TOOL RETURNED AN ERROR', 'warn'));
    if (c.uncertain) tool.push(chip('UPSTREAM FAILED · MAY HAVE TAKEN EFFECT', 'warn'));
  } else {
    tool.push(h('div', { class: 'ctxline' }, 'context stays ', labelChip(c.ctx_before)));
  }
  const key = `${sid}:${c.call}`;
  const details = h('details', { class: 'fdetails' }, h('summary', null, 'Details'), h('div', { class: 'inner' }, detailBody(c, sid, base)));
  if (openDetails.has(key)) details.open = true;
  details.addEventListener('toggle', () => { details.open ? openDetails.add(key) : openDetails.delete(key); });
  return h('article', { class: `fcall v-${kind}${isNew ? ' is-new' : ''}${focusCall === c.call ? ' focus-call' : ''}`, id: `call-${c.call}`, 'aria-label': `${c.call} ${c.tool} ${c.verdict}` },
    h('div', { class: 'fcall-h' }, h('b', null, c.call), h('span', null, fmtClock(c.ts)), h('span', null, `audit event #${c.seq}`), c.external ? chip('EXTERNAL', 'mute') : null),
    h('div', { class: 'fgrid' },
      h('div', { class: 'fcol' }, h('span', { class: 'role' }, 'AGENT'), h('div', { class: 'tool-name' }, c.tool), argList(c.args)),
      h('div', { class: 'fcol' }, h('span', { class: 'role' }, 'WEIR'), wb),
      h('div', { class: 'fcol' }, h('span', { class: 'role' }, 'TOOL'), c.server ? h('div', { class: 'tool-name' }, c.server) : null, tool)),
    details);
}

function detailBody(c, sid, base) {
  const out = [];
  if (c.rules.length) {
    out.push(h('div', null, c.rules.map((r) => h('div', { class: 'prov' },
      h('div', { class: 'rules' }, ruleChip(r, c), h('span', { class: 'muted small' }, `${r.title} · ${r.verdict === 'HOLD' ? 'configured to hold' : 'configured to deny'}`)),
      h('p', { class: 'why' }, r.message + '.'),
      r.sources.map((x) => h('div', { class: 'src' }, 'value matches ', h('a', { href: `${base}/flow?call=${x.call}` }, x.call), `(${x.tool}, `, labelChip(x.label_obj), `) · ${x.kind} / ${x.via} · ${x.hits} hit${x.hits === 1 ? '' : 's'}`))))));
  } else out.push(h('p', { class: 'muted' }, 'No rule fired.'));
  if (c.destinations.length) out.push(h('p', { class: 'small' }, h('b', null, 'Destinations: '), c.destinations.map((d) => `${d.kind} (${d.reason})`).join('; ')));
  if (c.approval) {
    const a = c.approval;
    out.push(h('p', { class: 'small' }, h('b', null, 'Approval '), h('span', { class: 'mono' }, a.id), ` · ${a.state}`,
      a.requested_by_call ? ` · requested by ${a.requested_by_call}` : '', a.consumed_by_call ? ` · used by ${a.consumed_by_call}` : '',
      a.resolved_by ? ` · resolved by ${a.resolved_by}` : ''));
  }
  out.push(h('p', { class: 'small muted' }, `Gateway verdict name: ${c.raw_verdict} · call hash ${c.call_hash || '–'}… · decided ${fmtDateTime(c.ts)}${c.ts_result ? ' · result recorded ' + fmtClock(c.ts_result) : ''}`));
  return out;
}

// ---------------------------------------------------------------------- tabs
function flowTab(d, base, route, prev) {
  const calls = d.calls;
  if (!calls.length) return h('div', { class: 'card' }, empty('No tool calls in this session yet', 'Calls appear here as the agent makes them.'));
  const known = prev ? new Set(prev.calls.map((c) => c.call)) : null;
  const focus = route.query.get('call');
  const wrap = h('div', null,
    h('div', { class: 'flowhead', 'aria-hidden': 'true' }, h('span', null, 'AGENT'), h('span', null, 'WEIR'), h('span', null, 'TOOL')),
    h('div', { class: 'flow' }, calls.map((c) => callRow(c, d.summary.id, base, known && !known.has(c.call), focus))));
  if (focus) queueMicrotask(() => document.getElementById(`call-${focus}`)?.scrollIntoView({ block: 'center' }));
  return wrap;
}

function provTab(d) {
  const edges = d.provenance;
  const caption = h('p', { class: 'muted small' }, 'Only relationships Weir recorded: a rule hit that names an earlier result as the place a matched value or destination appeared. A match means the tracker found that text there; it does not show how it travelled, and nothing else is inferred.');
  if (!edges.length) return h('div', { class: 'card' }, empty('No data-flow relationships were recorded', 'None of the calls in this session matched a value or destination from an earlier result.'), h('div', { class: 'card-b' }, caption));
  const order = d.calls.map((c) => c.call);
  const verdict = Object.fromEntries(d.calls.map((c) => [c.call, c.verdict]));
  const rowH = 48, top = 24, w = 600, rail = 280;
  const svg = s('svg', { class: 'provsvg', viewBox: `0 0 ${w} ${top + rowH * order.length}`, role: 'img', 'aria-label': `Data-flow between ${order.length} calls: ${edges.map((e) => `${e.from} to ${e.to}`).join(', ')}` });
  const y = (id) => top + rowH * order.indexOf(id) + 6;
  const colour = (v) => (v === 'DENY' ? 'var(--deny)' : v === 'HOLD' ? 'var(--hold)' : 'var(--allow)');
  svg.append(s('line', { x1: rail, y1: y(order[0]), x2: rail, y2: y(order[order.length - 1]), stroke: 'var(--line-2)', 'stroke-width': 2 }));
  order.forEach((id) => {
    const c = d.calls.find((x) => x.call === id);
    const t = s('text', { x: 4, y: y(id) + 1, fill: 'var(--text)', 'font-size': 13, 'font-family': 'var(--mono)', 'font-weight': 600 }); t.textContent = `${id}  ${c.tool}`; svg.append(t);
    const v = s('text', { x: 4, y: y(id) + 17, fill: colour(c.verdict), 'font-size': 11, 'font-weight': 700, 'letter-spacing': '0.05em' }); v.textContent = c.verdict; svg.append(v);
    svg.append(s('circle', { cx: rail, cy: y(id), r: 6, fill: colour(c.verdict) }));
  });
  edges.forEach((e, i) => {
    if (!order.includes(e.from) || !order.includes(e.to)) return;
    const y0 = y(e.from), y1 = y(e.to), bend = rail + 34 + 20 * Math.min(5, Math.abs(order.indexOf(e.to) - order.indexOf(e.from)));
    const col = colour(e.verdict);
    svg.append(s('path', { d: `M ${rail + 6} ${y0} C ${bend} ${y0}, ${bend} ${y1}, ${rail + 9} ${y1}`, fill: 'none', stroke: col, 'stroke-width': 1.8, 'stroke-dasharray': e.verdict === 'DENY' ? null : '5 3' }));
    svg.append(s('path', { d: `M ${rail + 7} ${y1} L ${rail + 15} ${y1 - 4.5} L ${rail + 15} ${y1 + 4.5} Z`, fill: col }));
    const lab = s('text', { x: bend + 8, y: (y0 + y1) / 2 + 4 + (i % 2) * 13, fill: 'var(--text-2)', 'font-size': 11, 'font-family': 'var(--mono)' }); lab.textContent = `${e.rule} ×${e.hits}`; svg.append(lab);
  });
  const rows = edges.map((e) => h('tr', null, h('td', { class: 'mono' }, e.from), h('td', null, e.source_tool, ' ', labelChip(parseLabel(e.source_label))), h('td', { class: 'mono' }, e.to), h('td', null, e.to_tool), h('td', null, h('span', { class: 'rc' }, e.rule)), h('td', null, `${e.kind} / ${e.via}`), h('td', { class: 'num' }, String(e.hits))));
  return h('div', { class: 'prov' }, caption, h('div', { class: 'card' }, h('div', { class: 'card-b' }, svg)),
    h('div', { class: 'card tw' }, h('table', null, h('thead', null, h('tr', null, ['Source call', 'Source result', 'Used in', 'Tool', 'Rule', 'Matched by', 'Hits'].map((t, i) => h('th', { class: i === 6 ? 'num' : '' }, t)))), h('tbody', null, rows))));
}

function parseLabel(text) {
  const [conf, integ] = String(text).split('/');
  const R = { public: 0, internal: 1, secret: 2, trusted: 0, untrusted: 1 };
  return { conf, integ, rank: [R[conf] ?? 0, R[integ] ?? 0] };
}

function ctxTab(d) {
  const L = d.lattice;
  const visits = new Map(); // "conf/integ" -> [call ids that first raised the context to it]
  visits.set(L.bottom, ['start']);
  d.ctx_steps.forEach((st) => { if (st.grew && st.after) { const k = st.after.text; visits.set(k, [...(visits.get(k) || []), st.call]); } });
  const cur = d.summary.ctx.text;
  const cell = (conf, integ) => {
    const k = `${conf}/${integ}`;
    return h('div', { class: `lcell${visits.has(k) ? ' on' : ''}${cur === k ? ' cur' : ''}`, role: 'group', 'aria-label': `${k}${visits.has(k) ? ', reached' : ', not reached'}${cur === k ? ', current' : ''}` },
      h('b', null, k), h('div', { class: 'visits' }, (visits.get(k) || []).map((v) => h('span', null, v))), cur === k ? h('span', { class: 'small' }, 'current') : null);
  };
  const grid = h('div', { class: 'lattice' },
    h('span'), ...L.integ.map((i) => h('span', { class: 'ax' }, i)),
    ...[...L.conf].reverse().flatMap((c) => [h('span', { class: 'ax' }, c), ...L.integ.map((i) => cell(c, i))]));
  const rows = d.ctx_steps.map((st) => h('tr', null, h('td', { class: 'mono' }, st.call), h('td', { class: 'mono' }, st.tool), h('td', null, labelChip(st.before)), h('td', null, labelChip(st.after, st.grew)),
    h('td', null, st.grew ? 'raised by this result' : st.forwarded ? 'unchanged' : 'not forwarded: unchanged')));
  return h('div', { class: 'prov' },
    h('p', { class: 'muted small' }, `The session context is the join of the labels of everything Weir has returned to the agent. It starts at ${L.bottom} and only grows: confidentiality ${L.conf.join(' < ')}, integrity ${L.integ.join(' < ')}. Boxes show the states this session reached and the call that first raised it to each.`),
    h('div', { class: 'card' }, h('div', { class: 'card-b' }, grid)),
    d.ctx_steps.length ? h('div', { class: 'card tw' }, h('table', null, h('thead', null, h('tr', null, ['Call', 'Tool', 'Context before', 'Context after', 'Note'].map((t) => h('th', null, t)))), h('tbody', null, rows))) : null);
}

async function eventsTab(ds, sid) {
  const a = await get(`d/${ds}/audit`, { session: sid, limit: 200 });
  const rows = a.latest.map((e) => h('tr', { class: e.broken ? 'bad' : '' }, h('td', { class: 'num mono' }, `#${e.seq}`), h('td', null, fmtClock(e.ts)), h('td', { class: 'mono' }, e.kind), h('td', { class: 'wrap' }, e.summary), h('td', { class: 'hashes' }, e.hash)));
  return h('div', { class: 'card tw' }, h('table', null, h('thead', null, h('tr', null, ['Event', 'Time', 'Kind', 'Summary', 'Hash'].map((t) => h('th', null, t)))), h('tbody', rows)));
}

// ---------------------------------------------------------------------- page
export function sessionView(ds, base, backHref, backLabel) {
  return {
    title: (route, data) => (data ? `Session ${data.summary.id}` : 'Session'),
    async load(route) {
      const sid = route.sid;
      const data = await get(`d/${ds}/sessions/${encodeURIComponent(sid)}`);
      const tab = route.tab;
      if (tab === 'approvals') data.session_approvals = (await get(`d/${ds}/approvals`)).approvals.filter((a) => a.session === sid);
      if (tab === 'events') data.events_html = await eventsTab(ds, sid);
      return data;
    },
    render(d, route, rerender, prev) {
      const sm = d.summary;
      const tab = route.tab;
      if (prev && prev.summary.id === sm.id) {
        const known = new Set(prev.calls.map((c) => c.call));
        const fresh = d.calls.filter((c) => !known.has(c.call));
        if (fresh.length) announce(fresh.map((c) => `New ${c.verdict}: ${c.call} ${c.tool}`).join('. '));
      }
      const page = h('div', { class: 'page' });
      page.append(h('div', null, h('a', { href: backHref, class: 'small' }, `← ${backLabel}`)));
      page.append(h('div', { class: 'page-head' }, h('div', null, h('h2', { class: 'mono wrap' }, sm.id), h('p', null, `policy ${sm.policy_name || '–'} ${sm.policy_sha || ''}`)), h('div', { class: 'tools' }, sourceBadge(sm.source))));
      if (sm.source.kind !== 'live-local') {
        const ex = sm.source.extra || {};
        page.append(banner(sm.source.kind === 'synthetic-demo' ? 'demo' : 'note', h('b', null, sm.source.label + '. '), sm.source.detail,
          ex.arm ? h('div', null, h('b', null, 'Arm: '), ex.arm) : null,
          ex.approver ? h('div', null, h('b', null, 'Approver: '), ex.approver) : null,
          ex.agent ? h('div', null, h('b', null, 'Agent: '), ex.agent) : null));
      }
      if (sm.approver_kinds.some((k) => k.startsWith('auto')) && sm.source.kind === 'live-local') {
        page.append(banner('warn', h('b', null, 'Some approvals here were resolved by a programmatic approver, not a person. '), 'The audit log records them with the name “auto”.'));
      }
      if (sm.state_row_matches_audit === false) page.append(banner('warn', h('b', null, 'The stored session row and the audit events disagree about the context label. '), 'The page shows the audit events; the row cannot be verified from here.'));
      if (sm.malformed_events) page.append(banner('bad', h('b', null, `${sm.malformed_events} audit event(s) could not be parsed. `), 'They are skipped in the views below.'));
      page.append(h('div', { class: 'card' }, h('div', { class: 'card-b' }, h('div', { class: 'rules' },
        h('span', { class: 'label' }, 'context'), labelChip(sm.ctx),
        h('span', { class: 'counts' }, h('span', null, `${sm.counts.calls} calls`), h('span', null, icon('allow', 14), sm.counts.allow, ' allow'), h('span', null, icon('hold', 14), sm.counts.hold, ' hold'), h('span', null, icon('deny', 14), sm.counts.deny, ' deny')),
        sm.pending_approvals ? chip(`${sm.pending_approvals} approval${sm.pending_approvals === 1 ? '' : 's'} waiting`, 'warn') : null,
        sm.audit.chain_ok ? chip('CHAIN VERIFIED', 'ok') : chip('CHAIN VERIFICATION FAILED', 'bad'),
        h('span', { class: 'muted small' }, `last activity ${ago(sm.last_activity)}`)))));
      const tabs = [['flow', 'Flow'], ['provenance', 'Provenance'], ['context', 'Context'], ['approvals', 'Approvals'], ['events', 'Audit events']];
      page.append(h('nav', { class: 'tabs', 'aria-label': 'Session views' }, tabs.map(([k, label]) => h('a', { href: `${base}/${k}`, 'aria-current': tab === k ? 'page' : null }, label))));
      if (tab === 'provenance') page.append(provTab(d));
      else if (tab === 'context') page.append(ctxTab(d));
      else if (tab === 'approvals') {
        const list = d.session_approvals || [];
        page.append(...(list.length ? list.map((a) => approvalCard(a, rerender)) : [h('div', { class: 'card' }, empty('No approvals in this session', 'Holds show up here, and in the Approvals view while they are waiting.'))]));
      } else if (tab === 'events') page.append(d.events_html);
      else page.append(flowTab(d, base, route, prev));
      return page;
    },
  };
}
