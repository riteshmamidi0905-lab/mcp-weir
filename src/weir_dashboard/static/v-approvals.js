import { get, post, ApiError } from './api.js';
import { h, icon, fmtDateTime, ago, until } from './dom.js';
import { argList, empty, labelChip, pageHead, ruleChip, toast, announce, banner, chip } from './ui.js';

const confirming = new Map(); // approval id -> 'approve' | 'deny' (survives a re-render)
const results = new Map();    // approval id -> last message from the server
export const openDetails = new Set();

const STATE_TEXT = {
  pending: ['WAITING FOR A PERSON', 'warn'],
  approved: ['APPROVED · NOT YET USED', 'ok'],
  denied: ['DENIED', 'bad'],
  consumed: ['USED ONCE', 'mute'],
  expired: ['EXPIRED', 'mute'],
};

export function approvalCard(a, rerender) {
  const pending = a.state === 'pending';
  const [stext, skind] = STATE_TEXT[a.state] || [a.state.toUpperCase(), 'mute'];
  const head = h('div', { class: 'ap-h' },
    icon('hold', 16), h('span', null, pending ? 'APPROVAL REQUIRED' : 'APPROVAL'),
    chip(stext, skind), h('span', { class: 'mono' }, a.id),
    pending ? h('span', { class: 'sp', 'data-expires': a.expires }, until(a.expires)) : h('span', { class: 'sp' }, a.state === 'expired' ? `expired ${ago(a.expires)}` : ''));
  const reasons = h('div', { class: 'prov' },
    a.rules.map((r) => h('div', null, h('div', { class: 'rules' }, ruleChip({ code: r.code, title: r.title, verdict: 'HOLD', message: '' }, null)), null)),
    a.reasons.map((m) => h('p', { class: 'why' }, m + '.')));
  const flows = a.flows.length ? h('div', null, h('h4', null, 'Where the flagged value came from'),
    h('ul', { class: 'prov' }, a.flows.map((f) => h('li', { class: 'src' }, 'a value in this call matches ', h('b', { class: 'mono' }, f.call), ` (${f.tool}, `, labelChip(f.label_obj), `) · ${f.kind}/${f.via} · ${f.hits} hit${f.hits === 1 ? '' : 's'}`))),
    h('p', { class: 'muted small' }, 'A match means the tracker found the same text or destination in that earlier result. It does not show how it got here.')) : null;
  const ctx = a.ctx_at_hold ? h('p', { class: 'ctxline' }, 'Session context when held ', labelChip(parse(a.ctx_at_hold)), a.context_changed ? [h('span', null, '· now '), labelChip(parse(a.ctx_now), true)] : null) : null;
  const changed = a.context_changed ? banner('warn', h('b', null, 'The session has changed since this was held. '), 'The approval is bound to the exact call, not to the session state; if the call is repeated and now also breaks a deny rule it is blocked and this approval stays unused until it expires.') : null;
  const body = h('div', { class: 'ap-b' },
    h('div', null, h('div', { class: 'tool-name' }, a.tool), h('p', { class: 'muted small' }, `session ${a.session} · requested as ${a.requested_call || '–'} · exact-call hash ${a.call_hash}… · ${fmtDateTime(a.created)}`)),
    h('div', { class: 'ap-two' },
      h('div', null, h('h4', null, 'What the agent asked for'), argList(a.args),
        a.args.some((x) => x.kind === 'digest') ? h('p', { class: 'muted small' }, 'Content is shown as length and digest only. Approving a send means approving something you cannot read here.') : null),
      h('div', null, h('h4', null, 'Why Weir held it'), reasons)),
    flows, ctx, changed);
  const card = h('article', { class: `ap${pending ? '' : ' done'}`, id: `ap-${a.id}`, 'aria-label': `Approval ${a.id} for ${a.tool}` }, head, body);

  if (pending && a.can_resolve) {
    const mode = confirming.get(a.id);
    const busy = h('span', { class: 'sr-only', role: 'status' });
    const act = h('div', { class: 'ap-act' });
    if (!mode) {
      act.append(
        h('p', { class: 'note' }, 'Approve lets the agent’s next identical call run once, before this expires. Weir does not run it for you. Deny blocks that exact call from now on in this session.'),
        h('button', { type: 'button', class: 'btn btn-approve', onclick: () => { confirming.set(a.id, 'approve'); rerender(); } }, 'Approve once'),
        h('button', { type: 'button', class: 'btn btn-deny', onclick: () => { confirming.set(a.id, 'deny'); rerender(); } }, 'Deny'));
    } else {
      const verb = mode === 'approve' ? 'Approve' : 'Deny';
      const go = h('button', { type: 'button', class: `btn ${mode === 'approve' ? 'btn-approve' : 'btn-deny'}`, dataset: { fk: `go-${a.id}` } }, `Confirm: ${verb.toLowerCase()} this exact call`);
      go.addEventListener('click', async () => {
        go.disabled = true;
        try {
          const r = await post(`approvals/${a.id}`, { decision: mode, fingerprint: a.fingerprint });
          results.set(a.id, { ok: true, text: r.message });
          toast(r.message); announce(r.message);
        } catch (e) {
          const msg = e instanceof ApiError ? e.message : 'Could not reach the dashboard server.';
          results.set(a.id, { ok: false, text: msg });
          toast(msg); announce(msg);
        }
        confirming.delete(a.id);
        rerender(true);
      });
      act.append(h('p', { class: 'note' }, `${verb} this exact call (${a.tool}, hash ${a.call_hash}…) once?`), go,
        h('button', { type: 'button', class: 'btn', onclick: () => { confirming.delete(a.id); rerender(); } }, 'Cancel'), busy);
    }
    card.append(act);
  } else if (pending) {
    card.append(h('div', { class: 'ap-res' }, 'This is demonstration data: its approvals were resolved by a simulated approver.'));
  } else {
    const line = {
      approved: 'Approved. The gateway is waiting for the agent to repeat the identical call; it does not run it by itself.',
      denied: 'Denied. Repeating the identical call is blocked (R-APPROVAL-DENIED).',
      consumed: `Used once${a.used_by_call ? ' by ' + a.used_by_call : ''}. A further identical call needs a new approval.`,
      expired: 'Expired without being used.',
    }[a.state];
    const by = a.resolved_by ? ` Resolved by ${a.resolved_by}${a.resolved_at ? ' at ' + fmtDateTime(a.resolved_at) : ''}.` : '';
    card.append(h('div', { class: 'ap-res' }, (line || '') + by));
  }
  const res = results.get(a.id);
  if (res) card.append(h('div', { class: 'ap-res', role: res.ok ? 'status' : 'alert' }, res.text));
  return card;
}

function parse(text) {
  const [conf, integ] = String(text).split('/');
  const R = { public: 0, internal: 1, secret: 2, trusted: 0, untrusted: 1 };
  return { conf, integ, rank: [R[conf] ?? 0, R[integ] ?? 0] };
}

export const approvalsView = {
  title: () => 'Approvals',
  async load() { return get('d/live/approvals'); },
  render(data, route, rerender) {
    const filter = route.query.get('show') || 'pending';
    // a card just decided on this page stays where it is, so the result can be read
    const items = data.approvals.filter((a) => (filter === 'pending' ? a.state === 'pending' || results.has(a.id) : filter === 'resolved' ? a.state !== 'pending' : true));
    const nPending = data.approvals.filter((a) => a.state === 'pending').length;
    const seg = h('div', { class: 'seg', role: 'group', 'aria-label': 'Filter approvals' },
      [['pending', `Waiting (${nPending})`], ['resolved', 'Resolved'], ['all', 'All']].map(([k, label]) =>
        h('button', { type: 'button', 'aria-pressed': String(filter === k), onclick: () => { location.hash = `#/approvals${k === 'pending' ? '' : '?show=' + k}`; } }, label)));
    const page = h('div', { class: 'page' }, pageHead('Approvals', 'Calls Weir held for a person. Decisions use the same approval records as the weir approvals command.', seg));
    page.append(banner('note', h('b', null, 'How approval works. '), 'The gateway never keeps a held call open. The agent receives “approval required”, a person decides here (or on the command line), and the agent must then repeat the identical call. The approval is bound to that exact call, works once, and expires.'));
    if (!items.length) {
      page.append(h('div', { class: 'card' }, empty(filter === 'pending' ? 'Nothing is waiting for a decision' : 'No approvals to show',
        'A call appears here when a rule configured as HOLD fires on it. Calls blocked by a DENY rule never appear: an approval cannot override a deny.')));
    }
    for (const a of items) page.append(approvalCard(a, rerender));
    const focus = route.path[1];
    if (focus) queueMicrotask(() => document.getElementById(`ap-${focus}`)?.scrollIntoView({ block: 'center' }));
    return page;
  },
};
