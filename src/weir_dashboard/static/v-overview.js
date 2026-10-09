import { get } from './api.js';
import { h, icon, ago, fmtClock, fmtDateTime } from './dom.js';
import { banner, chip, empty, labelChip, pageHead, ruleChip, sourceBadge, verdictBadge } from './ui.js';

const counts = (c) => h('span', { class: 'counts', 'aria-label': `${c.allow} allow, ${c.hold} hold, ${c.deny} deny` },
  h('span', { class: c.allow ? '' : 'z' }, icon('allow', 14), c.allow), h('span', { class: c.hold ? '' : 'z' }, icon('hold', 14), c.hold), h('span', { class: c.deny ? '' : 'z' }, icon('deny', 14), c.deny));

const NOT_LIVE_NOTE = {
  'synthetic-demo': 'This database contains SYNTHETIC DEMO sessions. They are not a live system.',
  'recorded-replay': 'This database contains RECORDED REAL-MODEL REPLAY sessions. They are not live.',
  unknown: 'A source file next to this database could not be read, so the sessions below are not claimed to be live.',
};

export const overviewView = {
  title: () => 'Overview',
  async load() {
    try { return await get('overview'); } catch (e) { if (e.state && ['missing', 'empty', 'corrupt', 'schema', 'unreadable'].includes(e.state)) return { dbError: e }; throw e; }
  },
  render(d, route, rerender) {
    if (d.dbError) return dbProblem(d.dbError);
    const page = h('div', { class: 'page' });
    page.append(pageHead('Overview', 'What the gateway has recorded in this database. Nothing on this page is estimated.'));
    for (const [k, text] of Object.entries(NOT_LIVE_NOTE)) if (d.sessions.by_source[k]) page.append(banner(k === 'synthetic-demo' ? 'demo' : 'warn', text));
    const a = d.activity;
    const verifyBtn = h('button', { type: 'button', class: 'btn', onclick: async (e) => { e.currentTarget.disabled = true; e.currentTarget.textContent = 'Verifying…'; await get('overview', { verify: '1' }); rerender(true); } }, 'Verify chain');
    page.append(h('div', { class: 'kpis' },
      h('section', { class: 'card kpi', 'aria-label': 'Gateway activity' }, h('span', { class: 'label' }, 'Gateway activity'),
        h('div', { class: 'kpi-v' }, a.last_event == null ? 'No events yet' : ago(a.last_event), a.last_event == null ? null : chip(a.recent ? 'RECENT ACTIVITY' : 'NO RECENT ACTIVITY', a.recent ? 'ok' : 'mute')),
        h('span', { class: 'kpi-s' }, 'time since the last audit event. ' + a.note)),
      h('section', { class: 'card kpi', 'aria-label': 'Audit chain' }, h('span', { class: 'label' }, 'Audit chain'),
        h('div', { class: `kpi-v ${d.audit.ok ? 'chain-ok' : 'chain-bad'}` }, d.audit.ok ? 'VERIFIED' : 'FAILED'),
        h('span', { class: 'kpi-s' }, d.audit.ok ? `${d.audit.events} events · checked ${ago(d.audit.checked_at)}` : d.audit.message + (d.audit.first_bad_seq != null ? ` First failure at event #${d.audit.first_bad_seq}.` : '')),
        h('div', null, verifyBtn, ' ', h('a', { href: '#/audit', class: 'small' }, 'Audit view'))),
      h('section', { class: 'card kpi', 'aria-label': 'Sessions' }, h('span', { class: 'label' }, 'Sessions'),
        h('div', { class: 'kpi-v' }, String(d.sessions.total), h('span', { class: 'muted' }, ''), chip(`${d.sessions.active} active`, d.sessions.active ? 'ok' : 'mute')),
        h('span', { class: 'kpi-s' }, `active = an event in the last ${Math.round(d.sessions.window_s / 60)} min; the log has no end-of-session marker`),
        h('a', { href: '#/sessions', class: 'small' }, 'Open sessions')),
      h('section', { class: 'card kpi', 'aria-label': 'Pending approvals' }, h('span', { class: 'label' }, 'Pending approvals'),
        h('div', { class: 'kpi-v' }, String(d.approvals.pending), d.approvals.pending ? chip('NEEDS A PERSON', 'warn') : null),
        h('span', { class: 'kpi-s' }, 'holds waiting for APPROVE or DENY'),
        h('a', { href: '#/approvals', class: 'small' }, 'Open approvals'))));
    const dd = d.decisions;
    page.append(h('section', { class: 'card', 'aria-label': 'Decisions' },
      h('div', { class: 'card-h' }, h('h3', null, 'Decisions recorded'), h('span', { class: 'muted small' }, `${dd.calls} tool calls in ${d.sessions.total} sessions`)),
      h('div', { class: 'card-b' }, counts(dd), h('span', { class: 'muted small' }, '  allow · hold (needs a person) · deny (cannot be approved)'))));
    const recent = d.recent;
    page.append(h('section', { class: 'card', 'aria-label': 'Recent decisions' }, h('div', { class: 'card-h' }, h('h3', null, 'Recent decisions')),
      recent.length ? h('div', { class: 'tw' }, h('table', null, h('thead', null, h('tr', null, ['Time', 'Session', 'Call', 'Tool', 'Decision', 'Rules'].map((t) => h('th', null, t)))),
        h('tbody', recent.map((r) => h('tr', { class: 'row', onclick: () => { location.hash = `#/sessions/${encodeURIComponent(r.session)}/flow?call=${r.call}`; } },
          h('td', null, fmtClock(r.ts)), h('td', { class: 'mono' }, r.session), h('td', { class: 'mono' }, r.call), h('td', { class: 'mono' }, r.tool), h('td', null, h('span', { class: 'rules' }, verdictBadge(r.verdict), r.status === 'EXECUTED_AFTER_APPROVAL' ? chip('RAN AFTER APPROVAL', 'ok') : null)),
          h('td', null, h('span', { class: 'rules' }, r.rules.map((c) => h('span', { class: 'rc' }, c))))))))) :
        empty('No sessions recorded yet', 'Point a gateway at this database, then make a tool call:', `weir --db ${d.database.name} run --policy examples/policies/workspace.toml`)));
    return page;
  },
};

export function dbProblem(e) {
  const text = {
    missing: ['Waiting for the database', 'The file does not exist yet. The gateway creates it the first time it runs. This page keeps checking.'],
    empty: ['The database has no Weir tables yet', 'It is empty or was not created by Weir.'],
    corrupt: ['The file is not a readable SQLite database', 'Nothing was changed. Check the path you passed with --db.'],
    schema: ['This database uses a schema this dashboard does not support', e.message],
    unreadable: ['The database could not be opened', e.message],
  }[e.state] || ['The database could not be read', e.message];
  return h('div', { class: 'page' }, pageHead('Overview'), h('div', { class: 'card' }, empty(text[0], text[1])));
}

export const sessionsView = {
  title: () => 'Sessions',
  async load() {
    try { return await get('d/live/sessions'); } catch (e) { if (e.status === 503) return { dbError: e }; throw e; }
  },
  render(d) {
    if (d.dbError) return dbProblem(d.dbError);
    const page = h('div', { class: 'page' });
    page.append(pageHead('Sessions', 'Each row is one gateway session in this database. Open one to follow its calls.'));
    if (!d.sessions.length) { page.append(h('div', { class: 'card' }, empty('No sessions yet', 'Sessions appear when a gateway opens one.'))); return page; }
    const href = (s) => `#/sessions/${encodeURIComponent(s.id)}/flow`;
    const rows = d.sessions.map((s) => h('tr', { class: 'row', onclick: () => { location.hash = href(s); } },
      h('td', null, h('a', { href: href(s), class: 'mono wrap', onclick: (e) => e.stopPropagation() }, s.id)),
      h('td', null, sourceBadge(s.source)), h('td', null, fmtDateTime(s.started)), h('td', null, ago(s.last_activity)),
      h('td', null, labelChip(s.ctx)), h('td', { class: 'num' }, String(s.counts.calls)), h('td', null, counts(s.counts)),
      h('td', { class: 'num' }, s.pending_approvals ? chip(String(s.pending_approvals), 'warn') : '0'),
      h('td', null, s.audit.chain_ok ? chip('VERIFIED', 'ok') : chip('FAILED', 'bad'))));
    const cards = d.sessions.map((s) => h('a', { class: 'rowcard', href: href(s) },
      h('div', { class: 'rules' }, h('b', { class: 'mono wrap' }, s.id)), h('div', null, sourceBadge(s.source)),
      h('div', { class: 'ctxline' }, labelChip(s.ctx), `${s.counts.calls} calls`, counts(s.counts)),
      h('div', { class: 'ctxline' }, `last ${ago(s.last_activity)}`, s.pending_approvals ? chip(`${s.pending_approvals} waiting`, 'warn') : null, s.audit.chain_ok ? chip('VERIFIED', 'ok') : chip('FAILED', 'bad'))));
    page.append(h('div', { class: 'card tw stack' },
      h('table', null, h('thead', null, h('tr', null, ['Session', 'Source', 'Started', 'Last activity', 'Context', 'Calls', 'Allow · Hold · Deny', 'Pending', 'Audit'].map((t, i) => h('th', { class: i === 5 || i === 7 ? 'num' : '' }, t)))), h('tbody', rows)),
      h('div', { class: 'cardlist' }, cards)));
    return page;
  },
};
