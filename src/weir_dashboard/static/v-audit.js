import { get } from './api.js';
import { h, icon, ago, fmtClock, fmtDateTime } from './dom.js';
import { banner, chip, empty, pageHead } from './ui.js';
import { dbProblem } from './v-overview.js';

export const auditView = {
  title: () => 'Audit',
  async load(route) {
    try { return await get('d/live/audit', { limit: 200, ...(route.query.get('verify') ? { verify: '1' } : {}) }); } catch (e) { if (e.status === 503) return { dbError: e }; throw e; }
  },
  render(d, route, rerender) {
    if (d.dbError) return dbProblem(d.dbError);
    const c = d.chain;
    const page = h('div', { class: 'page' });
    const btn = h('button', { type: 'button', class: 'btn btn-primary', onclick: async (e) => { e.currentTarget.disabled = true; e.currentTarget.textContent = 'Verifying…'; await get('d/live/audit', { verify: '1', limit: 1 }); rerender(true); } }, 'Verify chain');
    page.append(pageHead('Audit', 'The gateway’s hash-chained event log. Verification uses the gateway store’s own check.', btn));
    page.append(h('section', { class: 'card', 'aria-label': 'Chain status' }, h('div', { class: 'card-b' },
      h('div', { class: `big-status ${c.ok ? 'chain-ok' : 'chain-bad'}`, role: 'status' }, icon(c.ok ? 'allow' : 'deny', 26), c.ok ? 'CHAIN VERIFIED' : 'Hash-chain verification failed.'),
      h('dl', { class: 'kv' }, h('dt', null, 'Events in chain'), h('dd', null, String(d.total_events)),
        h('dt', null, c.ok ? 'Events checked' : 'Events that verified before the failure'), h('dd', null, String(c.events)),
        c.ok ? null : [h('dt', null, 'First failure'), h('dd', null, `event #${c.first_bad_seq}${c.first_bad_session ? ' in session ' + c.first_bad_session : ''}`)],
        h('dt', null, 'Latest event'), h('dd', null, d.latest_event ? `#${d.latest_event.seq} · ${fmtDateTime(d.latest_event.ts)} · session ${d.latest_event.session || '–'}` : 'none'),
        h('dt', null, 'Checked'), h('dd', null, ago(c.checked_at))),
      h('p', { class: 'muted small' }, c.scope))));
    if (!c.ok) page.append(banner('bad', h('b', null, 'Hash-chain verification failed. '), `Events up to #${(c.first_bad_seq ?? 1) - 1} still match their links; event #${c.first_bad_seq} does not match, so events from there on cannot be relied on. The cause is not known from here: it could be an edit, a partial write or a copy of the file.`));
    const kinds = Object.entries(d.kinds);
    page.append(h('section', { class: 'card' }, h('div', { class: 'card-h' }, h('h3', null, 'Events by kind')), h('div', { class: 'card-b rules' }, kinds.length ? kinds.map(([k, n]) => chip(`${k} · ${n}`)) : h('span', { class: 'muted' }, 'none'))));
    const rows = d.latest.map((e) => h('tr', { class: e.broken ? 'bad' : '' }, h('td', { class: 'num mono' }, `#${e.seq}`), h('td', null, fmtClock(e.ts)), h('td', { class: 'mono' }, e.session || '–'), h('td', { class: 'mono' }, e.kind), h('td', { class: 'wrap' }, e.summary),
      h('td', { class: 'hashes' }, `${e.prev}…→${e.hash}…`)));
    page.append(h('section', { class: 'card' }, h('div', { class: 'card-h' }, h('h3', null, `Latest ${d.latest.length} events`)),
      d.latest.length ? h('div', { class: 'tw' }, h('table', null, h('thead', null, h('tr', null, ['Event', 'Time', 'Session', 'Kind', 'Summary', 'Hash link'].map((t) => h('th', null, t)))), h('tbody', rows))) : empty('No events yet')));
    return page;
  },
};
