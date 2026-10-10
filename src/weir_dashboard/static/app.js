import { get, prefs, savePref } from './api.js';
import { clear, h, icon, until } from './dom.js';
import { announce, empty, initSheet, openSheet, pageHead } from './ui.js';
import { approvalsView } from './v-approvals.js';
import { auditView } from './v-audit.js';
import { demoView } from './v-demo.js';
import { sessionView } from './v-flow.js';
import { overviewView, sessionsView } from './v-overview.js';
import { policyView } from './v-policy.js';

const NAV = [['overview', 'Overview', 'overview'], ['sessions', 'Sessions', 'sessions'], ['approvals', 'Approvals', 'approvals'], ['audit', 'Audit', 'audit'], ['policy', 'Policy', 'policy'], ['demo', 'Demo', 'demo']];
const main = document.getElementById('main');
const state = { route: null, view: null, data: null, key: '', pending: 0, lastStamp: null, lastRender: 0, seq: 0 };

function parseRoute() {
  const raw = location.hash.replace(/^#\/?/, '');
  const [p, q] = raw.split('?');
  const path = p.split('/').filter(Boolean).map(decodeURIComponent);
  return { path: path.length ? path : ['overview'], query: new URLSearchParams(q || ''), raw };
}

function demoSession(route) {
  const run = route.path[1], arm = route.path[2];
  const ds = `demo.${run}.${arm}`;
  route.tab = route.path[3] || 'flow';
  const base = `#/demo/${run}/${arm}`;
  const v = sessionView(ds, base, `#/demo/${run}`, 'Demo');
  const load = v.load;
  v.load = async (r) => { r.sid = (await get(`d/${ds}/sessions`)).sessions[0]?.id; return load(r); };
  return v;
}

function resolve(route) {
  const [a, b, c, d] = route.path;
  switch (a) {
    case 'sessions':
      if (b) { route.sid = b; route.tab = c || 'flow'; return sessionView('live', `#/sessions/${encodeURIComponent(b)}`, '#/sessions', 'Sessions'); }
      return sessionsView;
    case 'approvals': return approvalsView;
    case 'audit': return auditView;
    case 'policy': route.tab = b; return policyView;
    case 'demo': return c && /^(strict|careless)$/.test(c) ? demoSession(route) : demoView;
    default: return overviewView;
  }
}

function setNav(active) {
  const nav = document.getElementById('nav');
  clear(nav);
  for (const [k, label, ic] of NAV) {
    const a = h('a', { href: `#/${k}`, 'aria-current': active === k ? 'page' : null }, icon(ic, 16), h('span', null, label));
    if (k === 'approvals' && state.pending) a.append(h('span', { class: 'nb', 'aria-label': `${state.pending} waiting` }, String(state.pending)));
    nav.append(a);
  }
}

function captureFocus() {
  const el = document.activeElement;
  if (!el || !main.contains(el)) return null;
  const fk = el.closest('[data-fk]')?.dataset.fk;
  const id = el.closest('[id]')?.id;
  return { fk, id, tag: el.tagName, text: el.textContent?.slice(0, 40) };
}
function restoreFocus(f) {
  if (!f) return;
  const el = (f.fk && main.querySelector(`[data-fk="${CSS.escape(f.fk)}"]`)) || (f.id && main.querySelector(`#${CSS.escape(f.id)} button, #${CSS.escape(f.id)} a`));
  el?.focus({ preventScroll: true });
}

// A quiet refresh (a poll, a button's re-render) belongs to the view it started from: if the person has navigated since, it is dropped.
const stale = (route, quiet) => quiet && parseRoute().raw !== route.raw;

async function show(route, { quiet = false, reload = true } = {}) {
  if (stale(route, quiet)) return;
  const my = ++state.seq;
  const view = resolve(route);
  const key = route.path.slice(0, 3).join('/') + (route.tab || '');
  if (!quiet) { document.title = 'Weir Control Center'; }
  let data = state.data;
  if (reload || state.key !== key) {
    // Take the change stamp before reading the data: anything that lands after this point makes the next poll differ.
    try {
      const p0 = (await get('pulse')).live;
      state.lastStamp = JSON.stringify(p0);
      if (p0.stamp) state.pending = p0.stamp.pending;
    } catch { /* the poll will report the problem */ }
    try { data = await view.load(route); } catch (e) {
      if (my !== state.seq) return;
      setNav(route.path[0]);
      const msg = e.state === 'missing' && e.status === 404 ? 'Nothing here.' : e.message;
      clear(main).append(h('div', { class: 'page' }, pageHead('Something went wrong'), h('div', { class: 'card' }, empty(msg, e.status === 503 ? 'The database could not be read right now. The page keeps trying.' : ''))));
      document.getElementById('title').textContent = 'Error';
      return;
    }
  }
  if (my !== state.seq || stale(route, quiet)) return; // a newer navigation won
  const prev = state.key === key ? state.data : null;
  const focus = captureFocus();
  const node = view.render(data, route, (r) => show(route, { quiet: true, reload: r === true }), prev);
  main.style.minHeight = `${main.offsetHeight}px`;
  clear(main).append(node);
  main.style.minHeight = '';
  Object.assign(state, { route, view, data, key, lastRender: Date.now() });
  document.getElementById('title').textContent = view.title(route, data);
  document.title = `${view.title(route, data)} · Weir Control Center`;
  setNav(route.path[0]);
  if (quiet) restoreFocus(focus); else { window.scrollTo(0, route.query.get('call') ? window.scrollY : 0); }
}

function route() {
  const r = parseRoute();
  state.key = state.route && parseRouteKey(r) === state.key ? state.key : '';
  show(r);
}
const parseRouteKey = (r) => r.path.slice(0, 3).join('/');

// ---------------------------------------------------------------- polling
const pollEl = document.getElementById('poll');
function pollState(kind, text) { pollEl.className = `poll ${kind === 'on' ? '' : kind}`; pollEl.lastChild.textContent = text; }

async function tick() {
  if (document.hidden) return;
  try {
    const p = await get('pulse');
    pollState('on', 'polling 1 s');
    const live = p.live;
    const pend = live.stamp ? live.stamp.pending : 0;
    if (pend !== state.pending) { state.pending = pend; setNav(state.route?.path[0]); }
    const st = JSON.stringify(live);
    const changed = state.lastStamp !== null && st !== state.lastStamp;
    state.lastStamp = st;
    const onLive = state.route && !(state.route.path[0] === 'demo') && state.route.path[0] !== 'policy';
    if (onLive && (changed || Date.now() - state.lastRender > 15000)) show(state.route, { quiet: true });
  } catch { pollState('err', 'server not reachable'); }
}

// ---------------------------------------------------------------- chrome
function theme(t) {
  if (t) document.documentElement.dataset.theme = t; else delete document.documentElement.dataset.theme;
}
function initChrome() {
  theme(prefs.theme);
  const maskBtn = document.getElementById('mask');
  maskBtn.setAttribute('aria-pressed', String(prefs.mask));
  maskBtn.addEventListener('click', () => {
    prefs.mask = !prefs.mask; savePref('mask', prefs.mask ? '1' : '0');
    maskBtn.setAttribute('aria-pressed', String(prefs.mask));
    announce(prefs.mask ? 'Destinations and clear arguments are masked' : 'Masking is off');
    show(state.route, { quiet: true });
  });
  const themeBtn = document.getElementById('theme');
  const dark = () => (document.documentElement.dataset.theme || (matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light')) === 'dark';
  const label = () => { themeBtn.textContent = dark() ? 'Light' : 'Dark'; };
  label();
  themeBtn.addEventListener('click', () => { const t = dark() ? 'light' : 'dark'; prefs.theme = t; savePref('theme', t); theme(t); label(); });
  const info = () => openSheet('What Weir does not see', boundaryBody(), document.getElementById('info'));
  document.getElementById('info').addEventListener('click', info);
  document.getElementById('boundary-more').addEventListener('click', (e) => openSheet('What Weir does not see', boundaryBody(), e.currentTarget));
  initSheet();
  get('config').then((c) => { document.getElementById('railfoot').append(h('b', null, 'LOCAL ONLY'), h('span', null, `127.0.0.1:${c.port}`), h('span', { class: 'wrap' }, c.db_name)); }).catch(() => {});
}

function boundaryBody() {
  const note = document.getElementById('boundary-text').textContent;
  return h('div', null, h('p', null, h('b', null, note)),
    h('ul', { class: 'prov' },
      h('li', null, 'Weir sits between an agent host and its MCP servers. It sees tool calls and tool results, and nothing else.'),
      h('li', null, 'It does not see the user’s prompt, the model’s reasoning or the final answer. If a secret is already in the model’s context, the model can repeat it in its reply without making a tool call, and nothing on this page would show it.'),
      h('li', null, 'So a quiet dashboard does not mean nothing leaked. It means no mediated call was held or blocked.'),
      h('li', null, 'This page reads what Weir recorded. It is not part of the gateway, adds no rules, and does not change any decision.')));
}

// the countdown on pending approvals
setInterval(() => document.querySelectorAll('[data-expires]').forEach((el) => { el.textContent = until(Number(el.dataset.expires)); }), 1000);

initChrome();
window.addEventListener('hashchange', route);
route();
setInterval(tick, 1000);
document.addEventListener('visibilitychange', () => { if (!document.hidden) tick(); });
