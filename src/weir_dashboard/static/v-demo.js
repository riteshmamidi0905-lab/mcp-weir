import { get, post } from './api.js';
import { h, icon } from './dom.js';
import { banner, chip, empty, pageHead, ruleChip, toast, verdictBadge } from './ui.js';
import { argList } from './ui.js';

let busy = false;

function step(i, c, extra) {
  return h('div', { class: 'dstep' },
    h('div', { class: 'rules' }, h('b', { class: 'mono' }, `${i}.`), h('span', { class: 'tool-name' }, c.tool), extra),
    c.args ? argList(c.args) : null);
}

function weirColumn(arm, d, run) {
  const sm = d.summary;
  const steps = d.calls.map((c, i) => h('div', { class: 'dstep' },
    h('div', { class: 'rules' }, h('b', { class: 'mono' }, `${i + 1}.`), h('span', { class: 'tool-name' }, c.tool), verdictBadge(c.verdict)),
    argList(c.args),
    h('p', { class: 'why' }, c.path + (c.rules.length ? ':' : '.')),
    c.rules.length ? h('div', { class: 'rules' }, c.rules.map((r) => ruleChip(r, c))) : null));
  return h('section', { class: 'card dcol', 'aria-label': arm.title },
    h('div', { class: 'card-h' }, h('h3', null, arm.title), h('span', { class: 'muted small' }, arm.approver)),
    steps, outcome(arm),
    h('div', { class: 'card-b' }, h('a', { class: 'btn', href: `#/demo/${run.id}/${arm.key}/flow` }, 'Open full flow', icon('arrow', 14))));
}

function outcome(arm) {
  return h('div', { class: `dout ${arm.attacker_got_secret ? 'bad' : 'good'}`, role: 'status' }, icon(arm.attacker_got_secret ? 'deny' : 'allow', 16),
    arm.attacker_got_secret ? 'In this synthetic world the planted secret reached the attacker’s address.' : 'In this synthetic world nothing reached the attacker.');
}

function plainColumn(arm) {
  return h('section', { class: 'card dcol', 'aria-label': arm.title },
    h('div', { class: 'card-h' }, h('h3', null, arm.title), h('span', { class: 'muted small' }, 'No audit record exists for this arm: this is the demo runner’s own list of the calls the agent made.')),
    arm.calls.map((c, i) => step(i + 1, c, chip('RAN · nothing checked it', 'mute'))), outcome(arm));
}

export const demoView = {
  title: () => 'Demo',
  async load(route) {
    const info = await get('demo');
    const id = route.path[1] || (info.runs.length ? info.runs[info.runs.length - 1].id : null);
    const run = info.runs.find((r) => r.id === id) || null;
    const detail = {};
    if (run) for (const arm of run.arms) if (arm.gateway) detail[arm.key] = await get(`d/${arm.dataset}/sessions/${encodeURIComponent(arm.session)}`);
    return { info, run, detail };
  },
  render({ info, run, detail }, route, rerender) {
    const page = h('div', { class: 'page' });
    const load = (kind) => async (e) => {
      if (busy) return; busy = true; e.currentTarget.disabled = true;
      try { const r = await post('demo/load', { kind }); toast(`${r.label} loaded`); location.hash = `#/demo/${r.id}`; } catch (err) { toast(err.message); }
      busy = false; rerender(true);
    };
    page.append(pageHead('Demo', 'A scripted walk-through of one poisoned task, three ways. Separate from your live database.',
      h('button', { type: 'button', class: 'btn btn-primary', disabled: !info.synthetic_available, title: info.synthetic_available ? '' : 'the demo needs a repository checkout installed with pip install -e .', onclick: load('synthetic') }, 'LOAD SYNTHETIC DEMO'),
      h('button', { type: 'button', class: 'btn', disabled: !info.recorded_available, title: info.recorded_available ? '' : 'demo/recorded/f1-web.json is not in this checkout', onclick: load('recorded') }, 'LOAD RECORDED REAL-MODEL REPLAY')));
    page.append(banner('demo', h('b', null, 'DEMO · SYNTHETIC DEMONSTRATION. '), 'A scripted agent (or recorded model replies) in an invented world, with a simulated approver. Nothing here is a live session, and it says nothing about how often attacks succeed: that is what the frozen evaluation measures, and it is not touched by this page.'));
    if (!run) { page.append(h('div', { class: 'card' }, empty('No demonstration loaded', 'Load one to see the same task run with no gateway, with a careful simulated approver, and with an approve-everything simulated approver. The gateway decisions are computed when you load it.'))); return page; }
    page.append(h('div', { class: 'card' }, h('div', { class: 'card-b' }, h('div', { class: 'rules' }, h('span', { class: `sb sb-${run.kind === 'recorded' ? 'recorded' : 'synthetic-demo'}` }, h('i'), run.label), h('span', { class: 'muted small' }, `scenario ${run.scenario}`)),
      h('dl', { class: 'kv' }, h('dt', null, 'User asked'), h('dd', null, run.task), h('dt', null, 'Planted in a web page the agent reads'), h('dd', { class: 'wrap' }, run.planted_instruction + '…'), h('dt', null, 'Agent'), h('dd', null, run.agent)),
      h('p', { class: 'muted small' }, run.detail + ' ' + run.note))));
    page.append(h('div', { class: 'demo-cols' }, run.arms.map((arm) => arm.gateway ? weirColumn(arm, detail[arm.key], run) : plainColumn(arm))));
    if (info.runs.length > 1) page.append(h('p', { class: 'muted small' }, 'Other runs: ', info.runs.filter((r) => r.id !== run.id).map((r) => h('a', { href: `#/demo/${r.id}` }, `${r.label.toLowerCase()} ${r.id.slice(-6)} `))));
    return page;
  },
};
