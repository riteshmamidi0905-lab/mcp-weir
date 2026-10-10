// Browser tests for the Weir Control Center. Run by tests/test_dashboard_ui.py, which starts the servers and sets the environment.
import test, { after, before } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { spawnSync } from 'node:child_process';
import path from 'node:path';

const need = (k) => { if (!process.env[k]) throw new Error(`${k} is not set`); return process.env[k]; };
const BASE = need('WEIR_UI_URL');
const TAMPERED = need('WEIR_UI_TAMPERED_URL');
const { chromium } = createRequire(path.join(need('WEIR_PLAYWRIGHT_DIR'), 'x.js'))('playwright');
const NOTE = "Weir mediates MCP tool calls and results. It does not inspect the model's final answer.";
const ROUTES = ['overview', 'sessions', 'sessions/live-2/flow', 'sessions/live-2/provenance', 'sessions/live-2/context', 'sessions/live-2/approvals', 'sessions/live-2/events', 'approvals', 'audit', 'policy', 'policy/tools', 'policy/rules', 'policy/pinning', 'demo'];
const WIDTHS = [1440, 1280, 1024, 768, 390];

let browser;
before(async () => { browser = await chromium.launch(); });
after(async () => { await browser.close(); });

async function open(route, { width = 1280, height = 900, base = BASE, scheme = 'light', reducedMotion = 'no-preference', touch = false } = {}) {
  const ctx = await browser.newContext({ viewport: { width, height }, colorScheme: scheme, reducedMotion, hasTouch: touch });
  const page = await ctx.newPage();
  page.errors = [];
  page.on('console', (m) => { if (m.type() === 'error' || /Content Security Policy|Refused to/.test(m.text())) page.errors.push(m.text()); });
  page.on('pageerror', (e) => page.errors.push(String(e)));
  await page.goto(`${base}/#/${route}`);
  await page.waitForSelector('main .page, main .card', { timeout: 8000 });
  page.ctx = ctx;
  return page;
}
const goto = async (page, route, heading) => {
  await page.goto(`${page.url().split('#')[0]}#/${route}`);
  await page.waitForFunction((h) => document.querySelector('main h2')?.textContent.trim() === h, heading, { timeout: 8000 });
};
const done = async (page) => { assert.deepEqual(page.errors, [], 'no console errors or CSP violations'); await page.ctx.close(); };
const api = async (p, base = BASE) => (await fetch(`${base}/api/${p}`, { headers: { Host: new URL(base).host } })).json();

test('every view renders with landmarks, one h1 in the bar, the answer-channel sentence and no console errors', async () => {
  const page = await open('overview');
  for (const r of ROUTES) {
    await page.goto(`${BASE}/#/${r}`);
    await page.waitForSelector('main .page', { timeout: 8000 });
    assert.equal(await page.locator('#boundary-text').innerText(), NOTE, r);
    assert.equal(await page.locator('main').count(), 1);
    assert.equal(await page.locator('nav[aria-label="Primary"]').count(), 1);
    assert.equal(await page.locator('h1').count(), 1, r);
    assert.equal(await page.locator('#info').isVisible(), true);
    const ids = await page.$$eval('[id]', (els) => els.map((e) => e.id));
    assert.equal(new Set(ids).size, ids.length, `duplicate ids on ${r}`);
    const nameless = await page.$$eval('button, a[href], input, select', (els) => els.filter((e) => !(e.getAttribute('aria-label') || e.textContent.trim() || e.getAttribute('title'))).length);
    assert.equal(nameless, 0, `controls without an accessible name on ${r}`);
  }
  await done(page);
});

test('the boundary note opens from the header button and the footer link and closes with Escape', async () => {
  const page = await open('sessions');
  await page.click('#info');
  const dlg = page.locator('dialog#sheet');
  assert.match(await dlg.innerText(), /does not inspect the model's final answer/);
  assert.match(await dlg.innerText(), /quiet dashboard does not mean nothing leaked/);
  await page.keyboard.press('Escape');
  assert.equal(await dlg.evaluate((d) => d.open), false);
  assert.equal(await page.evaluate(() => document.activeElement.id), 'info', 'focus returns to the button');
  await page.click('#boundary-more');
  assert.equal(await dlg.evaluate((d) => d.open), true);
  await done(page);
});

test('overview reports what is recorded, claims nothing about the gateway process, and shows the audit chain', async () => {
  const page = await open('overview');
  const text = await page.locator('main').innerText();
  assert.match(text, /VERIFIED/);
  assert.match(text, /RECENT ACTIVITY|NO RECENT ACTIVITY/);
  assert.match(text, /cannot see whether a gateway process is running/);
  assert.doesNotMatch(text, /\b(RUNNING|STOPPED)\b|uptime/);
  assert.match(await page.locator('[aria-label="Pending approvals"]').innerText(), /^PENDING APPROVALS\s*\n?\s*2/i);
  assert.match(await page.locator('#nav a:has-text("Approvals")').innerText(), /2/);
  await done(page);
});

test('sessions: all are labelled LIVE LOCAL SESSION, none is demo, and a row opens its flow', async () => {
  const page = await open('sessions');
  const rows = page.locator('table tbody tr');
  assert.equal(await rows.count(), 4);
  assert.equal(await page.locator('.sb[data-source="live-local"]').count() >= 4, true);
  assert.equal(await page.locator('.sb-synthetic-demo, .sb-recorded').count(), 0);
  assert.match(await page.locator('table').innerText(), /LIVE LOCAL SESSION/);
  await rows.filter({ hasText: 'live-2' }).first().click();
  await page.waitForSelector('.fcall');
  assert.match(page.url(), /#\/sessions\/live-2\/flow/);
  await done(page);
});

test('flow: ALLOW, HOLD and DENY are different in word, icon, border style and card edge, and a DENY has no approval control', async () => {
  const page = await open('sessions/live-2/flow');
  await page.waitForSelector('.fcall');
  const kinds = await page.$$eval('.fcall', (els) => els.map((e) => [e.id, [...e.classList].find((c) => c.startsWith('v-'))]));
  assert.deepEqual(kinds, [['call-c1', 'v-allow'], ['call-c2', 'v-allow'], ['call-c3', 'v-hold'], ['call-c4', 'v-hold'], ['call-c5', 'v-deny']]);
  const badge = async (sel) => page.locator(`${sel} .vb`).first().evaluate((e) => ({ text: e.textContent.trim(), border: getComputedStyle(e).borderTopStyle, svg: e.querySelector('svg').innerHTML }));
  const a = await badge('#call-c1'), h = await badge('#call-c3'), d = await badge('#call-c5');
  assert.deepEqual([a.text, h.text, d.text], ['ALLOW', 'HOLD', 'DENY']);
  assert.equal(h.border, 'dashed'); assert.equal(d.border, 'solid');
  assert.equal(new Set([a.svg, h.svg, d.svg]).size, 3, 'three different icon shapes');
  const edge = (sel) => page.locator(sel).evaluate((e) => getComputedStyle(e, '::before').backgroundImage);
  assert.match(await edge('#call-c3'), /repeating-linear-gradient/);
  assert.equal(await edge('#call-c5'), 'none');
  assert.equal(await page.locator('#call-c5 button:has-text("Approve"), #call-c5 a:has-text("Approval required")').count(), 0);
  assert.match(await page.locator('#call-c5').innerText(), /Blocked\. No approval can override this\./);
  assert.match(await page.locator('#call-c3').innerText(), /Held: R-UNTRUSTED-READ/);
  assert.match(await page.locator('#call-c4').innerText(), /RAN AFTER APPROVAL/);
  assert.match(await page.locator('#call-c5 .tool-name').first().innerText(), /mail__send_message/);
  await done(page);
});

test('a HOLD that is waiting says APPROVAL REQUIRED and links to the decision', async () => {
  const page = await open('sessions/live-1/flow');
  await page.waitForSelector('.fcall');
  const card = page.locator('.fcall.v-hold').last();
  assert.match(await card.innerText(), /WAITING FOR APPROVAL/);
  await card.locator('a:has-text("Approval required")').click();
  await page.waitForSelector('.ap');
  assert.match(await page.locator('.ap').first().innerText(), /APPROVAL REQUIRED/);
  await done(page);
});

test('decision details: rules, sources and the call hash are one click away, and a source link jumps to that call', async () => {
  const page = await open('sessions/live-2/flow');
  await page.waitForSelector('#call-c5');
  await page.locator('#call-c5 .fdetails > summary').click();
  const t = await page.locator('#call-c5 .fdetails').innerText();
  assert.match(t, /R-FLOW-CONF/); assert.match(t, /value matches\s+c4/); assert.match(t, /Gateway verdict name: DENY/);
  await page.locator('#call-c5 .fdetails a:has-text("c4")').first().click();
  await page.waitForSelector('#call-c4.focus-call');
  await done(page);
});

test('rule inspector opens from a chip with the keyboard, explains the rule from the policy, and returns focus', async () => {
  const page = await open('sessions/live-2/flow');
  await page.waitForSelector('#call-c5');
  const chip = page.locator('#call-c5 .rules .rc', { hasText: 'R-FLOW-CONF' }).first();
  await chip.focus();
  await page.keyboard.press('Enter');
  const dlg = page.locator('dialog#sheet');
  await dlg.waitFor({ state: 'visible' });
  const t = await dlg.innerText();
  assert.match(t, /R-FLOW-CONF/); assert.match(t, /flow_conf_secret/); assert.match(t, /DENY/); assert.match(t, /flow_conf_internal/); assert.match(t, /HOLD/);
  assert.match(t, /secret data would leave the trust boundary/); assert.match(t, /from\s+c4/); assert.match(t, /can a person approve past it\?/i);
  assert.match(t, /seen in this database/i);
  await page.keyboard.press('Escape');
  assert.equal(await page.evaluate(() => document.activeElement.textContent.trim()), 'R-FLOW-CONF');
  await done(page);
});

test('provenance shows only recorded edges and context shows the label lattice from the session', async () => {
  const page = await open('sessions/live-2/provenance');
  await page.waitForSelector('.provsvg');
  assert.equal(await page.locator('table tbody tr').count(), 2);
  assert.match(await page.locator('main').innerText(), /Only relationships Weir recorded/);
  await page.goto(`${BASE}/#/sessions/live-2/context`);
  await page.waitForSelector('.lattice');
  assert.equal(await page.locator('.lcell').count(), 6);
  assert.match(await page.locator('.lcell.cur').innerText(), /secret\/untrusted/);
  assert.equal(await page.locator('.lcell.on').count(), 4);
  assert.match(await page.locator('main').innerText(), /only grows/);
  await page.goto(`${BASE}/#/sessions/live-3/provenance`);
  await page.waitForSelector('.empty');
  assert.match(await page.locator('.empty').innerText(), /No data-flow relationships were recorded/);
  await done(page);
});

test('audit: VERIFY CHAIN re-checks the chain and the page says what the check is and is not', async () => {
  const page = await open('audit');
  await page.getByRole('button', { name: 'Verify chain' }).click();
  await page.waitForSelector('.big-status.chain-ok');
  const t = await page.locator('main').innerText();
  assert.match(t, /CHAIN VERIFIED/); assert.match(t, /Latest event/); assert.match(t, /cannot show that events were not removed/);
  assert.match(t, /Events in chain/);
  // regression: a button's re-render that arrives after the person has navigated away must not pull them back to the old view
  await page.getByRole('button', { name: 'Verify chain' }).click();
  await page.evaluate(() => { location.hash = '#/policy'; });
  await page.waitForFunction(() => document.querySelector('main h2')?.textContent.trim() === 'Policy', null, { timeout: 8000 });
  await page.waitForTimeout(1500);
  assert.equal(await page.locator('main h2').first().innerText(), 'Policy', 'still on the page the person navigated to');
  assert.equal(await page.evaluate(() => location.hash), '#/policy');
  await done(page);
});

test('audit: a broken chain says "Hash-chain verification failed." with the first failing event and never "tampering detected"', async () => {
  const page = await open('audit', { base: TAMPERED });
  await page.waitForSelector('.big-status.chain-bad');
  const t = await page.locator('main').innerText();
  assert.match(t, /Hash-chain verification failed\./); assert.match(t, /First failure\s*event #1/); assert.match(t, /cannot be relied on/);
  assert.doesNotMatch(t, /tamper|immutable/i);
  assert.equal(await page.locator('tr.bad').count(), 1);
  await goto(page, 'overview', 'Overview');
  assert.match(await page.locator('[aria-label="Audit chain"]').innerText(), /FAILED/);
  await goto(page, 'sessions', 'Sessions');
  assert.match(await page.locator('table').innerText(), /FAILED/);
  await done(page);
});

test('policy is read-only: settings, tools, rule table with configured actions, and pinning wording', async () => {
  const page = await open('policy');
  await page.waitForSelector('.kv');
  let t = await page.locator('main').innerText();
  assert.match(t, /workspace/); assert.match(t, /MATCHES THIS FILE/); assert.match(t, /Read-only/);
  assert.equal(await page.locator('main input, main textarea, main select').count(), 0, 'nothing to edit');
  await page.click('a:has-text("Tools")');
  await page.waitForSelector('article.card');
  t = await page.locator('main').innerText();
  assert.match(t, /mail__send_message/); assert.match(t, /EGRESS/); assert.match(t, /\/secrets\/\*/);
  await page.click('.tabs a:has-text("Rules")');
  await page.waitForSelector('table');
  assert.equal(await page.locator('table tbody tr').count(), 12);
  assert.match(await page.locator('table tbody tr', { hasText: 'R-FLOW-CONF' }).innerText(), /DENY[\s\S]*HOLD/);
  await page.locator('table tbody tr', { hasText: 'R-GATE' }).locator('button').click();
  await page.locator('dialog#sheet').waitFor({ state: 'visible' });
  await page.waitForFunction(() => document.querySelector('#sheet-body').textContent.includes('OFF'));
  assert.match(await page.locator('dialog#sheet').innerText(), /OFF/);
  await page.keyboard.press('Escape');
  await page.click('.tabs a:has-text("Tool pinning")');
  await page.waitForSelector('.big-status');
  t = await page.locator('main').innerText();
  assert.match(t, /TOOL DEFINITIONS PINNED ✓/); assert.match(t, /does not record which lock file the gateway ran with/);
  assert.match(t, /advanced: pinned digests/i);
  await done(page);
});

test('mask hides destinations and clear arguments on screen and keeps digests', async () => {
  const page = await open('sessions/live-2/flow');
  await page.waitForSelector('#call-c5');
  assert.match(await page.locator('#call-c5').innerText(), /verify@evil\.example/);
  await page.click('#mask');
  await page.waitForFunction(() => !document.querySelector('#call-c5').innerText.includes('verify@evil.example'));
  const t = await page.locator('#call-c5').innerText();
  assert.match(t, /v•••@•••\.example/); assert.match(t, /sha256/);
  assert.doesNotMatch(await page.locator('main').innerText(), /payroll/);
  assert.equal(await page.locator('#mask').getAttribute('aria-pressed'), 'true');
  await done(page);
});

test('demo: synthetic and recorded runs are labelled, computed by the gateway, and never mixed with the live sessions', async () => {
  const page = await open('demo');
  assert.match(await page.locator('.banner-demo').innerText(), /SYNTHETIC DEMONSTRATION/);
  await page.getByRole('button', { name: 'LOAD SYNTHETIC DEMO' }).click();
  await page.waitForSelector('.demo-cols', { timeout: 15000 });
  let t = await page.locator('main').innerText();
  assert.match(t, /SYNTHETIC DEMO/); assert.match(t, /NO GATEWAY/); assert.match(t, /WEIR \+ CAREFUL SIMULATED APPROVER/); assert.match(t, /WEIR \+ APPROVE-EVERYTHING SIMULATED APPROVER/);
  assert.match(t, /No audit record exists for this arm/); assert.match(t, /planted secret reached the attacker/);
  assert.match(t, /Held, approver declined, blocked/); assert.match(t, /Held, approver approved, ran/);
  assert.equal(await page.locator('.dcol').count(), 3);
  await page.getByRole('link', { name: 'Open full flow' }).last().click();
  await page.waitForSelector('.fcall');
  assert.equal(await page.locator('.sb[data-source="synthetic-demo"]').count() >= 1, true);
  assert.equal(await page.locator('.sb-live, .sb-idle').count(), 0, 'a demo session never looks live');
  assert.match(await page.locator('.banner-demo').innerText(), /SYNTHETIC DEMO/);
  assert.match(await page.locator('.banner-demo').innerText(), /simulated approver/);
  await page.goto(`${BASE}/#/demo`);
  await page.getByRole('button', { name: 'LOAD RECORDED REAL-MODEL REPLAY' }).click();
  await page.waitForFunction(() => document.querySelector('.sb-recorded'), null, { timeout: 15000 });
  t = await page.locator('main').innerText();
  assert.match(t, /RECORDED REAL-MODEL REPLAY/); assert.match(t, /recorded from a local run/);
  await page.getByRole('link', { name: 'Open full flow' }).first().click();
  await page.waitForSelector('.fcall');
  assert.equal(await page.locator('.sb[data-source="recorded-replay"]').count() >= 1, true);
  assert.equal(await page.locator('.sb-live, .sb-idle').count(), 0, 'a recorded session never looks live');
  await goto(page, 'sessions', 'Sessions');
  assert.equal(await page.locator('table tbody tr').count(), 4, 'the live list has only live sessions');
  assert.doesNotMatch(await page.locator('table').innerText(), /demo-/);
  await done(page);
});

test('keyboard: the skip link comes first, focus is visible, and the theme can be switched', async () => {
  const page = await open('overview');
  await page.keyboard.press('Tab');
  assert.equal(await page.evaluate(() => document.activeElement.className), 'skip');
  const ring = await page.evaluate(() => { const s = getComputedStyle(document.activeElement); return [s.outlineStyle, s.outlineWidth]; });
  assert.deepEqual(ring, ['solid', '2px']);
  await page.keyboard.press('Enter');
  assert.equal(await page.evaluate(() => document.activeElement.id), 'main');
  for (let i = 0; i < 3; i++) await page.keyboard.press('Tab');
  const reached = await page.evaluate(() => document.activeElement.closest('nav, main, .tools') !== null);
  assert.equal(reached, true);
  const before = await page.evaluate(() => getComputedStyle(document.body).backgroundColor);
  await page.click('#theme');
  const after = await page.evaluate(() => getComputedStyle(document.body).backgroundColor);
  assert.notEqual(before, after);
  await done(page);
});

test('reduced motion turns the animations off', async () => {
  const on = await open('overview', { reducedMotion: 'no-preference' });
  assert.equal(await on.locator('.poll i').evaluate((e) => getComputedStyle(e).animationName), 'pulse');
  await done(on);
  const off = await open('overview', { reducedMotion: 'reduce' });
  assert.equal(await off.locator('.poll i').evaluate((e) => getComputedStyle(e).animationName), 'none');
  const t = await off.locator('.btn').first().evaluate((e) => getComputedStyle(e).transitionDuration);
  assert.match(t, /^0s(, 0s)*$/);
  await done(off);
});

test('dark colour scheme renders every view without errors', async () => {
  const page = await open('overview', { scheme: 'dark' });
  for (const r of ['overview', 'sessions/live-2/flow', 'approvals', 'audit', 'policy/rules', 'demo']) {
    await page.goto(`${BASE}/#/${r}`);
    await page.waitForSelector('main .page');
  }
  assert.notEqual(await page.evaluate(() => getComputedStyle(document.body).backgroundColor), 'rgb(246, 247, 249)');
  await done(page);
});

for (const width of WIDTHS) {
  test(`layout at ${width}px: no page-level horizontal overflow on any view, and ${width < 768 ? 'touch targets of at least 44px, stacked flow' : 'sidebar navigation'}`, async () => {
    const page = await open('overview', { width, height: width < 500 ? 844 : 900, touch: width < 500 });
    for (const r of ROUTES) {
      await page.goto(`${BASE}/#/${r}`);
      await page.waitForSelector('main .page');
      await page.waitForTimeout(150);
      const over = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
      assert.equal(over <= 0, true, `${r} overflows by ${over}px at ${width}`);
    }
    await page.goto(`${BASE}/#/sessions/live-2/flow`);
    await page.waitForSelector('.fcall');
    const cols = await page.locator('.fgrid').first().evaluate((e) => getComputedStyle(e).gridTemplateColumns.split(' ').length);
    assert.equal(cols, width <= 860 ? 1 : 3);
    const rail = await page.locator('.rail').evaluate((e) => getComputedStyle(e).position);
    assert.equal(rail, width <= 768 ? 'fixed' : 'sticky');
    if (width <= 768) {
      const small = [];
      for (const route of ['approvals', 'sessions/live-2/flow', 'policy/rules', 'demo']) {
        await page.goto(`${BASE}/#/${route}`);
        await page.waitForSelector('main .page');
        const found = await page.$$eval('button, .btn, .iconbtn, .rc, .seg button, .tabs a, .nav a, summary', (els) => els.filter((e) => e.offsetParent !== null && !e.closest('dialog:not([open])')).map((e) => [e.textContent.trim().slice(0, 24), Math.round(e.getBoundingClientRect().height)]).filter(([, h]) => h < 44));
        small.push(...found.map((f) => `${route}: ${f.join(' ')}`));
      }
      assert.deepEqual(small, [], 'every touch target is at least 44px tall');
    }
    await done(page);
  });
}

test('live updates: a call the gateway makes now appears in the open flow without a reload, and is announced', async () => {
  const page = await open('sessions/live-1/flow');
  await page.waitForSelector('.fcall');
  const before = await page.locator('.fcall').count();
  const r = spawnSync(need('WEIR_PYTHON'), [need('WEIR_MORE_CALLS'), need('WEIR_UI_DB')], { encoding: 'utf8' });
  assert.equal(r.status, 0, r.stderr);
  await page.waitForFunction((n) => document.querySelectorAll('.fcall').length > n, before, { timeout: 8000 });
  assert.equal(await page.locator('.fcall').count(), before + 1);
  assert.equal(await page.locator('.fcall.is-new').count() <= 1, true);
  assert.match(await page.locator('#announce').innerText(), /^New ALLOW: c\d+ web__fetch_url/);
  assert.match(await page.locator('.poll').innerText(), /polling/);
  await done(page);
});

test('approvals: a person approves one exact call after a second confirmation, and the page and the database agree', async () => {
  const page = await open('approvals');
  await page.waitForSelector('.ap');
  assert.equal(await page.locator('.ap').count(), 2);
  const card = page.locator('.ap', { hasText: 'live-1' });
  const id = (await card.locator('.ap-h .mono').innerText()).trim();
  assert.match(await card.innerText(), /APPROVAL REQUIRED/);
  assert.match(await card.innerText(), /next identical call/);
  await card.getByRole('button', { name: 'Approve once' }).click();
  const go = page.getByRole('button', { name: /Confirm: approve this exact call/ });
  await go.waitFor();
  assert.equal(await page.evaluate(() => document.activeElement.tagName) !== 'BODY', true);
  assert.equal((await api('d/live/approvals')).approvals.find((a) => a.id === id).state, 'pending', 'one click changes nothing');
  await go.click();
  await page.waitForFunction((i) => document.querySelector(`#ap-${i}`)?.innerText.includes('APPROVED'), id, { timeout: 8000 });
  const t = await page.locator(`#ap-${id}`).innerText();
  assert.match(t, /Approved\. The gateway is waiting for the agent to repeat the identical call/);
  assert.match(t, /person, via this dashboard/);
  const row = (await api('d/live/approvals')).approvals.find((a) => a.id === id);
  assert.equal(row.state, 'approved'); assert.equal(row.resolved_by_raw, 'dashboard');
  await done(page);
});

test('approvals: deny is also two steps, and a stale page cannot decide an approval that has already been decided', async () => {
  const stale = await open('approvals');
  await stale.waitForSelector('.ap');
  await stale.route('**/api/pulse*', (r) => r.abort());
  const pendingCards = stale.locator('.ap:has-text("WAITING FOR A PERSON")');
  assert.equal(await pendingCards.count(), 1);
  const id = (await pendingCards.first().locator('.ap-h .mono').innerText()).trim();
  // someone else (another tab, or the command line) resolves it first
  const other = await open('approvals');
  await other.waitForSelector('.ap');
  await other.locator('.ap:has-text("WAITING FOR A PERSON")').getByRole('button', { name: 'Deny' }).click();
  await other.getByRole('button', { name: /Confirm: deny this exact call/ }).click();
  await other.waitForFunction((i) => document.querySelector(`#ap-${i}`)?.innerText.includes('DENIED'), id, { timeout: 8000 });
  assert.match(await other.locator(`#ap-${id}`).innerText(), /Denied\. Repeating the identical call is blocked \(R-APPROVAL-DENIED\)/);
  // the stale page still shows the buttons; pressing them changes nothing and says why
  await stale.locator(`#ap-${id}`).getByRole('button', { name: 'Approve once' }).click();
  await stale.getByRole('button', { name: /Confirm: approve this exact call/ }).click();
  await stale.waitForSelector('.ap-res[role="alert"]', { timeout: 8000 });
  assert.match(await stale.locator('.ap-res[role="alert"]').innerText(), /already (denied|approved)|Nothing was changed/);
  assert.equal((await api('d/live/approvals')).approvals.find((a) => a.id === id).state, 'denied');
  await done(other);
  await stale.ctx.close();
});

test('approvals: nothing waiting shows an explanation, and resolved approvals show who decided', async () => {
  const page = await open('approvals');
  await page.waitForSelector('main .page');
  assert.match(await page.locator('main').innerText(), /Nothing is waiting for a decision/);
  await page.getByRole('button', { name: 'Resolved' }).click();
  await page.waitForSelector('.ap');
  const t = await page.locator('main').innerText();
  assert.match(t, /Resolved by person, via this dashboard/); assert.match(t, /cli-user \(command line\)/);
  await done(page);
});
