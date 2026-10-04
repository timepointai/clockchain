// Local browser smoke run, not part of `node --test`: it needs Playwright and
// a Chromium, which CI does not install. Run after `build.sh --fixture`:
//
//   node web/explorer/test/browser-smoke.mjs
//
// Serves dist/ on a loopback port, opens every view over the synthetic
// fixture, runs "Verify in your browser" with the recorded export, and fails
// on any console error, CSP violation, failed request or wrong outcome.
import http from 'node:http';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { createRequire } from 'node:module';
import { explorer } from './fixture.mjs';

const require = createRequire(import.meta.url);
let chromium;
try {
  ({ chromium } = require('playwright'));
} catch {
  ({ chromium } = require(path.join(process.execPath, '../../lib/node_modules/playwright')));
}
const dist = path.join(explorer, 'dist');
const types = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.json': 'application/json', '.wasm': 'application/wasm' };
const server = http.createServer(async (req, res) => {
  const rel = decodeURIComponent(new URL(req.url, 'http://x').pathname).replace(/^\/+/, '') || 'index.html';
  const file = path.join(dist, path.normalize(rel));
  if (!file.startsWith(dist)) return res.writeHead(403).end();
  try {
    const body = await readFile(file);
    res.writeHead(200, { 'content-type': types[path.extname(file)] ?? 'application/octet-stream' }).end(body);
  } catch {
    res.writeHead(404).end();
  }
});
await new Promise((r) => server.listen(0, '127.0.0.1', r));
const base = `http://127.0.0.1:${server.address().port}/index.html?fixture=synthetic`;

const browser = await chromium.launch(process.env.CHROMIUM ? { executablePath: process.env.CHROMIUM } : {});
const page = await browser.newPage();
const problems = [];
// HTTP errors are judged by URL below; the browser's own console line for
// them carries no URL. Only the deliberately unrecorded as_of read may 404.
const UNRECORDED = `.as_of.${'7f'.padEnd(64, '0')}.json`;
page.on('console', (m) => m.type() === 'error' && !m.text().startsWith('Failed to load resource') && problems.push(`console: ${m.text()}`));
page.on('response', (r) => r.status() >= 400 && !r.url().endsWith(UNRECORDED) && problems.push(`HTTP ${r.status()}: ${r.url()}`));
page.on('pageerror', (e) => problems.push(`pageerror: ${e.message}`));
page.on('requestfailed', (r) => problems.push(`requestfailed: ${r.url()}`));
const expect = (ok, what) => {
  if (!ok) problems.push(`expected: ${what}`);
  else console.log(`ok - ${what}`);
};

await page.goto(base);
await page.waitForSelector('main table');
const subjects = await page.$$eval('main tbody tr', (rows) => rows.length);
expect(subjects === 3, 'subjects list shows the 3 fixture subjects');
expect((await page.textContent('main .banner')).includes('Not verified yet'), 'the subjects view is labelled not verified before a run');
await page.click('text=synthetic/harbour-press');
await page.waitForSelector('blockquote');
const claim = await page.textContent('blockquote');
expect(claim.includes('two presses'), 'subject view shows the current revision prose');
expect((await page.textContent('main')).includes('1901-03-05'), 'subject view renders the asserted time');
const subjectUrl = page.url();
const checks = await page.$$eval('.check li', (l) => l.map((x) => x.textContent));
expect(checks.length === 2 && checks.every((c) => c.startsWith('pass')), `subject and prose reads verify on the page (${checks.length})`);
expect((await page.textContent('main')).includes('hashes to the committed body'), 'displayed prose is confirmed against its body hash');
await page.fill('input[name=asof]', '1901-03-04');
await page.click('form.inline button');
await page.waitForFunction(() => location.hash.includes('/as_of/'));
const hidden = await page.waitForFunction(() => document.querySelector('main').textContent.includes('after_as_of'), null, { timeout: 10000 }).then(() => true, () => false);
expect(hidden, 'as_of read before the asserted day hides the revision');
expect((await page.$$eval('.check li', (l) => l.map((x) => x.textContent))).every((c) => c.startsWith('pass')), 'the as_of read verifies');
// A tampered prose response: the page must say so, not present it as the claim.
await page.route('**/prose.json', async (route) => {
  const r = await route.fetch();
  const body = JSON.parse(await r.text());
  if (body.prose) body.prose += ' Altered in transit.';
  await route.fulfill({ response: r, body: JSON.stringify(body) });
});
await page.goto(subjectUrl);
const flagged = await page.waitForFunction(() => document.querySelector('main').textContent.includes('was NOT confirmed'), null, { timeout: 10000 }).then(() => true, () => false);
expect(flagged, 'tampered prose is flagged as unconfirmed');
expect((await page.$$eval('.check li', (l) => l.map((x) => x.textContent))).some((c) => c.startsWith('fail')), 'tampered prose fails read:prose on the page');
await page.unroute('**/prose.json');
// The verified prose of the subject's OLDER revision, served for the current
// one: it hashes correctly, but it is not the current claim.
const older = await page.evaluate(async () => {
  const snap = await (await fetch('./fixtures/synthetic/snapshot.json')).json();
  const hex = (b) => b.map((x) => x.toString(16).padStart(2, '0')).join('');
  const sub = location.hash.split('/')[2];
  const cur = (await (await fetch(`./fixtures/synthetic/subjects/${sub}.json`)).json()).revision.id;
  return snap.revisions.map((r) => ({ id: hex(r.id), subject: hex(r.subject) })).find((r) => r.subject === sub && r.id !== hex(cur)).id;
});
await page.route('**/prose.json', async (route) => {
  const r = await route.fetch({ url: route.request().url().replace(/revisions\/[0-9a-f]{64}\//, `revisions/${older}/`) });
  await route.fulfill({ response: r });
});
await page.goto(`${subjectUrl.split('#')[0]}#/`);
await page.goto(subjectUrl);
const swapped = await page.waitForFunction(() => document.querySelector('main').textContent.includes('another revision than the current one'), null, { timeout: 10000 }).then(() => true, () => false);
expect(swapped, 'verified prose of an older revision is not shown as the current claim');
await page.unroute('**/prose.json');
// An as_of that was never recorded is a refusal, not a failed verification.
await page.goto(`${subjectUrl}/as_of/${'7f'.padEnd(64, '0')}`);
const refused = await page.waitForFunction(() => document.querySelector('main').textContent.includes('not_recorded'), null, { timeout: 10000 }).then(() => true, () => false);
expect(refused, 'an unrecorded as_of read is shown as a refusal');
await page.goto(subjectUrl);
await page.waitForSelector('text=printing-and-publishing path');
await page.click('text=printing-and-publishing path');
await page.waitForSelector('.kind-path li');
const path3 = await page.$$eval('.kind-path li strong', (l) => l.map((x) => x.textContent));
expect(path3.length === 3 && path3.every((s) => !/-/.test(s)), `TT kind path has 3 labelled levels (${path3.join(' > ')})`);
await page.goto(`${base}#/dag`);
await page.waitForSelector('svg.dag g.node');
expect((await page.$$('svg.dag g.node')).length === 11, 'DAG draws 10 events and 1 missing parent');
await page.goto(`${base}#/edges`);
await page.waitForSelector('form.inline');
await page.click('text=Query support');
await page.waitForSelector('#support-result .badge');
expect((await page.textContent('#support-result')).includes('supported'), 'support query answers from the fixture');
expect((await page.textContent('#support-result .check')).startsWith('pass'), 'the support read names the verified commitment');
await page.goto(`${base}#/verify`);
await page.click('button.primary');
await page.waitForSelector('#verify-result .outcome');
const outcome = await page.textContent('#verify-result .outcome .badge');
expect(outcome === 'verified', `verify outcome with the recorded export is "${outcome}"`);
const notRecomputed = await page.textContent('main');
expect(notRecomputed.includes('The fold itself.'), 'report states that the fold is not recomputed');
await page.uncheck('input[name=recorded]');
await page.click('button.primary');
await page.waitForFunction(() => document.querySelector('#verify-result .outcome .badge')?.textContent === 'partial');
expect(true, 'without an export the outcome is partial');
await page.goto(`${base}#/dag`);
await page.waitForSelector('main .banner');
expect((await page.getAttribute('main .banner', 'class')).includes('partial'), 'after a partial run the DAG view is labelled partial');
await page.screenshot({ path: path.join(explorer, 'dist', 'verify.png'), fullPage: true });

await browser.close();
server.close();
if (problems.length) {
  console.error(problems.join('\n'));
  process.exit(1);
}
console.log('browser smoke run passed');
