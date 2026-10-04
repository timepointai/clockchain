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
page.on('console', (m) => m.type() === 'error' && problems.push(`console: ${m.text()}`));
page.on('pageerror', (e) => problems.push(`pageerror: ${e.message}`));
page.on('requestfailed', (r) => problems.push(`requestfailed: ${r.url()}`));
const expect = (ok, what) => {
  if (!ok) problems.push(`expected: ${what}`);
  else console.log(`ok - ${what}`);
};

await page.goto(base);
await page.waitForSelector('main table');
const subjects = await page.$$eval('main tbody tr', (rows) => rows.length);
expect(subjects === 2, 'subjects list shows the 2 fixture subjects');
await page.click('text=synthetic/harbour-press');
await page.waitForSelector('blockquote');
const claim = await page.textContent('blockquote');
expect(claim.includes('two presses'), 'subject view shows the current revision prose');
expect((await page.textContent('main')).includes('1901-03-05'), 'subject view renders the asserted time');
await page.click('text=printing-and-publishing path');
await page.waitForSelector('.kind-path li');
const path3 = await page.$$eval('.kind-path li strong', (l) => l.map((x) => x.textContent));
expect(path3.length === 3 && path3.every((s) => !/-/.test(s)), `TT kind path has 3 labelled levels (${path3.join(' > ')})`);
await page.goto(`${base}#/dag`);
await page.waitForSelector('svg.dag g.node');
expect((await page.$$('svg.dag g.node')).length === 10, 'DAG draws 9 events and 1 missing parent');
await page.goto(`${base}#/edges`);
await page.waitForSelector('form.inline');
await page.click('text=Query support');
await page.waitForSelector('#support-result .badge');
expect((await page.textContent('#support-result')).includes('supported'), 'support query answers from the fixture');
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
await page.screenshot({ path: path.join(explorer, 'dist', 'verify.png'), fullPage: true });

await browser.close();
server.close();
if (problems.length) {
  console.error(problems.join('\n'));
  process.exit(1);
}
console.log('browser smoke run passed');
