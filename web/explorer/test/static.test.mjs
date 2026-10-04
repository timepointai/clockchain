// The page loads nothing from another origin, and served text never reaches
// an HTML parser.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile, readdir } from 'node:fs/promises';
import path from 'node:path';
import { explorer } from './fixture.mjs';

const sources = async () => {
  const js = (await readdir(path.join(explorer, 'js'))).map((f) => `js/${f}`);
  return Promise.all(['index.html', 'style.css', ...js].map(async (f) => [f, await readFile(path.join(explorer, f), 'utf8')]));
};

test('no external URLs or CDNs in the shipped page', async () => {
  for (const [f, s] of await sources()) {
    const urls = s.match(/(?:https?:)?\/\/[a-z0-9.-]+\.[a-z]{2,}/gi) ?? [];
    // The SVG namespace is an identifier, not a fetch.
    assert.deepEqual(urls.filter((u) => u !== 'http://www.w3.org'), [], f);
    assert.doesNotMatch(s, /@import|<link[^>]+href="(?!style\.css)/, f);
  }
});

test('content security policy is same-origin only', async () => {
  const html = await readFile(path.join(explorer, 'index.html'), 'utf8');
  const csp = /Content-Security-Policy" content="([^"]+)"/.exec(html)[1];
  assert.match(csp, /default-src 'none'/);
  assert.match(csp, /script-src 'self' 'wasm-unsafe-eval';/);
  assert.match(csp, /connect-src 'self';/);
  assert.doesNotMatch(csp, /unsafe-inline|https?:|\*/);
});

test('no HTML-parsing sinks in the UI code', async () => {
  for (const [f, s] of await sources()) {
    if (!f.endsWith('.js')) continue;
    assert.doesNotMatch(s, /innerHTML|outerHTML|insertAdjacentHTML|document\.write|eval\(|new Function/, f);
  }
});
