// JavaScript script sources: a `.js` / `.mjs` file in the scripts folder runs with this Node and answers as a source.
import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'child_process';
import { mkdtempSync, readFileSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { parseHeader, scanScripts } from '../src/lib/sources/scripts/engine';
import { javascript } from '../src/lib/sources/scripts/javascript';

const CJS = `// @name JS Demo
// @supports latest
const [cmd, ...args] = process.argv.slice(2);
const answers = {
  search: () => [{ id: 's1', title: 'Found ' + args[0] }],
  latest: () => [{ id: 's2', title: 'Newest p' + args[0] }],
  chapters: () => [{ id: 'c1', number: 1 }],
  pages: () => ['https://img.example/1.jpg'],
};
if (!answers[cmd]) { console.error('no such thing'); process.exit(1); }
console.log(JSON.stringify(answers[cmd]()));
`;

const ESM = `// @id esm-demo
const [cmd, q] = process.argv.slice(2);
await new Promise((r) => setTimeout(r, 5));
console.log(JSON.stringify(cmd === 'search' ? [{ id: 'e1', title: 'ESM ' + q }] : null));
`;

test('a .js and a .mjs file are sources', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'jssrc-'));
  writeFileSync(join(dir, 'js-demo.js'), CJS);
  writeFileSync(join(dir, 'esm.mjs'), ESM);
  const [esm, js] = scanScripts(dir, [javascript]);
  assert.equal(js.id, 'js-demo');
  assert.equal(js.name, 'JS Demo');
  assert.equal((await js.search('x'))[0].title, 'Found x');
  assert.equal((await js.latest!(3))[0].title, 'Newest p3');
  assert.deepEqual((await js.listChapters('s1')).map((c) => c.number), [1]);
  assert.deepEqual(await js.getPageUrls('c1'), ['https://img.example/1.jpg']);
  await assert.rejects(js.getSeries('s1'), /no such thing/);
  assert.equal(esm.id, 'esm-demo');
  assert.equal((await esm.search('top-level await'))[0].title, 'ESM top-level await');
});

test('the example script parses and names itself', () => {
  const file = join(__dirname, '../../docs/script-sources/mangadex.mjs');
  execFileSync(process.execPath, ['--check', file]);
  const h = parseHeader(readFileSync(file, 'utf8'));
  assert.equal(h.id, 'mangadex-js');
  assert.deepEqual(h.supports, ['latest', 'popular']);
});
