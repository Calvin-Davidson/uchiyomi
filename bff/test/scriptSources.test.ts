// Script sources (lib/sources/scripts/engine.ts): a plain script file answers the protocol on stdout and becomes
// a SourceAdapter. Driven here through a stand-in runner that runs the file with this Node, so the engine is tested
// without any particular language installed.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { makeScriptAdapter, parseHeader, scanScripts, type ScriptRunner } from '../src/lib/sources/scripts/engine';
import { unnumberedOf } from '../src/lib/sources/types';

const runner: ScriptRunner = {
  name: 'test', exts: ['.tjs'],
  command: (file, args) => ({ cmd: process.execPath, args: [file, ...args], env: { ELECTRON_RUN_AS_NODE: '1' } }),
};

const SCRIPT = `// @id    demo
// @name  Demo Site
// @lang  en
// @supports latest
const [cmd, a, b] = process.argv.slice(2);
const out = {
  search: () => [{ id: 's1', title: 'Found ' + a + ' p' + b, cover: 'https://img.example/1.jpg' }, { id: '', title: 'dropped' }],
  latest: () => [{ id: 's2', title: 'Newest p' + a }],
  series: () => a === 'none' ? null : { id: a, title: 'Series ' + a, genres: ['Action'] },
  chapters: () => [{ id: 'c1', number: 1 }, { id: 'c2', number: '2.5', title: 'Half' }, { id: 'c3', title: 'Extra' }],
  pages: () => ['https://img.example/p1.jpg', { url: 'https://img.example/p2.jpg' }],
  fail: () => { console.error('debug line'); console.error('site said no'); process.exit(3); },
}[cmd];
console.log('a debug print before the answer');
console.log(JSON.stringify(out()));
`;

const dir = mkdtempSync(join(tmpdir(), 'scriptsrc-'));
const file = join(dir, 'demo.tjs');
writeFileSync(file, SCRIPT);

test('the header names the source without running it', () => {
  const h = parseHeader(SCRIPT);
  assert.equal(h.id, 'demo');
  assert.equal(h.name, 'Demo Site');
  assert.deepEqual(h.supports, ['latest']);
  assert.equal(parseHeader('# @id py-site\n# @supports latest, popular').id, 'py-site');
});

test('a script answers every call of the adapter', async () => {
  const a = makeScriptAdapter(file, SCRIPT, [runner])!;
  assert.equal(a.id, 'demo');
  assert.equal(a.name, 'Demo Site');
  assert.equal(a.lang, 'en');
  assert.equal(typeof a.latest, 'function');
  assert.equal(a.popular, undefined, 'only what @supports names');

  const found = await a.search('one piece');
  assert.deepEqual(found.map((s) => [s.sourceId, s.title, s.source, s.coverUrl]), [['s1', 'Found one piece p1', 'demo', 'https://img.example/1.jpg']]);
  assert.equal((await a.searchPage!('x', 3))[0].title, 'Found x p3');
  assert.equal((await a.latest!(2))[0].title, 'Newest p2');
  assert.deepEqual((await a.getSeries('abc'))?.genres, ['Action']);
  assert.equal(await a.getSeries('none'), null);

  const ch = await a.listChapters('abc');
  assert.deepEqual(ch.map((c) => [c.sourceId, c.number]), [['c1', 1], ['c2', 2.5]]);
  assert.equal(unnumberedOf(ch), 1, 'a chapter without a number is counted as dropped');
  assert.deepEqual(await a.getPageUrls('c1'), ['https://img.example/p1.jpg', 'https://img.example/p2.jpg']);
});

test('a failing script fails its call with the last line it wrote to stderr', async () => {
  // A runner that turns every command into `fail`, reached through the same path a real call takes.
  const failing: ScriptRunner = { ...runner, command: (f, args) => runner.command(f, ['fail', ...args.slice(1)]) };
  const a = makeScriptAdapter(file, SCRIPT, [failing])!;
  await assert.rejects(a.search('x'), /script demo search: site said no/);
});

test('the folder scan takes only the extensions a runner knows', () => {
  writeFileSync(join(dir, 'notes.txt'), '// @id notes');
  const found = scanScripts(dir, [runner]);
  assert.deepEqual(found.map((a) => a.id), ['demo']);
  assert.deepEqual(scanScripts(join(dir, 'missing'), [runner]), []);
});
