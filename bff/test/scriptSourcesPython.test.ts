// Python script sources: a `.py` file in the scripts folder runs through the Python runner and answers as a source.
// Skipped where no Python is installed.
import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'child_process';
import { mkdtempSync, readFileSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { parseHeader, scanScripts } from '../src/lib/sources/scripts/engine';
import { python } from '../src/lib/sources/scripts/python';

const py = python.command('', []).cmd;
const has = (() => { try { execFileSync(py, ['--version']); return true; } catch { return false; } })();

const SCRIPT = `# @name  Py Demo
# @supports popular
import json, sys
cmd, *args = sys.argv[1:]
if cmd == "search":
    print(json.dumps([{"id": "s1", "title": "Résultat " + args[0], "genres": ["Drame"]}]))
elif cmd == "popular":
    print(json.dumps([{"id": "s2", "title": "Top page " + args[0]}]))
elif cmd == "chapters":
    print(json.dumps([{"id": "c1", "number": 1}, {"id": "c2", "number": "2"}]))
elif cmd == "pages":
    print(json.dumps(["https://img.example/1.jpg"]))
else:
    print("no such thing", file=sys.stderr); sys.exit(1)
`;

test('a .py file is a source', { skip: !has && `no ${py} here` }, async () => {
  const dir = mkdtempSync(join(tmpdir(), 'pysrc-'));
  writeFileSync(join(dir, 'py-demo.py'), SCRIPT);
  const [a] = scanScripts(dir, [python]);
  assert.equal(a.id, 'py-demo', 'the file name, when the header names no id');
  assert.equal(a.name, 'Py Demo');
  assert.equal((await a.search('été'))[0].title, 'Résultat été', 'UTF-8 both ways');
  assert.equal((await a.popular!(2))[0].title, 'Top page 2');
  assert.deepEqual((await a.listChapters('s1')).map((c) => c.number), [1, 2]);
  assert.deepEqual(await a.getPageUrls('c1'), ['https://img.example/1.jpg']);
  await assert.rejects(a.getSeries('s1'), /no such thing/);
});

test('the example script compiles and names itself', { skip: !has && `no ${py} here` }, () => {
  const file = join(__dirname, '../../docs/script-sources/mangadex.py');
  execFileSync(py, ['-m', 'py_compile', file], { env: { ...process.env, PYTHONDONTWRITEBYTECODE: '1', PYTHONPYCACHEPREFIX: tmpdir() } });
  const h = parseHeader(readFileSync(file, 'utf8'));
  assert.equal(h.id, 'mangadex-py');
  assert.deepEqual(h.supports, ['latest', 'popular']);
});
