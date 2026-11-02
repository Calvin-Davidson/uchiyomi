// C# script sources: a `.cs` file in the scripts folder is a .NET 10 file-based app, built once and run per call.
// The end-to-end case is skipped where no `dotnet` is installed.
import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'child_process';
import { mkdtempSync, readFileSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { parseHeader, scanScripts } from '../src/lib/sources/scripts/engine';
import { csharp } from '../src/lib/sources/scripts/csharp';

const has = (() => { try { execFileSync(csharp.command('', []).cmd, ['--version']); return true; } catch { return false; } })();

test('a call is `dotnet run <file> -- <args>`, so a dash in a query never reaches dotnet', () => {
  const c = csharp.command('/s/a.cs', ['search', '-x', '1']);
  assert.equal(c.cmd, 'dotnet');
  assert.deepEqual(c.args, ['run', '/s/a.cs', '--', 'search', '-x', '1']);
  assert.deepEqual(csharp.warm!('/s/a.cs')!.args, ['build', '/s/a.cs']);
});

test('the example script names itself', () => {
  const h = parseHeader(readFileSync(join(__dirname, '../../docs/script-sources/mangadex.cs'), 'utf8'));
  assert.equal(h.id, 'mangadex-cs');
  assert.deepEqual(h.supports, ['latest', 'popular']);
});

const SCRIPT = `// @name CS Demo
// @supports latest
if (args.Length == 0) return 2;
switch (args[0])
{
    case "search": Console.WriteLine($"[{{\\"id\\":\\"s1\\",\\"title\\":\\"Found {args[1]}\\"}}]"); return 0;
    case "latest": Console.WriteLine($"[{{\\"id\\":\\"s2\\",\\"title\\":\\"Newest p{args[1]}\\"}}]"); return 0;
    case "chapters": Console.WriteLine("[{\\"id\\":\\"c1\\",\\"number\\":1}]"); return 0;
    default: Console.Error.WriteLine("no such thing"); return 1;
}
`;

test('a .cs file is a source', { skip: !has && 'no dotnet here', timeout: 300_000 }, async () => {
  const dir = mkdtempSync(join(tmpdir(), 'cssrc-'));
  writeFileSync(join(dir, 'cs-demo.cs'), SCRIPT);
  const [a] = scanScripts(dir, [csharp]);
  assert.equal(a.id, 'cs-demo');
  assert.equal(a.name, 'CS Demo');
  assert.equal((await a.search('x'))[0].title, 'Found x');
  assert.equal((await a.latest!(2))[0].title, 'Newest p2');
  assert.deepEqual((await a.listChapters('s1')).map((c) => c.number), [1]);
  await assert.rejects(a.getSeries('s1'), /no such thing/);
});
