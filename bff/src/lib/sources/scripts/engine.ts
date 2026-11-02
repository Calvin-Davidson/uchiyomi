// Script sources: a source written as ONE plain script file (C#, Python, JavaScript) instead of a compiled
// plugin or an extension APK. The file lives in `SOURCES_DIR/scripts/`, is run as a child process once per
// call, and answers on stdout with JSON. Nothing is compiled ahead of time and nothing is loaded into this
// process, so a broken or slow script can only fail its own call.
//
// The protocol (docs/CONFIGURATION.md, "Script sources"):
//
//   <runner> <file> search   <query> <page>   → [series]
//   <runner> <file> series   <seriesId>       → series | null
//   <runner> <file> chapters <seriesId>       → [chapter]
//   <runner> <file> pages    <chapterId>      → [url]
//   <runner> <file> latest   <page>           → [series]   (only when the header says `@supports latest`)
//   <runner> <file> popular  <page>           → [series]   (only when the header says `@supports popular`)
//
// A series is `{ id, title, summary?, status?, genres?, author?, cover?, url?, updatedAt? }`, a chapter
// `{ id, number, title?, lang?, publishedAt?, scanlator?, url? }`. A non-zero exit is a failed call, and the
// last line of stderr is what the error says.
//
// What the source is called comes from a header of comment tags at the top of the file, so loading a script
// never runs it (a .NET script's first run compiles it, which takes seconds):
//
//   // @id        example        (default: the file name)
//   // @name      Example        (default: the id)
//   // @lang      en
//   // @base      https://example.org
//   // @referer   https://example.org/
//   // @supports  latest popular
//   // @timeout   30000          (ms per call)
//
// `#` works in place of `//` for Python.
import { execFile } from 'child_process';
import { readdirSync, readFileSync, statSync } from 'fs';
import { basename, extname, join } from 'path';
import { UNNUMBERED, type SourceAdapter, type SourceChapter, type SourceSeries } from '../types';
import { RUNNERS } from './runners';

/** How one kind of script file is run. Each language adds one of these to runners.ts. */
export interface ScriptRunner {
  /** Which language this is, for logs. */
  name: string;
  /** File extensions (with the dot, lower case) this runner takes. */
  exts: string[];
  /** The command line for one call: executable + its arguments, the protocol's own arguments appended after. */
  command(file: string, args: string[]): { cmd: string; args: string[]; env?: NodeJS.ProcessEnv };
  /** Run once before the first call, every call waiting for it (a .NET script's build). Optional. */
  warm?(file: string): { cmd: string; args: string[]; env?: NodeJS.ProcessEnv } | null;
  /** Default per-call budget in ms when the header names none. */
  timeoutMs?: number;
}

export interface ScriptHeader {
  id?: string; name?: string; lang?: string; base?: string; referer?: string;
  supports: string[]; timeout?: number; concurrency?: number;
}

/** Folder the scripts are read from: `SCRIPT_SOURCES_DIR`, else `scripts/` inside SOURCES_DIR. */
export const scriptsDir = (sourcesDir = process.env.SOURCES_DIR || '/sources'): string =>
  process.env.SCRIPT_SOURCES_DIR || join(sourcesDir, 'scripts');

const DEFAULT_TIMEOUT_MS = 30_000;
const MAX_OUTPUT = 16 * 1024 * 1024;

/** The `@tag value` lines at the top of a script (only the first 60 lines are read). */
export function parseHeader(text: string): ScriptHeader {
  const h: ScriptHeader = { supports: [] };
  for (const line of text.split(/\r?\n/).slice(0, 60)) {
    const m = /^\s*(?:\/\/+|#+|\*)\s*@([a-z]+)\s+(.+?)\s*$/i.exec(line);
    if (!m) continue;
    const key = m[1].toLowerCase(), v = m[2];
    if (key === 'id') h.id = v;
    else if (key === 'name') h.name = v;
    else if (key === 'lang') h.lang = v;
    else if (key === 'base') h.base = v;
    else if (key === 'referer') h.referer = v;
    else if (key === 'supports') h.supports.push(...v.toLowerCase().split(/[\s,]+/).filter(Boolean));
    else if (key === 'timeout' && Number(v) > 0) h.timeout = Number(v);
    else if (key === 'concurrency' && Number(v) > 0) h.concurrency = Math.floor(Number(v));
  }
  return h;
}

const slug = (s: string) => s.toLowerCase().replace(/[^a-z0-9._-]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 60);

type Cmd = { cmd: string; args: string[]; env?: NodeJS.ProcessEnv };

function exec(c: Cmd, timeout: number): Promise<string> {
  return new Promise((resolve, reject) => {
    execFile(c.cmd, c.args, {
      timeout, maxBuffer: MAX_OUTPUT, windowsHide: true, encoding: 'utf8',
      env: { ...process.env, ...c.env },
    }, (err, stdout, stderr) => {
      if (err) {
        const said = String(stderr || '').trim().split(/\r?\n/).pop() || '';
        const why = (err as any).killed ? `timed out after ${timeout}ms` : (said || err.message);
        reject(new Error(why));
      } else resolve(String(stdout));
    });
  });
}

/** The JSON a script printed: all of stdout, or (when it printed other lines too) its last line. */
export function parseOutput(out: string): unknown {
  const t = out.trim();
  if (!t) return null;
  try { return JSON.parse(t); } catch { /* fall through */ }
  const last = t.split(/\r?\n/).pop()!.trim();
  return JSON.parse(last);
}

const str = (v: unknown): string | undefined => (v == null || v === '' ? undefined : String(v));

export function toSeries(x: any, source: string): SourceSeries | null {
  const id = str(x?.id ?? x?.sourceId), title = str(x?.title);
  if (!id || !title) return null;
  const genres = Array.isArray(x.genres) ? x.genres.map(String).filter(Boolean) : undefined;
  return {
    sourceId: id, source, title,
    summary: str(x.summary ?? x.description), status: str(x.status), genres,
    author: str(x.author), coverUrl: str(x.cover ?? x.coverUrl), url: str(x.url), updatedAt: str(x.updatedAt),
  };
}

export function toChapters(list: unknown): SourceChapter[] {
  const out: SourceChapter[] = [];
  let unnumbered = 0;
  for (const x of Array.isArray(list) ? list as any[] : []) {
    const id = str(x?.id ?? x?.sourceId);
    const n = x?.number ?? x?.chapter;
    const number = n == null || n === '' ? NaN : Number(n);
    if (!id) continue;
    if (!Number.isFinite(number)) { unnumbered++; continue; }
    out.push({
      sourceId: id, number, title: str(x.title), lang: str(x.lang), publishedAt: str(x.publishedAt ?? x.date),
      scanlator: str(x.scanlator), url: str(x.url),
    });
  }
  if (unnumbered) Object.defineProperty(out, UNNUMBERED, { value: unnumbered });
  return out;
}

export function toPages(list: unknown): string[] {
  return (Array.isArray(list) ? list : []).map((p: any) => str(typeof p === 'string' ? p : p?.url)).filter((u): u is string => !!u);
}

/** One script file as a SourceAdapter. Null when no runner takes its extension. */
export function makeScriptAdapter(file: string, text = readFileSync(file, 'utf8'), runners = RUNNERS): SourceAdapter | null {
  const ext = extname(file).toLowerCase();
  const runner = runners.find((r) => r.exts.includes(ext));
  if (!runner) return null;
  const h = parseHeader(text);
  const id = slug(h.id || basename(file, extname(file)));
  if (!id) return null;
  const timeout = h.timeout ?? runner.timeoutMs ?? DEFAULT_TIMEOUT_MS;

  // At most `concurrency` processes of one script at a time (default 2): a search across every source must not
  // start a pile of interpreters for one site.
  const limit = h.concurrency ?? 2;
  let running = 0;
  const queue: (() => void)[] = [];
  const slot = async () => {
    if (running >= limit) await new Promise<void>((r) => queue.push(r));
    running++;
  };
  const release = () => { running--; queue.shift()?.(); };

  let warmed: Promise<void> | null = null;
  const warm = () => {
    if (!warmed) {
      const w = runner.warm?.(file);
      // A failed warm-up is not fatal: the call itself then says why the script does not run.
      warmed = w ? exec(w, Math.max(timeout, 300_000)).then(() => undefined, (e) => {
        console.warn(`[sources] script ${basename(file)}: ${runner.name} warm-up failed: ${(e as Error).message}`);
      }) : Promise.resolve();
    }
    return warmed;
  };

  const call = async (command: string, ...args: (string | number)[]): Promise<unknown> => {
    await warm();
    await slot();
    try {
      const out = await exec(runner.command(file, [command, ...args.map(String)]), timeout);
      try { return parseOutput(out); } catch { throw new Error('did not print JSON'); }
    } catch (e) {
      throw new Error(`script ${id} ${command}: ${(e as Error).message}`);
    } finally { release(); }
  };

  const seriesList = (r: unknown) => (Array.isArray(r) ? r : []).map((x) => toSeries(x, id)).filter((s): s is SourceSeries => !!s);
  const supports = (c: string) => h.supports.includes(c);

  const a: SourceAdapter = {
    id,
    name: h.name || id,
    ...(h.lang ? { lang: h.lang } : {}),
    ...(h.base ? { base: h.base } : {}),
    ...(h.referer ? { imageReferer: h.referer } : {}),
    search: async (q) => seriesList(await call('search', q, 1)),
    searchPage: async (q, page) => seriesList(await call('search', q, page)),
    getSeries: async (sid) => toSeries(await call('series', sid), id),
    listChapters: async (sid) => toChapters(await call('chapters', sid)),
    getPageUrls: async (cid) => toPages(await call('pages', cid)),
  };
  if (supports('latest')) a.latest = async (page = 1) => seriesList(await call('latest', page));
  if (supports('popular')) a.popular = async (page = 1) => seriesList(await call('popular', page));
  // Build ahead in the background, so the first person to search is not the one who waits for it.
  if (runner.warm) void warm();
  return a;
}

/** Every script in the scripts folder whose extension a runner takes. Missing folder → none. */
export function scanScripts(dir = scriptsDir(), runners = RUNNERS): SourceAdapter[] {
  let names: string[] = [];
  try { names = readdirSync(dir); } catch { return []; }
  const out: SourceAdapter[] = [];
  for (const f of names.sort()) {
    if (f.startsWith('.')) continue;
    const p = join(dir, f);
    try {
      if (!statSync(p).isFile()) continue;
      const a = makeScriptAdapter(p, readFileSync(p, 'utf8'), runners);
      if (a) out.push(a);
    } catch (e) { console.warn(`[sources] failed to load script ${f}: ${(e as Error)?.message}`); }
  }
  return out;
}
