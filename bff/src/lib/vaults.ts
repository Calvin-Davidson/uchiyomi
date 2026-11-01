// Moving a series into a vault, and back out (docs/VAULTS.md). Both run only when a member asks; there is no background work.
//
// IN: the series is read from the library as it is now (its metadata, every chapter, the mover's reading progress),
// encrypted under a new item key, and written to CONFIG_DIR/e2e-vault/<vault>/<item>/. Only then is it erased from the
// library the way an admin would (Remove, Delete files, Forget: lib/libraryAdmin.ts), so its title, chapters, progress,
// bookmarks and cached images are gone from the database and the disk. The server can't read the item after that.
//
// OUT: the member's browser opens the item key and sends it for this one request. The chapters are written back as
// CBZ files (with ComicInfo.xml) into the downloads folder under the series' old folder, and a library scan picks them
// up as a new series. The vault copy is deleted once that is done.
import { mkdir, readFile, rm, stat, writeFile } from 'fs/promises';
import { createHash, randomUUID } from 'crypto';
import path from 'path';
import AdmZip from 'adm-zip';
import sharp from 'sharp';
import { q, one } from './db';
import { env } from '../env';
import { cbzPages, cbzEntry, DL_ROOT, persistScan } from './library';
import { deleteSeries, deleteSeriesFiles, forgetSeries } from './libraryAdmin';
import { writeAtomic } from './fsAtomic';
import { ad, chapterFile, newItemKey, openRecord, openString, pageCountOf, sealRecord, sealString, vaultPublicKey } from './vaultCrypto';

export const VAULT_DIR = path.join(env.CONFIG_DIR, 'e2e-vault');
export const itemDir = (vaultId: string, itemId: string) => path.join(VAULT_DIR, vaultId, itemId);
export const chapterPath = (vaultId: string, itemId: string, n: number) => path.join(itemDir(vaultId, itemId), `${n}.bin`);
export const coverPath = (vaultId: string, itemId: string) => path.join(itemDir(vaultId, itemId), 'cover.bin');

const TYPE: Record<string, string> = { jpg: 'image/jpeg', jpeg: 'image/jpeg', png: 'image/png', webp: 'image/webp', gif: 'image/gif', avif: 'image/avif' };
const EXT: Record<string, string> = Object.fromEntries(Object.entries(TYPE).map(([k, v]) => [v, k]));
const typeOf = (name: string) => TYPE[name.toLowerCase().split('.').pop() || ''] || 'image/jpeg';

/** What an item's manifest holds: everything the vault pages show. Encrypted; the server never stores it in the clear. */
export interface Manifest {
  v: 3;
  title: string;
  folder: string;
  source: string;
  summary: string | null;
  author: string | null;
  status: string | null;
  genres: string[];
  web: string | null;
  movedAt: string;
  chapters: Array<{ number: number; title: string | null; publishedAt: string | null; pages: Array<{ t: string; w: number | null; h: number | null }> }>;
}
/** A member's reading state in one item: page reached and done, per chapter index. */
export interface ItemState { chapters: Record<string, { page: number; completed: boolean; at: string }> }

// ── Jobs: a move takes as long as reading every page, so it answers at once and is polled ─────────────────────
export interface Job { id: string; kind: 'in' | 'out'; vaultId: string; userId: string; done: number; total: number; state: 'running' | 'done' | 'failed'; error?: string; itemId?: string }
const jobs = new Map<string, Job>();
export const jobOf = (id: string, userId: string): Job | null => { const j = jobs.get(id); return j && j.userId === userId ? j : null; };
function start(job: Omit<Job, 'id' | 'done' | 'total' | 'state'>, run: (j: Job) => Promise<void>): Job {
  const j: Job = { ...job, id: randomUUID(), done: 0, total: 0, state: 'running' };
  jobs.set(j.id, j);
  void run(j).then(() => { j.state = 'done'; }, (e) => { j.state = 'failed'; j.error = String((e as Error)?.message || e).slice(0, 200); })
    .finally(() => setTimeout(() => jobs.delete(j.id), 60 * 60_000).unref());
  return j;
}
/** A series already being moved: a second click joins nothing and starts nothing. */
const busy = new Set<string>();

/** The image cache's copies of a series (lib/imageCache.ts keys by sha256 of the variant, under CACHE_DIR/ab/cd/). */
async function purgeCache(seriesId: string, books: Array<{ id: string; pages: number }>): Promise<void> {
  const variants: string[] = [];
  for (const k of ['p', 'c']) for (const w of ['', ':w800', ':w1600']) variants.push(`lib-sthumb:${seriesId}:${k}${w}`);
  for (const b of books) variants.push(`lib-bthumb:${b.id}`);
  for (const variant of variants) {
    const key = createHash('sha256').update(variant).digest('hex');
    const dir = path.join(env.CACHE_DIR, key.slice(0, 2), key.slice(2, 4));
    await rm(path.join(dir, `${key}.bin`), { force: true }).catch(() => {});
    await rm(path.join(dir, `${key}.json`), { force: true }).catch(() => {});
  }
}

/** Move one series into a vault. The caller has checked the vault role and that the series is visible to them. */
export function moveIn(vault: { id: string; publicKey: string }, seriesId: string, userId: string): Job {
  if (busy.has(seriesId)) throw Object.assign(new Error('busy'), { code: 'busy' });
  busy.add(seriesId);
  return start({ kind: 'in', vaultId: vault.id, userId }, async (job) => {
    const itemId = randomUUID();
    const dir = itemDir(vault.id, itemId);
    try {
      const s = await one<{ title: string; folder: string; source: string; summary: string | null; author: string | null; status: string | null; genres: string[]; web: string | null }>(
        'SELECT title, folder, source, summary, author, status, genres, web FROM lib_series WHERE id = $1', [seriesId]);
      if (!s) throw new Error('not_found');
      const books = await q<{ id: string; root: string; file: string; number: number; title: string | null; pages: number; published_at: Date | null }>(
        'SELECT id, root, file, number, title, pages, published_at FROM lib_books WHERE series_id = $1 AND pruned_at IS NULL ORDER BY number, file', [seriesId]);
      job.total = books.length;
      const key = newItemKey(vaultPublicKey(vault.publicKey), vault.id, itemId);
      await mkdir(dir, { recursive: true });
      const manifest: Manifest = {
        v: 3, title: s.title, folder: s.folder, source: s.source, summary: s.summary, author: s.author, status: s.status,
        genres: s.genres ?? [], web: s.web, movedAt: new Date().toISOString(), chapters: [],
      };
      let bytes = 0;
      let cover: Buffer | null = null;
      for (const [ci, b] of books.entries()) {
        const abs = path.join(b.root, b.file);
        const names = await cbzPages(abs);
        const records: Buffer[] = [];
        const pages: Manifest['chapters'][number]['pages'] = [];
        for (const [pi, name] of names.entries()) {
          const data = await cbzEntry(abs, name);
          const m = await sharp(data).metadata().catch(() => null);
          if (!cover) cover = await sharp(data).resize({ width: 400, withoutEnlargement: true }).webp({ quality: 80 }).toBuffer().catch(() => null);
          records.push(sealRecord(key.raw, data, ad.page(itemId, ci, pi)));
          pages.push({ t: typeOf(name), w: m?.width ?? null, h: m?.height ?? null });
        }
        const file = chapterFile(records);
        await writeAtomic(chapterPath(vault.id, itemId, ci), file);
        bytes += file.length;
        manifest.chapters.push({ number: b.number, title: b.title, publishedAt: b.published_at ? new Date(b.published_at).toISOString() : null, pages });
        job.done = ci + 1;
      }
      if (cover) await writeAtomic(coverPath(vault.id, itemId), sealRecord(key.raw, cover, ad.cover(itemId)));
      // The mover's progress comes along, encrypted the same way their browser will write it from now on.
      const rp = await q<{ book_id: string; page: number; completed: boolean; updated_at: Date }>(
        'SELECT book_id, page, completed, updated_at FROM read_progress WHERE user_id = $1 AND series_id = $2', [userId, seriesId]);
      const state: ItemState = { chapters: {} };
      for (const r of rp) {
        const ci = books.findIndex((b) => b.id === r.book_id);
        if (ci >= 0) state.chapters[ci] = { page: r.page, completed: r.completed, at: new Date(r.updated_at).toISOString() };
      }
      await q('INSERT INTO e2e_vault_items (id, vault_id, item_key, meta, chapters, bytes) VALUES ($1, $2, $3, $4, $5, $6)',
        [itemId, vault.id, key.sealed, sealString(key.raw, Buffer.from(JSON.stringify(manifest)), ad.meta(itemId)), books.length, bytes]);
      if (Object.keys(state.chapters).length) {
        await q('INSERT INTO e2e_vault_state (item_id, user_id, sealed) VALUES ($1, $2, $3)',
          [itemId, userId, sealString(key.raw, Buffer.from(JSON.stringify(state)), ad.state(itemId, userId))]);
      }
      key.raw.fill(0);
      job.itemId = itemId;
      // Now the library forgets it: the same three steps as Admin → Libraries.
      await deleteSeries(seriesId);
      const files = await deleteSeriesFiles(seriesId);
      if (!files.ok) throw new Error(`moved, but the library copy was not deleted: ${files.reason}`);
      const forgot = await forgetSeries(seriesId);
      if (!forgot.ok) throw new Error(`moved, but the library has not forgotten the series: ${forgot.message}`);
      await purgeCache(seriesId, books);
    } catch (e) {
      // Nothing half-made is left in the vault; a failure after the item was saved keeps it (the library copy stays too).
      if (!job.itemId) await rm(dir, { recursive: true, force: true }).catch(() => {});
      throw e;
    } finally { busy.delete(seriesId); }
  });
}

const XML = (x: string) => x.replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F]/g, '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
const safeSeg = (x: string) => x.replace(/[<>:"\\|?*\u0000-\u001F]/g, '_').replace(/^\.+/, '_').trim().slice(0, 120) || 'Series';

/** Open an item's manifest with its raw key; throws if the key is not this item's. */
export async function openManifest(item: { id: string; meta: string }, raw: Buffer): Promise<Manifest> {
  return JSON.parse(openString(raw, item.meta, ad.meta(item.id)).toString('utf8')) as Manifest;
}

/** Move one item out of a vault, back into the library. `raw` is the item key the member's browser opened. */
export function moveOut(vaultId: string, item: { id: string; meta: string }, raw: Buffer, userId: string): Job {
  if (busy.has(item.id)) throw Object.assign(new Error('busy'), { code: 'busy' });
  busy.add(item.id);
  return start({ kind: 'out', vaultId, userId }, async (job) => {
    try {
      const m = await openManifest(item, raw);
      job.total = m.chapters.length;
      // The old folder, under the downloads root; a folder already there gets a suffix rather than being mixed into.
      const segs = m.folder.split('/').filter((x) => x && x !== '.' && x !== '..').map(safeSeg);
      let rel = segs.length ? segs.join('/') : safeSeg(m.title);
      if (await stat(path.join(DL_ROOT, rel)).catch(() => null)) rel = `${rel} (from vault ${item.id.slice(0, 8)})`;
      const out = path.join(DL_ROOT, rel);
      await mkdir(out, { recursive: true });
      for (const [ci, ch] of m.chapters.entries()) {
        const file = await readFile(chapterPath(vaultId, item.id, ci));
        const n = pageCountOf(file);
        const zip = new AdmZip();
        for (let pi = 0; pi < n; pi++) {
          const start0 = Number(file.readBigUInt64BE(8 + pi * 8)), end = Number(file.readBigUInt64BE(8 + (pi + 1) * 8));
          const page = openRecord(raw, file.subarray(start0, end), ad.page(item.id, ci, pi));
          zip.addFile(`${String(pi + 1).padStart(4, '0')}.${EXT[ch.pages[pi]?.t] || 'jpg'}`, page);
        }
        zip.addFile('ComicInfo.xml', Buffer.from(`<?xml version="1.0" encoding="utf-8"?>\n<ComicInfo>\n  <Series>${XML(m.title)}</Series>\n  <Number>${ch.number}</Number>\n${ch.title ? `  <Title>${XML(ch.title)}</Title>\n` : ''}${m.summary ? `  <Summary>${XML(m.summary)}</Summary>\n` : ''}${m.author ? `  <Writer>${XML(m.author)}</Writer>\n` : ''}${m.genres.length ? `  <Genre>${XML(m.genres.join(', '))}</Genre>\n` : ''}${m.web ? `  <Web>${XML(m.web)}</Web>\n` : ''}</ComicInfo>\n`));
        // Two copies of one number (two scanlators) each keep their own file.
        const twin = m.chapters.findIndex((c) => c.number === ch.number) !== ci;
        await writeFile(path.join(out, `Chapter ${ch.number}${twin ? ` (${ci + 1})` : ''}.cbz`), zip.toBuffer());
        job.done = ci + 1;
      }
      await q('DELETE FROM e2e_vault_items WHERE id = $1', [item.id]);
      await rm(itemDir(vaultId, item.id), { recursive: true, force: true });
      await persistScan().catch(() => {});
    } finally { raw.fill(0); busy.delete(item.id); }
  });
}
