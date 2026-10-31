// Fork-only: encrypting a vault's chapter files, with the vault's PUBLIC key.
//
// Two ways in:
//   - sealZipForFolder(): the downloader's one hook (lib/downloader.ts, fork-marked). A chapter fetched for a series in a
//     vault is sealed in memory and only then written, so its pages never touch the disk in the clear.
//   - sweepVaults(): every chapter file of every vault that is not sealed yet -- a series just moved into a vault, a
//     chapter another path wrote (an import, a partial chapter's completion, a page clean-up) -- sealed in place.
//
// Only CBZ/ZIP chapters can be sealed (the downloader only ever writes those). A PDF, EPUB, CBR or loose folder in a
// vault is left as it is and reported in e2e_sealed.error, so the vault page can say which.
import AdmZip from 'adm-zip';
import sharp from 'sharp';
import { readFile, rm, stat } from 'fs/promises';
import type { Stats } from 'fs';
import { createHash } from 'crypto';
import path from 'path';
import { q, one } from '../../lib/db';
import { writeAtomic } from '../../lib/fsAtomic';
import { pageFileVersionOf } from '../../lib/pageCleanupFiles';
import { env } from '../../env';
import { isSealed, newChapterKey, sealPage, vaultPublicKey, type ChapterKey } from './crypto';
import { allVaults, vaultOf } from './vaults';

/** The page names lib/library.ts counts as pages (its IMG): only those are sealed; ComicInfo.xml and manifests stay readable. */
const IMG = /\.(jpe?g|png|webp|gif|avif)$/i;
const TYPE: Record<string, string> = { jpg: 'image/jpeg', jpeg: 'image/jpeg', png: 'image/png', webp: 'image/webp', gif: 'image/gif', avif: 'image/avif' };
const typeOf = (name: string) => TYPE[name.toLowerCase().split('.').pop() || ''] || 'application/octet-stream';

/**
 * Seal every page of `zip` that is not sealed yet, under one new chapter key. Returns how many pages it sealed;
 * zero leaves the archive untouched. Entries keep their names, order and every non-page file.
 */
export async function sealZip(zip: AdmZip, libraryId: string, publicKey: string): Promise<number> {
  let ck: ChapterKey | null = null;
  let n = 0;
  for (const e of zip.getEntries()) {
    if (e.isDirectory || !IMG.test(e.entryName)) continue;
    const data = e.getData();
    if (isSealed(data)) continue;
    ck ??= newChapterKey(vaultPublicKey(publicKey), libraryId);
    const m = await sharp(data).metadata().catch(() => null);
    const sealed = sealPage(ck, data, { type: typeOf(e.entryName), width: m?.width ?? null, height: m?.height ?? null });
    // Ciphertext does not compress: stored, not deflated.
    e.setData(sealed);
    e.header.method = 0;
    n++;
  }
  return n;
}

/** The vault (if any) the series in `seriesFolder` is in. */
async function vaultForFolder(seriesFolder: string) {
  const row = await one<{ library_id: string }>(
    'SELECT library_id FROM lib_series WHERE folder = $1 AND deleted_at IS NULL ORDER BY created_at LIMIT 1', [seriesFolder]);
  return vaultOf(row?.library_id);
}

/** The downloader's hook: the bytes to write for a chapter of `seriesFolder`, sealed when its series is in a vault. */
export async function sealZipForFolder(seriesFolder: string, zip: AdmZip): Promise<Buffer> {
  const v = await vaultForFolder(seriesFolder).catch(() => null);
  if (v) await sealZip(zip, v.libraryId, v.publicKey);
  return zip.toBuffer();
}

/**
 * Drop the image cache's copies made from a chapter's plain pages before it was sealed (lib/imageCache.ts keys a
 * variant by its sha256, under CACHE_DIR/ab/cd/). Their keys hold the file's version, so they would never be served
 * again -- but they would sit on disk until the cache evicts them. Covers the variants the web asks for: the chapter
 * and series thumbnails, the page itself and its 200/400/1200-wide copies. A `?fit=` copy (Reader -> Fit pages to my
 * screen) is keyed by the screen's width and is left to the cache's own eviction.
 */
export async function purgePlainCopies(bookId: string, seriesId: string | null, before: Stats, pages: number): Promise<void> {
  const variants = [`lib-bthumb:${bookId}`];
  if (seriesId) for (const k of ['p', 'c']) for (const w of ['', ':w800', ':w1600']) variants.push(`lib-sthumb:${seriesId}:${k}${w}`);
  const v = pageFileVersionOf(before);
  for (let n = 1; n <= pages; n++) {
    variants.push(`lib-page:${bookId}:${n}:${v}`);
    for (const w of [200, 400, 1200]) variants.push(`lib-page:${bookId}:${n}:w${w}:${v}`);
  }
  for (const variant of variants) {
    const key = createHash('sha256').update(variant).digest('hex');
    const dir = path.join(env.CACHE_DIR, key.slice(0, 2), key.slice(2, 4));
    await rm(path.join(dir, `${key}.bin`), { force: true }).catch(() => {});
    await rm(path.join(dir, `${key}.json`), { force: true }).catch(() => {});
  }
}

export interface SealResult { bookId: string; sealed: number; error?: string }

/** Seal one chapter file in place, and remember that it is done. */
export async function sealBook(book: { id: string; root: string; file: string; series_id?: string }, libraryId: string, publicKey: string): Promise<SealResult> {
  const abs = path.join(book.root, book.file);
  const note = (st: { mtimeMs: number; size: number } | null, pages: number | null, error: string | null) => q(
    `INSERT INTO e2e_sealed (book_id, mtime_ms, size, pages, error, sealed_at) VALUES ($1, $2, $3, $4, $5, now())
     ON CONFLICT (book_id) DO UPDATE SET mtime_ms = EXCLUDED.mtime_ms, size = EXCLUDED.size, pages = EXCLUDED.pages,
       error = EXCLUDED.error, sealed_at = now()`,
    [book.id, st ? Math.floor(st.mtimeMs) : null, st?.size ?? null, pages, error]).catch(() => {});
  if (!/\.(cbz|zip)$/i.test(book.file)) {
    await note(await stat(abs).catch(() => null), null, 'unsupported_format');
    return { bookId: book.id, sealed: 0, error: 'unsupported_format' };
  }
  try {
    const before = await stat(abs);
    const zip = new AdmZip(await readFile(abs));
    const n = await sealZip(zip, libraryId, publicKey);
    if (n) {
      // A writer that replaced the file while it was being sealed wins; the next sweep seals its version.
      const now = await stat(abs);
      if (now.mtimeMs !== before.mtimeMs || now.size !== before.size) return { bookId: book.id, sealed: 0, error: 'changed' };
      await writeAtomic(abs, zip.toBuffer());
      // The cached page sizes were measured from the plain pages; they are read again from the sealed headers.
      await q('UPDATE lib_books SET page_dims = NULL, page_dims_version = NULL WHERE id = $1', [book.id]);
      await purgePlainCopies(book.id, book.series_id ?? null, before, zip.getEntries().filter((e) => !e.isDirectory && IMG.test(e.entryName)).length);
    }
    const pages = zip.getEntries().filter((e) => !e.isDirectory && IMG.test(e.entryName)).length;
    await note(await stat(abs), pages, null);
    return { bookId: book.id, sealed: n };
  } catch (e) {
    const error = (e as NodeJS.ErrnoException)?.code === 'EACCES' || (e as NodeJS.ErrnoException)?.code === 'EROFS'
      ? 'read_only' : String((e as Error)?.message || e).slice(0, 200);
    await note(await stat(abs).catch(() => null), null, error);
    return { bookId: book.id, sealed: 0, error };
  }
}

let sweeping: Promise<{ sealed: number; failed: number }> | null = null;

/**
 * Seal every chapter file of every vault (or of one) that changed since it was last sealed. One at a time, and only
 * one sweep at once: a second call while one runs joins it.
 */
export function sweepVaults(onlyLibrary?: string): Promise<{ sealed: number; failed: number }> {
  if (sweeping) return sweeping;
  sweeping = (async () => {
    let sealed = 0, failed = 0;
    for (const v of allVaults()) {
      if (onlyLibrary && v.libraryId !== onlyLibrary) continue;
      const books = await q<{ id: string; series_id: string; root: string; file: string; mtime_ms: number | null; size: number | null; error: string | null }>(
        `SELECT b.id, b.series_id, b.root, b.file, e.mtime_ms, e.size, e.error
           FROM lib_books b JOIN lib_series s ON s.id = b.series_id LEFT JOIN e2e_sealed e ON e.book_id = b.id
          WHERE s.library_id = $1 AND b.pruned_at IS NULL`, [v.libraryId]);
      for (const b of books) {
        const st = await stat(path.join(b.root, b.file)).catch(() => null);
        if (!st) continue;
        if (b.mtime_ms === Math.floor(st.mtimeMs) && Number(b.size) === st.size && (!b.error || b.error === 'unsupported_format')) continue;
        const r = await sealBook(b, v.libraryId, v.publicKey);
        if (r.sealed) sealed++;
        if (r.error && r.error !== 'changed') failed++;
      }
    }
    return { sealed, failed };
  })().finally(() => { sweeping = null; });
  return sweeping;
}

/** What the vault page shows: how many chapter files there are, how many are sealed, and which could not be. */
export async function sealStatus(libraryId: string) {
  const [r] = await q<{ total: number; sealed: number; failed: number }>(
    `SELECT count(*)::int AS total,
            count(*) FILTER (WHERE e.error IS NULL AND e.mtime_ms IS NOT NULL)::int AS sealed,
            count(*) FILTER (WHERE e.error IS NOT NULL AND e.error <> 'changed')::int AS failed
       FROM lib_books b JOIN lib_series s ON s.id = b.series_id LEFT JOIN e2e_sealed e ON e.book_id = b.id
      WHERE s.library_id = $1 AND b.pruned_at IS NULL`, [libraryId]);
  const problems = await q<{ title: string; file: string; error: string }>(
    `SELECT s.title, b.file, e.error FROM e2e_sealed e JOIN lib_books b ON b.id = e.book_id JOIN lib_series s ON s.id = b.series_id
      WHERE s.library_id = $1 AND e.error IS NOT NULL AND e.error <> 'changed' ORDER BY s.title, b.file LIMIT 20`, [libraryId]);
  return { ...r, problems };
}
