import type { FastifyInstance, FastifyRequest } from 'fastify';
import { createHash, randomBytes } from 'node:crypto';
import { lstat, unlink, utimes, writeFile } from 'node:fs/promises';
import { extname } from 'node:path';
import sharp from 'sharp';
import { z } from 'zod';
import { DL_ROOT, LIBRARY_ROOT, cbzPages, cbzPageAt, listChapters, withScansHeld } from './library';
import { claimPrivateContentChange, claimPrivateContentRead } from './privateFence';
import { claimWriterFolders } from './bulkNewest';
import { folderBusy } from './numbering';
import { runsInside } from './updater';
import { privateFolderOwner, scopeForSeries } from './contentScope';
import { roleOf, userIdOf } from './auth';
import { viewCtxFor } from './visibility';
import { getSeriesRow } from './libraryAdmin';
import { one, q, tx } from './db';
import { containedPath, realContainedPath } from './fsGuard';
import { renameRetry } from './fsAtomic';
import { pageFileVersionOf } from './pageCleanupFiles';
import { isEncryptedPage } from './encryptedMedia';
import { pageCmp } from './naming';
import { libraryChanged } from './discoverIdentity';

const AdmZip = require('adm-zip');
const MAX_BYTES = 64 * 1024 * 1024;
const MAX_PAGES = 2000;

type BookFile = { id: string; root: string; file: string; pruned_at: string | null };
type JournalFile = Pick<BookFile, 'root' | 'file'> & { suffix: string };
type Job = { series_id: string; files: JournalFile[]; committed: boolean };

function refuse(statusCode: number, code: string): never {
  throw Object.assign(new Error(code), { statusCode, code });
}

async function paths({ root, file, suffix }: JournalFile) {
  // Stage beside the archive so both renames are on its filesystem. The scanner ignores these suffixes.
  const all = await Promise.all([file, file + suffix + '.tmp', file + suffix + '.bak'].map(async rel => {
    const abs = containedPath(root, rel);
    if (!abs || await realContainedPath(root, rel) !== abs) refuse(409, 'unsafe_archive');
    return abs;
  }));
  return { archive: all[0], staged: all[1], backup: all[2] };
}

async function exists(file: string) {
  return lstat(file).catch(error => {
    if (error.code === 'ENOENT') return null;
    throw error;
  });
}

async function remove(file: string) {
  await unlink(file).catch(error => { if (error.code !== 'ENOENT') throw error; });
}

async function settle(job: Job) {
  for (const file of job.files) {
    const { archive, staged, backup } = await paths(file);
    if (job.committed) await remove(backup);
    else if (await exists(backup)) await renameRetry(backup, archive);
    await remove(staged);
  }
  await q('DELETE FROM series_encryption_jobs WHERE series_id = $1', [job.series_id]);
}

export async function recoverSeriesEncryption() {
  for (const job of await q<Job>('SELECT * FROM series_encryption_jobs')) await settle(job);
}

async function ownedSeries(req: FastifyRequest, id: string) {
  const uid = userIdOf(req);
  const scope = await scopeForSeries(await viewCtxFor(uid, roleOf(req)), id, { write: true });
  if (scope?.visibility !== 'private' || scope.ownerUserId !== uid || scope.libraryId !== `private_${uid}`) refuse(404, 'not_found');
  const series = await getSeriesRow(id);
  if (!series || privateFolderOwner(series.folder) !== uid) refuse(404, 'not_found');
  return series;
}

async function manifest(series: NonNullable<Awaited<ReturnType<typeof getSeriesRow>>>) {
  const rows = await q<BookFile>('SELECT id, root, file, pruned_at FROM lib_books WHERE series_id = $1 ORDER BY id', [series.id]);
  const books = [], suffix = '.yomi-encryption-' + randomBytes(8).toString('hex');
  let totalBytes = 0, totalPages = 0;
  for (const row of rows) {
    const file = { ...row, root: row.root || LIBRARY_ROOT, suffix };
    if (row.pruned_at || !/\.(cbz|zip)$/i.test(row.file) || row.file.slice(0, row.file.lastIndexOf('/')) !== series.folder)
      refuse(409, 'unsupported_archive');
    const { archive } = await paths(file);
    const stat = await exists(archive);
    if (!stat?.isFile() || stat.nlink !== 1) refuse(409, 'unsafe_archive');
    totalBytes += stat.size;
    if (totalBytes > MAX_BYTES) refuse(413, 'conversion_too_large');
    const pages = await cbzPages(archive);
    totalPages += pages.length;
    if (!pages.length || totalPages > MAX_PAGES) refuse(413, 'conversion_too_large');
    books.push({ file, pages, version: pageFileVersionOf(stat), mtime: stat.mtime, atime: stat.atime, mode: stat.mode & 0o777 });
  }
  // An unindexed archive would be left in its old mode. Refuse before touching any file.
  for (const root of new Set([DL_ROOT, LIBRARY_ROOT, ...books.map(b => b.file.root)])) {
    const folder = containedPath(root, series.folder);
    if (!folder || (await exists(folder) && await realContainedPath(root, series.folder) !== folder)) refuse(409, 'unsafe_archive');
    if (!await exists(folder)) continue;
    const names = new Set(books.filter(b => b.file.root === root).map(b => b.file.file.slice(series.folder.length + 1)));
    if ((await listChapters(folder)).some(name => !names.has(name))) refuse(409, 'unsupported_archive');
  }
  const revision = createHash('sha256').update(JSON.stringify([series.encrypted, books.map(b => [b.file.id, b.version])])).digest('hex');
  return { revision, books, totalPages };
}

async function stage(req: FastifyRequest, books: Awaited<ReturnType<typeof manifest>>['books'], encrypted: boolean, totalPages: number) {
  if (!totalPages) return;
  if (!req.isMultipart()) refuse(415, 'bad_request');
  const parts = req.parts({ limits: { files: totalPages + 1, parts: totalPages + 1, fields: 0, fileSize: MAX_BYTES } })[Symbol.asyncIterator]();
  let bytes = 0;
  try {
    for (const book of books) {
      const { archive, staged } = await paths(book.file);
      const zip = new AdmZip(archive);
      const order: string[] = [];
      for (const name of book.pages) {
        if (!zip.getEntry(name)) refuse(409, 'unsupported_archive');
        const { value: part, done } = await parts.next();
        if (done || part.type !== 'file' || part.fieldname !== 'pages') refuse(400, 'incomplete_conversion');
        const chunks: Buffer[] = [];
        for await (const chunk of part.file) {
          bytes += chunk.length;
          if (bytes > MAX_BYTES) refuse(413, 'conversion_too_large');
          chunks.push(chunk);
        }
        const page = Buffer.concat(chunks);
        if (!page.length || part.file.truncated || isEncryptedPage(page) !== encrypted) refuse(400, 'invalid_page');
        let target = name;
        if (!encrypted) {
          const { format } = await sharp(page, { limitInputPixels: 64 * 1024 * 1024 }).metadata();
          if (!format || !['jpeg', 'png', 'webp', 'gif', 'heif'].includes(format)) refuse(400, 'invalid_page');
          const suffix = format === 'jpeg' ? '.jpg' : format === 'heif' ? '.avif' : '.' + format;
          const current = extname(name);
          if (current.toLowerCase() !== suffix && !(format === 'jpeg' && current.toLowerCase() === '.jpeg')) {
            target = name.slice(0, -current.length) + suffix;
            if (zip.getEntry(target)) refuse(409, 'unsupported_archive');
            zip.deleteFile(name);
          }
        }
        if (target === name) zip.updateFile(name, page);
        else zip.addFile(target, page);
        order.push(target);
      }
      if (order.some((name, i) => i > 0 && pageCmp(order[i - 1], name) > 0)) refuse(409, 'unsupported_archive');
      await writeFile(staged, zip.toBuffer(), { flag: 'wx', mode: book.mode, flush: true });
      await utimes(staged, book.atime, book.mtime);
    }
    if (!(await parts.next()).done) refuse(400, 'incomplete_conversion');
  } finally {
    await parts.return?.(undefined);
  }
}

export function seriesEncryptionRoutes(app: FastifyInstance) {
  app.get('/api/series/:id/encryption', async (req, reply) => {
    reply.header('cache-control', 'private, no-store');
    const { id } = req.params as { id: string };
    const series = await ownedSeries(req, id);
    const { revision, books } = await manifest(series);
    return { encrypted: series.encrypted, revision, books: books.map(b => ({ id: b.file.id, pages: b.pages.length, version: b.version })) };
  });

  app.get('/api/series/:id/encryption/:bookId/:page', async (req, reply) => {
    const { id, bookId, page } = req.params as { id: string; bookId: string; page: string };
    const { version } = req.query as { version?: string };
    const lease = claimPrivateContentRead([id]);
    if (!lease) refuse(409, 'busy');
    try {
      const series = await ownedSeries(req, id);
      const book = await one<BookFile>('SELECT id, root, file, pruned_at FROM lib_books WHERE id = $1 AND series_id = $2', [bookId, id]);
      if (!book || book.pruned_at || !/\.(cbz|zip)$/i.test(book.file) || book.file.slice(0, book.file.lastIndexOf('/')) !== series.folder)
        refuse(404, 'not_found');
      const archive = await realContainedPath(book.root || LIBRARY_ROOT, book.file);
      if (!archive || !Number.isSafeInteger(Number(page)) || Number(page) < 1) refuse(404, 'not_found');
      const stat = await exists(archive);
      if (!stat?.isFile() || stat.size > MAX_BYTES || pageFileVersionOf(stat) !== version) refuse(409, 'series_changed');
      const data = await cbzPageAt(archive, Number(page) - 1);
      if (!data || pageFileVersionOf(await lstat(archive)) !== version || isEncryptedPage(data.bytes) !== series.encrypted)
        refuse(409, 'series_changed');
      const suffix = extname(data.name).toLowerCase().slice(1);
      return reply.header('cache-control', 'private, no-store')
        .header('x-content-type-options', 'nosniff')
        .type(series.encrypted ? 'application/octet-stream' : 'image/' + (suffix === 'jpg' ? 'jpeg' : suffix))
        .send(data.bytes);
    } finally { lease.release(); }
  });

  app.put('/api/series/:id/encryption', async req => {
    const { id } = req.params as { id: string };
    const input = z.object({ encrypted: z.enum(['1', '0']).transform(v => v === '1'), revision: z.string().length(64) }).safeParse(req.query);
    if (!input.success) refuse(400, 'bad_request');
    const { encrypted, revision } = input.data;
    const series = await ownedSeries(req, id);
    const lease = claimPrivateContentChange(id);
    if (!lease) refuse(409, 'busy');
    const writer = claimWriterFolders([series.folder], folderBusy, () => runsInside(id) > 0);
    if (!writer) {
      lease.release();
      refuse(409, 'busy');
    }
    try {
      const current = await ownedSeries(req, id);
      const snapshot = await manifest(current);
      if (current.folder !== series.folder || snapshot.revision !== revision) refuse(409, 'series_changed');
      if (current.encrypted === encrypted) return { encrypted };
      const job = await one<Job>(`INSERT INTO series_encryption_jobs (series_id, files)
        VALUES ($1, $2) ON CONFLICT DO NOTHING RETURNING *`, [id, JSON.stringify(snapshot.books.map(b => b.file))]);
      if (!job) refuse(409, 'busy');
      try {
        await stage(req, snapshot.books, encrypted, snapshot.totalPages);
      } catch (error) {
        await settle(job);
        throw error;
      }
      return await withScansHeld(async () => {
        try {
          if ((await manifest(current)).revision !== revision) refuse(409, 'series_changed');
          await tx(async qq => {
            const [locked] = await qq<{ encrypted: boolean; folder: string; is_private: boolean; owner_user_id: string }>(
              'SELECT encrypted,folder,is_private,owner_user_id FROM lib_series WHERE id = $1 FOR UPDATE', [id]);
            if (!locked?.is_private || locked.owner_user_id !== userIdOf(req) || locked.folder !== current.folder || locked.encrypted !== current.encrypted)
              refuse(409, 'series_changed');
            for (const book of snapshot.books) {
              const { archive, staged, backup } = await paths(book.file);
              if (pageFileVersionOf(await lstat(archive)) !== book.version) refuse(409, 'series_changed');
              await renameRetry(archive, backup);
              await renameRetry(staged, archive);
              await qq('UPDATE lib_books SET size = $2, page_dims = NULL, page_dims_version = NULL WHERE id = $1',
                [book.file.id, (await lstat(archive)).size]);
            }
            await qq('UPDATE lib_series SET encrypted = $2 WHERE id = $1', [id, encrypted]);
            await qq('UPDATE series_encryption_jobs SET committed = true WHERE series_id = $1', [id]);
          });
        } finally {
          const pending = await one<Job>('SELECT * FROM series_encryption_jobs WHERE series_id = $1', [id]);
          if (pending) await settle(pending);
        }
        libraryChanged();
        return { encrypted };
      });
    } finally {
      writer.release();
      lease.release();
    }
  });
}
