// Fork-only: serving a vault's pages. routes/images.ts calls this (one fork-marked line each in serveLibBookPage and
// serveLibBookThumb) once it has resolved the chapter file for a viewer who may see it.
//
// A sealed page goes out exactly as stored -- the server cannot decrypt it -- labelled `application/x-uchiyomi-e2e`,
// with what the viewer's service worker (web/public/e2e-sw.js) needs to open it: the vault's private key sealed to
// THIS viewer's public key. The worker unwraps it with the key the viewer's device holds and hands the reader an
// ordinary image, so the reader, the thumbnails and offline downloads need no change. Resizing (`?w=`, `?fit=`) and the
// shared image cache are skipped for these pages: both need the plain image, and the cache must not hold a copy.
//
// Returns null for every chapter outside a vault, so those take the upstream path untouched.
import type { FastifyReply, FastifyRequest } from 'fastify';
import path from 'path';
import { one } from '../../lib/db';
import { cbzPageAt } from '../../lib/library';
import { isSealed, SEALED_TYPE } from './crypto';
import { anyVaults, vaultOf } from './vaults';
import { sweepVaults } from './seal';

const IMG_TYPE: Record<string, string> = { jpg: 'image/jpeg', jpeg: 'image/jpeg', png: 'image/png', webp: 'image/webp', gif: 'image/gif', avif: 'image/avif' };

export async function e2eServePage(
  _req: FastifyRequest, reply: FastifyReply, bookId: string, abs: string, pageNo: number, userId: string | null,
): Promise<FastifyReply | null> {
  if (!anyVaults()) return null;
  const row = await one<{ library_id: string }>('SELECT s.library_id FROM lib_books b JOIN lib_series s ON s.id = b.series_id WHERE b.id = $1', [bookId]);
  const vault = vaultOf(row?.library_id);
  if (!vault) return null;
  const member = userId
    ? await one<{ wrap_alg: string; wrapped_key: string }>('SELECT wrap_alg, wrapped_key FROM e2e_vault_members WHERE library_id = $1 AND user_id = $2', [vault.libraryId, userId])
    : null;
  if (!member) return reply.code(404).send({ error: 'not_found' });
  const page = await cbzPageAt(abs, pageNo - 1).catch(() => null);
  if (!page) return reply.code(404).send({ error: 'no_page' });
  reply.header('x-content-type-options', 'nosniff');
  if (!isSealed(page.bytes)) {
    // Not sealed yet (moved in moments ago, or written by a path that does not seal): readable as it is, never cached,
    // and sealed by the sweep this starts.
    void sweepVaults(vault.libraryId).catch(() => {});
    const ext = page.name.toLowerCase().split('.').pop() || '';
    return reply.header('content-type', IMG_TYPE[ext] || 'application/octet-stream').header('cache-control', 'private, no-store').send(page.bytes);
  }
  return reply
    .header('content-type', SEALED_TYPE)
    .header('cache-control', 'private, max-age=3600')
    .header('x-e2e-vault', vault.libraryId)
    .header('x-e2e-user', userId!)
    .header('x-e2e-alg', member.wrap_alg)
    .header('x-e2e-lk', member.wrapped_key)
    .send(page.bytes);
}

/**
 * A vault series' cover when it has no cover art of its own (no source or AniList cover, no upload or link): its first
 * page, sealed, for the service worker to open -- the upstream fallback would try to thumbnail a sealed page and fail.
 * routes/images.ts serveLibSeriesThumb calls it (one fork-marked line); null for every other series.
 */
export async function e2eServeSeriesCover(
  req: FastifyRequest, reply: FastifyReply, seriesId: string, userId: string | null,
): Promise<FastifyReply | null> {
  if (!anyVaults()) return null;
  const s = await one<{ library_id: string; has_art: boolean }>(
    `SELECT s.library_id,
            EXISTS (SELECT 1 FROM series_art a WHERE a.series_id = s.id AND a.cover IS NOT NULL)
         OR EXISTS (SELECT 1 FROM series_overrides o WHERE o.series_id = s.id AND o.cover IS NOT NULL AND o.cover <> 'first_page') AS has_art
       FROM lib_series s WHERE s.id = $1`, [seriesId]);
  if (!s || !vaultOf(s.library_id) || s.has_art) return null;
  const book = await one<{ id: string; root: string; file: string }>(
    'SELECT id, root, file FROM lib_books WHERE series_id = $1 AND pruned_at IS NULL ORDER BY number, file LIMIT 1', [seriesId]);
  if (!book) return reply.code(404).send({ error: 'not_found' });
  return e2eServePage(req, reply, book.id, path.join(book.root, book.file), 1, userId);
}
