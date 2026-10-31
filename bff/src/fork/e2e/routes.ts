// Fork-only: end-to-end encrypted ("private") libraries. HTTP routes, all under /api/e2e.
//
// The server is a dumb, access-controlled store of ciphertext: it checks WHO may read or write a library and keeps
// the bytes, but every key, name and page is encrypted in the browser (web/fork/e2e/crypto.ts) before it gets here.
// Strings the client hands over (`meta`, `wrapped`, `wrappedKey`, `publicKey`) are opaque to this file; it only
// bounds their size and alphabet. See schema.ts for what each table holds and docs/fork/e2e-libraries.md.
//
// Roles, per library: `owner` (one; manages members, rotates the key, deletes the library), `editor` (adds, renames
// and removes items) and `reader`. Being an admin of the server grants nothing here: an admin holds no key.
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { z } from 'zod';
import { q, one, tx } from '../../lib/db';
import { authenticate, userIdOf } from '../../lib/auth';
import { logAudit } from '../../lib/audit';
import * as store from './store';

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const uuid = z.string().regex(UUID_RE).transform((s) => s.toLowerCase());
/** An opaque client-made string: base64url segments joined by `.` or `:`, bounded. */
const opaque = (max: number) => z.string().min(1).max(max).regex(/^[A-Za-z0-9_\-.:]+$/);
/** An algorithm or unlock-method name: `ecdh-p256`, `ecies-p256-hkdf-aesgcm`, `passphrase`, later `device`. */
const name = z.string().regex(/^[a-z0-9][a-z0-9.\-]{0,39}$/);
const params = z.record(z.string(), z.unknown()).refine((p) => JSON.stringify(p).length <= 4096, 'params too large');
const role = z.enum(['editor', 'reader']);

/** Ciphertext bytes in one uploaded chunk: the client encrypts 960 KiB pieces, which stay under nginx's 1 MiB default. */
export const CHUNK_MAX = 1024 * 1024;
/** Chunks in one item: ~3.75 GiB at the client's chunk size. */
export const MAX_CHUNKS = 4096;
/** An item that was never committed is dropped after this. */
const PENDING_TTL_HOURS = 24;

const NOT_FOUND = { error: 'not_found' } as const;
const FORBIDDEN = { error: 'forbidden' } as const;
const bad = (reply: FastifyReply, detail?: string) => reply.code(400).send({ error: 'bad_request', ...(detail ? { detail } : {}) });

type Role = 'owner' | 'editor' | 'reader';
const RANK: Record<Role, number> = { reader: 0, editor: 1, owner: 2 };

interface Membership { role: Role; key_version: number; library_key_version: number; owner_id: string }

async function membership(libraryId: string, userId: string): Promise<Membership | null> {
  return one<Membership>(
    `SELECT m.role, m.key_version, l.key_version AS library_key_version, l.owner_id
       FROM e2e_library_members m JOIN e2e_libraries l ON l.id = m.library_id
      WHERE m.library_id = $1 AND m.user_id = $2`,
    [libraryId, userId],
  );
}

interface ItemRow { id: string; library_id: string; key_version: number; wrapped_key: string; meta: string; chunks: number; size: number; state: 'pending' | 'ready'; created_by: string | null; created_at: Date; updated_at: Date }
const itemOut = (r: ItemRow) => ({
  id: r.id, libraryId: r.library_id, keyVersion: r.key_version, wrappedKey: r.wrapped_key, meta: r.meta,
  chunks: r.chunks, size: Number(r.size), state: r.state, createdBy: r.created_by, createdAt: r.created_at, updatedAt: r.updated_at,
});

/** Drop items nobody committed (an upload that was abandoned), rows and chunks both. */
export async function sweepPendingItems(): Promise<number> {
  const gone = await q<{ id: string; library_id: string }>(
    `DELETE FROM e2e_items WHERE state = 'pending' AND updated_at < now() - make_interval(hours => $1) RETURNING id, library_id`,
    [PENDING_TTL_HOURS],
  );
  for (const g of gone) await store.removeItem(g.library_id, g.id).catch(() => {});
  return gone.length;
}

export default async function e2eRoutes(app: FastifyInstance) {
  app.addHook('preHandler', authenticate);
  // Encrypted chunks arrive raw. Scoped to this plugin, so no other route starts accepting octet-stream bodies.
  app.addContentTypeParser('application/octet-stream', { parseAs: 'buffer', bodyLimit: CHUNK_MAX }, (_req, body, done) => done(null, body));

  const uid = (req: FastifyRequest) => userIdOf(req);

  /** The caller's role in a library, or a 404 already sent (a library you are not in does not exist to you). */
  async function need(req: FastifyRequest, reply: FastifyReply, libraryId: string, min: Role): Promise<Membership | null> {
    const m = await membership(libraryId, uid(req));
    if (!m) { reply.code(404).send(NOT_FOUND); return null; }
    if (RANK[m.role] < RANK[min]) { reply.code(403).send(FORBIDDEN); return null; }
    return m;
  }

  /** An item and the caller's role in its library, under the same 404 rule. */
  async function needItem(req: FastifyRequest, reply: FastifyReply, itemId: string, min: Role): Promise<{ item: ItemRow; m: Membership } | null> {
    const item = await one<ItemRow>('SELECT * FROM e2e_items WHERE id = $1', [itemId]);
    if (!item) { reply.code(404).send(NOT_FOUND); return null; }
    const m = await need(req, reply, item.library_id, min);
    return m ? { item, m } : null;
  }

  // ── The caller's own key pair ────────────────────────────────────────────────────────────────────────────

  /** The public key and every wrapped copy of the private key; the browser unwraps one of them locally. */
  app.get('/api/e2e/keys', async (req, reply) => {
    const k = await one<{ alg: string; public_key: string; created_at: Date }>('SELECT alg, public_key, created_at FROM e2e_user_keys WHERE user_id = $1', [uid(req)]);
    if (!k) return reply.code(404).send({ error: 'no_keys' });
    const wraps = await q<{ id: string; kind: string; label: string; params: unknown; wrapped: string; created_at: Date; updated_at: Date }>(
      'SELECT id, kind, label, params, wrapped, created_at, updated_at FROM e2e_key_wraps WHERE user_id = $1 ORDER BY created_at', [uid(req)]);
    return {
      alg: k.alg, publicKey: k.public_key, createdAt: k.created_at,
      wraps: wraps.map((w) => ({ id: w.id, kind: w.kind, label: w.label, params: w.params, wrapped: w.wrapped, createdAt: w.created_at, updatedAt: w.updated_at })),
    };
  });

  const wrapBody = z.object({ kind: name, label: z.string().max(80).default(''), params, wrapped: opaque(8192) });

  /** First setup: a key pair made in the browser and its first wrap. Refused when one already exists. */
  app.put('/api/e2e/keys', async (req, reply) => {
    const b = z.object({ alg: name, publicKey: opaque(2048), wrap: wrapBody }).safeParse(req.body ?? {});
    if (!b.success) return bad(reply);
    const me = uid(req);
    const made = await tx(async (qq) => {
      const [k] = await qq('INSERT INTO e2e_user_keys (user_id, alg, public_key) VALUES ($1, $2, $3) ON CONFLICT (user_id) DO NOTHING RETURNING user_id', [me, b.data.alg, b.data.publicKey]);
      if (!k) return null;
      const [w] = await qq<{ id: string }>('INSERT INTO e2e_key_wraps (user_id, kind, label, params, wrapped) VALUES ($1, $2, $3, $4, $5) RETURNING id',
        [me, b.data.wrap.kind, b.data.wrap.label, JSON.stringify(b.data.wrap.params), b.data.wrap.wrapped]);
      return w;
    });
    if (!made) return reply.code(409).send({ error: 'keys_exist' });
    void logAudit('e2e.keys.create', { userId: me, req });
    return { ok: true, wrapId: made.id };
  });

  /**
   * Forget the key pair -- the only way out of a lost passphrase. Every library the caller owns is deleted with
   * its files (nobody could ever be given its key again), and they leave every library they were a member of.
   */
  app.delete('/api/e2e/keys', async (req, reply) => {
    const me = uid(req);
    const owned = await tx(async (qq) => {
      const libs = await qq<{ id: string }>('DELETE FROM e2e_libraries WHERE owner_id = $1 RETURNING id', [me]);
      await qq('DELETE FROM e2e_library_members WHERE user_id = $1', [me]);
      await qq('DELETE FROM e2e_user_keys WHERE user_id = $1', [me]);
      return libs;
    });
    for (const l of owned) await store.removeLibrary(l.id).catch(() => {});
    void logAudit('e2e.keys.reset', { userId: me, req, detail: { librariesDeleted: owned.length } });
    return reply.code(204).send();
  });

  /** Another way to unlock the same private key (a second passphrase, a recovery code, later a device key). */
  app.post('/api/e2e/keys/wraps', async (req, reply) => {
    const b = wrapBody.safeParse(req.body ?? {});
    if (!b.success) return bad(reply);
    const row = await one<{ id: string }>(
      `INSERT INTO e2e_key_wraps (user_id, kind, label, params, wrapped)
       SELECT $1, $2, $3, $4, $5 WHERE EXISTS (SELECT 1 FROM e2e_user_keys WHERE user_id = $1)
           AND (SELECT count(*) FROM e2e_key_wraps WHERE user_id = $1) < 20
       RETURNING id`,
      [uid(req), b.data.kind, b.data.label, JSON.stringify(b.data.params), b.data.wrapped]);
    if (!row) return reply.code(409).send({ error: 'no_keys_or_too_many' });
    return { id: row.id };
  });

  /** Re-wrap: a changed passphrase replaces the wrap it unlocked with. */
  app.put('/api/e2e/keys/wraps/:id', async (req, reply) => {
    const id = uuid.safeParse((req.params as { id: string }).id);
    const b = wrapBody.partial({ kind: true, label: true }).safeParse(req.body ?? {});
    if (!id.success || !b.success) return bad(reply);
    const row = await one<{ id: string }>(
      `UPDATE e2e_key_wraps SET params = $3, wrapped = $4, label = COALESCE($5, label), updated_at = now()
        WHERE id = $1 AND user_id = $2 RETURNING id`,
      [id.data, uid(req), JSON.stringify(b.data.params), b.data.wrapped, b.data.label ?? null]);
    if (!row) return reply.code(404).send(NOT_FOUND);
    return { ok: true };
  });

  /** Remove a way to unlock, never the last one (that would lock the caller out of every library). */
  app.delete('/api/e2e/keys/wraps/:id', async (req, reply) => {
    const id = uuid.safeParse((req.params as { id: string }).id);
    if (!id.success) return bad(reply);
    const row = await one<{ id: string }>(
      `DELETE FROM e2e_key_wraps WHERE id = $1 AND user_id = $2
          AND (SELECT count(*) FROM e2e_key_wraps WHERE user_id = $2) > 1 RETURNING id`, [id.data, uid(req)]);
    if (!row) return reply.code(409).send({ error: 'last_wrap_or_missing' });
    return reply.code(204).send();
  });

  /** Someone's public key, by username, to share a library with them. Only accounts that set up a vault have one. */
  app.get('/api/e2e/users/:username/key', async (req, reply) => {
    const username = String((req.params as { username: string }).username || '').slice(0, 120);
    const r = await one<{ id: string; username: string; display_name: string; alg: string; public_key: string }>(
      `SELECT u.id, u.username, u.display_name, k.alg, k.public_key
         FROM users u JOIN e2e_user_keys k ON k.user_id = u.id
        WHERE lower(u.username) = lower($1) AND NOT u.disabled`, [username]);
    if (!r) return reply.code(404).send(NOT_FOUND);
    return { userId: r.id, username: r.username, displayName: r.display_name, alg: r.alg, publicKey: r.public_key };
  });

  // ── Libraries ────────────────────────────────────────────────────────────────────────────────────────────

  const LIB_SELECT = `
    SELECT l.id, l.owner_id, l.key_version, l.meta, l.created_at, l.updated_at,
           m.role, m.key_version AS member_key_version, m.wrap_alg, m.wrapped_key,
           (SELECT count(*) FROM e2e_items i WHERE i.library_id = l.id AND i.state = 'ready') AS items
      FROM e2e_library_members m JOIN e2e_libraries l ON l.id = m.library_id`;
  const libOut = (r: any) => ({
    id: r.id, ownerId: r.owner_id, keyVersion: r.key_version, meta: r.meta, role: r.role,
    memberKeyVersion: r.member_key_version, wrapAlg: r.wrap_alg, wrappedKey: r.wrapped_key,
    items: Number(r.items), createdAt: r.created_at, updatedAt: r.updated_at,
  });

  app.get('/api/e2e/libraries', async (req) => {
    const rows = await q(`${LIB_SELECT} WHERE m.user_id = $1 ORDER BY l.created_at`, [uid(req)]);
    return rows.map(libOut);
  });

  /**
   * A new library. The id is made by the browser: it is bound into the encryption of the library key and the
   * metadata (as associated data), so the server cannot hand one library's ciphertext out as another's.
   */
  app.post('/api/e2e/libraries', async (req, reply) => {
    const b = z.object({ id: uuid, meta: opaque(16_384), wrapAlg: name, wrappedKey: opaque(2048) }).safeParse(req.body ?? {});
    if (!b.success) return bad(reply);
    const me = uid(req);
    const ok = await tx(async (qq) => {
      const [hasKeys] = await qq('SELECT 1 FROM e2e_user_keys WHERE user_id = $1', [me]);
      if (!hasKeys) return 'no_keys' as const;
      const [lib] = await qq('INSERT INTO e2e_libraries (id, owner_id, meta) VALUES ($1, $2, $3) ON CONFLICT (id) DO NOTHING RETURNING id', [b.data.id, me, b.data.meta]);
      if (!lib) return 'exists' as const;
      await qq(`INSERT INTO e2e_library_members (library_id, user_id, role, key_version, wrap_alg, wrapped_key, added_by)
                VALUES ($1, $2, 'owner', 1, $3, $4, $2)`, [b.data.id, me, b.data.wrapAlg, b.data.wrappedKey]);
      return 'ok' as const;
    });
    if (ok !== 'ok') return reply.code(409).send({ error: ok });
    void logAudit('e2e.library.create', { userId: me, req, detail: { library: b.data.id } });
    const [row] = await q(`${LIB_SELECT} WHERE m.user_id = $1 AND l.id = $2`, [me, b.data.id]);
    return libOut(row);
  });

  app.get('/api/e2e/libraries/:id', async (req, reply) => {
    const id = uuid.safeParse((req.params as { id: string }).id);
    if (!id.success) return reply.code(404).send(NOT_FOUND);
    const [row] = await q(`${LIB_SELECT} WHERE m.user_id = $1 AND l.id = $2`, [uid(req), id.data]);
    if (!row) return reply.code(404).send(NOT_FOUND);
    return libOut(row);
  });

  /** New encrypted metadata (a rename). Editors and the owner. */
  app.patch('/api/e2e/libraries/:id', async (req, reply) => {
    const id = uuid.safeParse((req.params as { id: string }).id);
    const b = z.object({ meta: opaque(16_384) }).safeParse(req.body ?? {});
    if (!id.success) return reply.code(404).send(NOT_FOUND);
    if (!b.success) return bad(reply);
    if (!(await need(req, reply, id.data, 'editor'))) return;
    await q('UPDATE e2e_libraries SET meta = $2, updated_at = now() WHERE id = $1', [id.data, b.data.meta]);
    return { ok: true };
  });

  app.delete('/api/e2e/libraries/:id', async (req, reply) => {
    const id = uuid.safeParse((req.params as { id: string }).id);
    if (!id.success) return reply.code(404).send(NOT_FOUND);
    if (!(await need(req, reply, id.data, 'owner'))) return;
    await q('DELETE FROM e2e_libraries WHERE id = $1', [id.data]);
    await store.removeLibrary(id.data).catch(() => {});
    void logAudit('e2e.library.delete', { userId: uid(req), req, detail: { library: id.data } });
    return reply.code(204).send();
  });

  // ── Members ──────────────────────────────────────────────────────────────────────────────────────────────

  /** Who is in the library, with each one's public key: the owner needs them to re-wrap at a key rotation. */
  app.get('/api/e2e/libraries/:id/members', async (req, reply) => {
    const id = uuid.safeParse((req.params as { id: string }).id);
    if (!id.success) return reply.code(404).send(NOT_FOUND);
    if (!(await need(req, reply, id.data, 'reader'))) return;
    const rows = await q<{ user_id: string; username: string | null; display_name: string; role: Role; key_version: number; alg: string | null; public_key: string | null; created_at: Date }>(
      `SELECT m.user_id, u.username, u.display_name, m.role, m.key_version, k.alg, k.public_key, m.created_at
         FROM e2e_library_members m JOIN users u ON u.id = m.user_id LEFT JOIN e2e_user_keys k ON k.user_id = m.user_id
        WHERE m.library_id = $1 ORDER BY (m.role = 'owner') DESC, m.created_at`, [id.data]);
    return rows.map((r) => ({ userId: r.user_id, username: r.username, displayName: r.display_name, role: r.role, keyVersion: r.key_version, alg: r.alg, publicKey: r.public_key, addedAt: r.created_at }));
  });

  /**
   * Add a member, or change their role. The owner's browser unwrapped the library key and wrapped it again to the
   * member's public key; it must be the CURRENT key version, or the member would be handed a key that opens nothing new.
   */
  app.put('/api/e2e/libraries/:id/members/:userId', async (req, reply) => {
    const p = z.object({ id: uuid, userId: uuid }).safeParse(req.params);
    const b = z.object({ role, keyVersion: z.number().int().min(1), wrapAlg: name, wrappedKey: opaque(2048) }).safeParse(req.body ?? {});
    if (!p.success) return reply.code(404).send(NOT_FOUND);
    if (!b.success) return bad(reply);
    const m = await need(req, reply, p.data.id, 'owner');
    if (!m) return;
    if (p.data.userId === m.owner_id) return reply.code(409).send({ error: 'is_owner' });
    if (b.data.keyVersion !== m.library_key_version) return reply.code(409).send({ error: 'stale_key', keyVersion: m.library_key_version });
    const target = await one('SELECT 1 FROM e2e_user_keys k JOIN users u ON u.id = k.user_id WHERE k.user_id = $1 AND NOT u.disabled', [p.data.userId]);
    if (!target) return reply.code(404).send({ error: 'no_keys' });
    await q(
      `INSERT INTO e2e_library_members (library_id, user_id, role, key_version, wrap_alg, wrapped_key, added_by)
       VALUES ($1, $2, $3, $4, $5, $6, $7)
       ON CONFLICT (library_id, user_id) DO UPDATE SET role = EXCLUDED.role, key_version = EXCLUDED.key_version,
         wrap_alg = EXCLUDED.wrap_alg, wrapped_key = EXCLUDED.wrapped_key`,
      [p.data.id, p.data.userId, b.data.role, b.data.keyVersion, b.data.wrapAlg, b.data.wrappedKey, uid(req)]);
    void logAudit('e2e.member.put', { userId: uid(req), req, detail: { library: p.data.id, member: p.data.userId, role: b.data.role } });
    return { ok: true };
  });

  /**
   * Remove a member (the owner), or leave (anyone but the owner). The server stops serving them at once; the owner's
   * browser should then rotate the key (below), so a key they kept opens nothing added afterwards.
   */
  app.delete('/api/e2e/libraries/:id/members/:userId', async (req, reply) => {
    const p = z.object({ id: uuid, userId: uuid }).safeParse(req.params);
    if (!p.success) return reply.code(404).send(NOT_FOUND);
    const self = p.data.userId === uid(req);
    const m = await need(req, reply, p.data.id, self ? 'reader' : 'owner');
    if (!m) return;
    if (p.data.userId === m.owner_id) return reply.code(409).send({ error: 'is_owner' });
    await q('DELETE FROM e2e_library_members WHERE library_id = $1 AND user_id = $2', [p.data.id, p.data.userId]);
    void logAudit('e2e.member.remove', { userId: uid(req), req, detail: { library: p.data.id, member: p.data.userId } });
    return reply.code(204).send();
  });

  /**
   * Rotate the library key: a new key version, wrapped to EVERY current member and re-wrapping EVERY item's key.
   * All or nothing, in one transaction; anything short of the full set is refused, so no member or item is ever
   * left on a key version the library no longer has. The chunks are not touched: they are under item keys.
   */
  app.post('/api/e2e/libraries/:id/rotate', { bodyLimit: 16 * 1024 * 1024 }, async (req, reply) => {
    const id = uuid.safeParse((req.params as { id: string }).id);
    const b = z.object({
      fromVersion: z.number().int().min(1),
      meta: opaque(16_384),
      members: z.array(z.object({ userId: uuid, wrapAlg: name, wrappedKey: opaque(2048) })).min(1).max(1000),
      items: z.array(z.object({ id: uuid, wrappedKey: opaque(2048) })).max(200_000),
    }).safeParse(req.body ?? {});
    if (!id.success) return reply.code(404).send(NOT_FOUND);
    if (!b.success) return bad(reply);
    if (!(await need(req, reply, id.data, 'owner'))) return;
    const out = await tx(async (qq) => {
      const [lib] = await qq<{ key_version: number }>('SELECT key_version FROM e2e_libraries WHERE id = $1 FOR UPDATE', [id.data]);
      if (!lib) return { code: 404, body: NOT_FOUND };
      if (lib.key_version !== b.data.fromVersion) return { code: 409, body: { error: 'stale_key', keyVersion: lib.key_version } };
      const members = await qq<{ user_id: string }>('SELECT user_id FROM e2e_library_members WHERE library_id = $1', [id.data]);
      const items = await qq<{ id: string }>('SELECT id FROM e2e_items WHERE library_id = $1', [id.data]);
      const same = (have: string[], sent: string[]) => have.length === sent.length && new Set(sent).size === sent.length && sent.every((s) => have.includes(s));
      if (!same(members.map((r) => r.user_id), b.data.members.map((r) => r.userId))) return { code: 409, body: { error: 'members_changed' } };
      if (!same(items.map((r) => r.id), b.data.items.map((r) => r.id))) return { code: 409, body: { error: 'items_changed' } };
      const next = lib.key_version + 1;
      await qq('UPDATE e2e_libraries SET key_version = $2, meta = $3, updated_at = now() WHERE id = $1', [id.data, next, b.data.meta]);
      for (const m of b.data.members) {
        await qq('UPDATE e2e_library_members SET key_version = $3, wrap_alg = $4, wrapped_key = $5 WHERE library_id = $1 AND user_id = $2',
          [id.data, m.userId, next, m.wrapAlg, m.wrappedKey]);
      }
      if (b.data.items.length) {
        await qq(`UPDATE e2e_items i SET key_version = $2, wrapped_key = v.k, updated_at = now()
                    FROM unnest($3::uuid[], $4::text[]) AS v(id, k) WHERE i.id = v.id AND i.library_id = $1`,
          [id.data, next, b.data.items.map((i) => i.id), b.data.items.map((i) => i.wrappedKey)]);
      }
      return { code: 200, body: { ok: true, keyVersion: next } };
    });
    if (out.code === 200) void logAudit('e2e.library.rotate', { userId: uid(req), req, detail: { library: id.data } });
    return reply.code(out.code).send(out.body);
  });

  // ── Items ────────────────────────────────────────────────────────────────────────────────────────────────

  app.get('/api/e2e/libraries/:id/items', async (req, reply) => {
    const id = uuid.safeParse((req.params as { id: string }).id);
    if (!id.success) return reply.code(404).send(NOT_FOUND);
    const m = await need(req, reply, id.data, 'reader');
    if (!m) return;
    // Pending (still uploading) items are the editors' business; a reader sees what is finished.
    const rows = await q<ItemRow>(
      `SELECT * FROM e2e_items WHERE library_id = $1 AND (state = 'ready' OR $2) ORDER BY created_at`, [id.data, RANK[m.role] >= RANK.editor]);
    return rows.map(itemOut);
  });

  /** Start an item: its wrapped content key and metadata. Chunks follow, then a commit. The id is the browser's (see libraries). */
  app.post('/api/e2e/libraries/:id/items', async (req, reply) => {
    const id = uuid.safeParse((req.params as { id: string }).id);
    const b = z.object({ id: uuid, keyVersion: z.number().int().min(1), wrappedKey: opaque(2048), meta: opaque(65_536) }).safeParse(req.body ?? {});
    if (!id.success) return reply.code(404).send(NOT_FOUND);
    if (!b.success) return bad(reply);
    const m = await need(req, reply, id.data, 'editor');
    if (!m) return;
    if (b.data.keyVersion !== m.library_key_version) return reply.code(409).send({ error: 'stale_key', keyVersion: m.library_key_version });
    const row = await one<ItemRow>(
      `INSERT INTO e2e_items (id, library_id, key_version, wrapped_key, meta, created_by) VALUES ($1, $2, $3, $4, $5, $6)
       ON CONFLICT (id) DO NOTHING RETURNING *`, [b.data.id, id.data, b.data.keyVersion, b.data.wrappedKey, b.data.meta, uid(req)]);
    if (!row) return reply.code(409).send({ error: 'exists' });
    return itemOut(row);
  });

  app.put('/api/e2e/items/:id/chunks/:n', async (req, reply) => {
    const p = z.object({ id: uuid, n: z.coerce.number().int().min(0).max(MAX_CHUNKS - 1) }).safeParse(req.params);
    if (!p.success) return reply.code(404).send(NOT_FOUND);
    const body = req.body;
    // 12-byte IV + 16-byte tag is the least an AES-GCM chunk can be.
    if (!Buffer.isBuffer(body) || body.length < 28) return bad(reply, 'octet-stream body expected');
    const r = await needItem(req, reply, p.data.id, 'editor');
    if (!r) return;
    if (r.item.state !== 'pending') return reply.code(409).send({ error: 'committed' });
    await store.writeChunk(r.item.library_id, r.item.id, p.data.n, body);
    await q('UPDATE e2e_items SET updated_at = now() WHERE id = $1', [r.item.id]);
    return { ok: true, bytes: body.length };
  });

  /** Seal an upload: every chunk 0..chunks-1 must be there. After this the item is read-only. */
  app.post('/api/e2e/items/:id/commit', async (req, reply) => {
    const id = uuid.safeParse((req.params as { id: string }).id);
    const b = z.object({ chunks: z.number().int().min(1).max(MAX_CHUNKS) }).safeParse(req.body ?? {});
    if (!id.success) return reply.code(404).send(NOT_FOUND);
    if (!b.success) return bad(reply);
    const r = await needItem(req, reply, id.data, 'editor');
    if (!r) return;
    if (r.item.state !== 'pending') return reply.code(409).send({ error: 'committed' });
    const sizes = await store.chunkSizes(r.item.library_id, r.item.id, b.data.chunks);
    if (!sizes) return reply.code(409).send({ error: 'missing_chunks' });
    await store.dropChunksFrom(r.item.library_id, r.item.id, b.data.chunks);
    const row = await one<ItemRow>(
      `UPDATE e2e_items SET state = 'ready', chunks = $2, size = $3, updated_at = now() WHERE id = $1 AND state = 'pending' RETURNING *`,
      [r.item.id, b.data.chunks, sizes.reduce((a, s) => a + s, 0)]);
    if (!row) return reply.code(409).send({ error: 'committed' });
    return itemOut(row);
  });

  app.get('/api/e2e/items/:id/chunks/:n', async (req, reply) => {
    const p = z.object({ id: uuid, n: z.coerce.number().int().min(0).max(MAX_CHUNKS - 1) }).safeParse(req.params);
    if (!p.success) return reply.code(404).send(NOT_FOUND);
    const r = await needItem(req, reply, p.data.id, 'reader');
    if (!r) return;
    if (r.item.state !== 'ready' || p.data.n >= r.item.chunks) return reply.code(404).send(NOT_FOUND);
    const c = await store.openChunk(r.item.library_id, r.item.id, p.data.n);
    if (!c) return reply.code(404).send(NOT_FOUND);
    return reply.type('application/octet-stream').header('content-length', c.size)
      .header('cache-control', 'private, no-store').header('x-content-type-options', 'nosniff').send(c.stream);
  });

  /** New encrypted metadata for an item (a rename). */
  app.patch('/api/e2e/items/:id', async (req, reply) => {
    const id = uuid.safeParse((req.params as { id: string }).id);
    const b = z.object({ meta: opaque(65_536) }).safeParse(req.body ?? {});
    if (!id.success) return reply.code(404).send(NOT_FOUND);
    if (!b.success) return bad(reply);
    const r = await needItem(req, reply, id.data, 'editor');
    if (!r) return;
    await q('UPDATE e2e_items SET meta = $2, updated_at = now() WHERE id = $1', [r.item.id, b.data.meta]);
    return { ok: true };
  });

  app.delete('/api/e2e/items/:id', async (req, reply) => {
    const id = uuid.safeParse((req.params as { id: string }).id);
    if (!id.success) return reply.code(404).send(NOT_FOUND);
    const r = await needItem(req, reply, id.data, 'editor');
    if (!r) return;
    await q('DELETE FROM e2e_items WHERE id = $1', [r.item.id]);
    await store.removeItem(r.item.library_id, r.item.id).catch(() => {});
    return reply.code(204).send();
  });
}
