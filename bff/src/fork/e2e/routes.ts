// Fork-only: end-to-end encrypted vaults. HTTP routes, all under /api/e2e.
//
// A vault is an ordinary library (a `libraries` row): its series are followed, checked for new chapters, downloaded,
// listed and read like any other. What differs is that every chapter file in it is sealed to the vault's public key
// (seal.ts), only its members see it (vaults.ts, through lib/visibility.ts), and their browsers decrypt the pages
// (web/public/e2e-sw.js). The server holds public keys and sealed private keys only; it can never read a page.
//
// Keys: each account has a key pair whose private half is wrapped in the browser by a KEK derived from the account
// password (`kind = 'password'`). Each vault has a key pair whose private half is sealed to each member's public key.
//
// Roles, per vault: `owner` (one; members, rename, delete), `editor` (moves series in), `reader`. Being a server admin
// grants nothing here.
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import rateLimit from '@fastify/rate-limit';
import { verify } from '@node-rs/argon2';
import { z } from 'zod';
import { q, one, tx } from '../../lib/db';
import { authenticate, userIdOf, roleOf } from '../../lib/auth';
import { logAudit } from '../../lib/audit';
import { seriesVisible, viewCtxFor } from '../../lib/visibility';
import { vaultPublicKey } from './crypto';
import { loadVaults, vaultOf, vaultsOf } from './vaults';
import { sealStatus, sweepVaults } from './seal';

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const uuid = z.string().regex(UUID_RE).transform((s) => s.toLowerCase());
const vaultId = z.string().regex(/^vault_[0-9a-f]{16}$/);
/** An opaque client-made string: base64url segments joined by `.` or `:`, bounded. */
const opaque = (max: number) => z.string().min(1).max(max).regex(/^[A-Za-z0-9_\-.:]+$/);
/** An algorithm or unlock-method name: `ecdh-p256`, `ecies-p256-hkdf-aesgcm`, `password`, later `device`. */
const name = z.string().regex(/^[a-z0-9][a-z0-9.\-]{0,39}$/);
const params = z.record(z.string(), z.unknown()).refine((p) => JSON.stringify(p).length <= 4096, 'params too large');
const role = z.enum(['editor', 'reader']);
const title = z.string().trim().min(1).max(80);

/** Vaults one account may own. */
const MAX_OWNED = 5;

const NOT_FOUND = { error: 'not_found' } as const;
const FORBIDDEN = { error: 'forbidden' } as const;
const bad = (reply: FastifyReply) => reply.code(400).send({ error: 'bad_request' });

type Role = 'owner' | 'editor' | 'reader';
const RANK: Record<Role, number> = { reader: 0, editor: 1, owner: 2 };

export default async function e2eRoutes(app: FastifyInstance) {
  // server.ts registers the limiter at the root; a test that mounts this plugin bare gets it here.
  if (!app.hasDecorator('createRateLimit')) await app.register(rateLimit, { global: false });
  app.addHook('preHandler', authenticate);
  const uid = (req: FastifyRequest) => userIdOf(req);

  /** The caller's role in a vault, or a 404 already sent (a vault you are not in does not exist to you). */
  async function need(req: FastifyRequest, reply: FastifyReply, id: string, min: Role): Promise<Role | null> {
    const r = vaultOf(id)?.members.get(uid(req));
    if (!r) { reply.code(404).send(NOT_FOUND); return null; }
    if (RANK[r] < RANK[min]) { reply.code(403).send(FORBIDDEN); return null; }
    return r;
  }

  // ── Status: what the web app reads at start ─────────────────────────────────────────────────────────────

  /** Whether this account has keys, and the vaults it is in (with its sealed copy of each vault's private key). */
  app.get('/api/e2e/status', async (req) => {
    const me = uid(req);
    const [k, user] = await Promise.all([
      one<{ public_key: string }>('SELECT public_key FROM e2e_user_keys WHERE user_id = $1', [me]),
      one<{ has_password: boolean }>(`SELECT (auth_kind = 'password' AND password_login) AS has_password FROM users WHERE id = $1`, [me]),
    ]);
    const vaults = await q<{ library_id: string; name: string; role: Role; owner_id: string; public_key: string; wrap_alg: string; wrapped_key: string }>(
      `SELECT v.library_id, l.name, m.role, v.owner_id, v.public_key, m.wrap_alg, m.wrapped_key
         FROM e2e_vault_members m JOIN e2e_vaults v ON v.library_id = m.library_id JOIN libraries l ON l.id = v.library_id
        WHERE m.user_id = $1 ORDER BY v.created_at`, [me]);
    return {
      enabled: true,
      hasKeys: !!k,
      publicKey: k?.public_key ?? null,
      // A vault is unlocked with the account password: an account signing in by SSO or a passwordless profile has none.
      passwordAccount: !!user?.has_password,
      vaults: vaults.map((v) => ({ id: v.library_id, name: v.name, role: v.role, ownerId: v.owner_id, publicKey: v.public_key, wrapAlg: v.wrap_alg, wrappedKey: v.wrapped_key })),
    };
  });

  /**
   * Is this the account's password? For making the first key pair while already signed in: the browser derives the KEK
   * from what was typed, and a typo there would lock the vault behind a password nobody knows. Rate-limited per account.
   */
  app.post('/api/e2e/verify-password', {
    config: { rateLimit: { max: 10, timeWindow: '10 minutes', hook: 'preHandler', keyGenerator: (req: FastifyRequest) => `e2e-pw:${userIdOf(req)}` } },
  }, async (req, reply) => {
    const b = z.object({ password: z.string().min(1).max(1024) }).safeParse(req.body ?? {});
    if (!b.success) return bad(reply);
    const u = await one<{ password_hash: string }>('SELECT password_hash FROM users WHERE id = $1', [uid(req)]);
    const ok = !!u?.password_hash && (await verify(u.password_hash, b.data.password).catch(() => false));
    return ok ? { ok: true } : reply.code(401).send({ error: 'wrong_password' });
  });

  // ── The caller's own key pair ────────────────────────────────────────────────────────────────────────────

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
    try { vaultPublicKey(b.data.publicKey); } catch { return bad(reply); }
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
   * Forget the key pair -- the way out of a forgotten password. Refused while the account owns a vault (its chapters
   * would be unreadable for good: empty and delete it first); every vault it was only a member of, it leaves.
   */
  app.delete('/api/e2e/keys', async (req, reply) => {
    const me = uid(req);
    if (await one('SELECT 1 FROM e2e_vaults WHERE owner_id = $1', [me])) return reply.code(409).send({ error: 'owns_vaults' });
    await tx(async (qq) => {
      await qq('DELETE FROM e2e_vault_members WHERE user_id = $1', [me]);
      await qq('DELETE FROM e2e_user_keys WHERE user_id = $1', [me]);
    });
    await loadVaults();
    void logAudit('e2e.keys.reset', { userId: me, req });
    return reply.code(204).send();
  });

  /** Another way to unlock the same private key (later: a device key). */
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

  /** Re-wrap: a changed password replaces the wrap it unlocked with. */
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

  /** Remove a way to unlock, never the last one. */
  app.delete('/api/e2e/keys/wraps/:id', async (req, reply) => {
    const id = uuid.safeParse((req.params as { id: string }).id);
    if (!id.success) return bad(reply);
    const row = await one<{ id: string }>(
      `DELETE FROM e2e_key_wraps WHERE id = $1 AND user_id = $2
          AND (SELECT count(*) FROM e2e_key_wraps WHERE user_id = $2) > 1 RETURNING id`, [id.data, uid(req)]);
    if (!row) return reply.code(409).send({ error: 'last_wrap_or_missing' });
    return reply.code(204).send();
  });

  /** Someone's public key, by username, to share a vault with them. Only accounts with keys have one. */
  app.get('/api/e2e/users/:username/key', async (req, reply) => {
    const username = String((req.params as { username: string }).username || '').slice(0, 120);
    const r = await one<{ id: string; username: string; display_name: string; alg: string; public_key: string }>(
      `SELECT u.id, u.username, u.display_name, k.alg, k.public_key
         FROM users u JOIN e2e_user_keys k ON k.user_id = u.id
        WHERE lower(u.username) = lower($1) AND NOT u.disabled`, [username]);
    if (!r) return reply.code(404).send(NOT_FOUND);
    return { userId: r.id, username: r.username, displayName: r.display_name, alg: r.alg, publicKey: r.public_key };
  });

  // ── Vaults ───────────────────────────────────────────────────────────────────────────────────────────────

  /**
   * A new vault: a library row (no folder of its own -- series are moved in, and stay pinned there), its public key,
   * and the owner's sealed copy of its private key. The key pair is made in the browser.
   */
  app.post('/api/e2e/vaults', async (req, reply) => {
    const b = z.object({ id: vaultId, name: title, alg: name, publicKey: opaque(2048), wrapAlg: name, wrappedKey: opaque(4096) }).safeParse(req.body ?? {});
    if (!b.success) return bad(reply);
    try { vaultPublicKey(b.data.publicKey); } catch { return bad(reply); }
    const me = uid(req);
    // The browser picks the id: its sealed copy of the private key is bound to it (associated data).
    const id = b.data.id;
    const out = await tx(async (qq) => {
      if (!(await qq('SELECT 1 FROM e2e_user_keys WHERE user_id = $1', [me])).length) return 'no_keys';
      const [{ n }] = await qq<{ n: number }>('SELECT count(*)::int AS n FROM e2e_vaults WHERE owner_id = $1', [me]);
      if (n >= MAX_OWNED) return 'too_many';
      if ((await qq('SELECT 1 FROM libraries WHERE id = $1', [id])).length) return 'exists';
      // A path no folder has, so the folder rule (lib/library.ts libraryIdFor) never files anything here by itself.
      await qq(`INSERT INTO libraries (id, name, path, sort_order) VALUES ($1, $2, $3, 1000)`, [id, b.data.name, `.uchiyomi-vault/${id}`]);
      await qq('INSERT INTO e2e_vaults (library_id, owner_id, alg, public_key) VALUES ($1, $2, $3, $4)', [id, me, b.data.alg, b.data.publicKey]);
      await qq(`INSERT INTO e2e_vault_members (library_id, user_id, role, wrap_alg, wrapped_key, added_by) VALUES ($1, $2, 'owner', $3, $4, $2)`,
        [id, me, b.data.wrapAlg, b.data.wrappedKey]);
      return 'ok';
    });
    if (out !== 'ok') return reply.code(409).send({ error: out });
    await loadVaults();
    void logAudit('e2e.vault.create', { userId: me, req, detail: { library: id } });
    return { id };
  });

  /** One vault: who is in it, and how far its chapters are sealed. */
  app.get('/api/e2e/vaults/:id', async (req, reply) => {
    const id = vaultId.safeParse((req.params as { id: string }).id);
    if (!id.success) return reply.code(404).send(NOT_FOUND);
    const myRole = await need(req, reply, id.data, 'reader');
    if (!myRole) return;
    const [lib, members, seal, series] = await Promise.all([
      one<{ name: string }>('SELECT name FROM libraries WHERE id = $1', [id.data]),
      q<{ user_id: string; username: string | null; display_name: string; role: Role; public_key: string | null }>(
        `SELECT m.user_id, u.username, u.display_name, m.role, k.public_key
           FROM e2e_vault_members m JOIN users u ON u.id = m.user_id LEFT JOIN e2e_user_keys k ON k.user_id = m.user_id
          WHERE m.library_id = $1 ORDER BY (m.role = 'owner') DESC, m.created_at`, [id.data]),
      sealStatus(id.data),
      one<{ n: number }>('SELECT count(*)::int AS n FROM lib_series WHERE library_id = $1 AND deleted_at IS NULL', [id.data]),
    ]);
    return {
      id: id.data, name: lib?.name ?? '', role: myRole, series: series?.n ?? 0, seal,
      members: members.map((m) => ({ userId: m.user_id, username: m.username, displayName: m.display_name, role: m.role, publicKey: m.public_key })),
    };
  });

  app.patch('/api/e2e/vaults/:id', async (req, reply) => {
    const id = vaultId.safeParse((req.params as { id: string }).id);
    const b = z.object({ name: title }).safeParse(req.body ?? {});
    if (!id.success) return reply.code(404).send(NOT_FOUND);
    if (!b.success) return bad(reply);
    if (!(await need(req, reply, id.data, 'owner'))) return;
    await q('UPDATE libraries SET name = $2 WHERE id = $1', [id.data, b.data.name]);
    return { ok: true };
  });

  /** Delete an EMPTY vault. Its series are removed from the library first, the usual way; nothing here deletes files. */
  app.delete('/api/e2e/vaults/:id', async (req, reply) => {
    const id = vaultId.safeParse((req.params as { id: string }).id);
    if (!id.success) return reply.code(404).send(NOT_FOUND);
    if (!(await need(req, reply, id.data, 'owner'))) return;
    if (await one('SELECT 1 FROM lib_series WHERE library_id = $1 AND deleted_at IS NULL', [id.data])) return reply.code(409).send({ error: 'not_empty' });
    await tx(async (qq) => {
      // Series removed earlier keep their row (a removed series can be put back); they go back to the main library.
      await qq(`UPDATE lib_series SET library_id = 'lib', library_pinned = false WHERE library_id = $1`, [id.data]);
      await qq('DELETE FROM user_libraries WHERE library_id = $1', [id.data]);
      await qq('DELETE FROM libraries WHERE id = $1', [id.data]);
    });
    await loadVaults();
    void logAudit('e2e.vault.delete', { userId: uid(req), req, detail: { library: id.data } });
    return reply.code(204).send();
  });

  /**
   * Move series into a vault. Each must be one the caller can see, and not already in a vault. They are pinned there
   * (the folder rule never takes them back out), their chapter files are sealed in the background, and every chapter
   * fetched for them from now on is sealed before it is written. There is no way back out: the server cannot decrypt.
   */
  app.post('/api/e2e/vaults/:id/series', async (req, reply) => {
    const id = vaultId.safeParse((req.params as { id: string }).id);
    const b = z.object({ seriesIds: z.array(z.string().min(1).max(64)).min(1).max(500) }).safeParse(req.body ?? {});
    if (!id.success) return reply.code(404).send(NOT_FOUND);
    if (!b.success) return bad(reply);
    if (!(await need(req, reply, id.data, 'editor'))) return;
    const ctx = await viewCtxFor(uid(req), roleOf(req));
    const moved: string[] = [];
    const skipped: Array<{ id: string; reason: string }> = [];
    for (const sid of b.data.seriesIds) {
      const row = await one<{ library_id: string }>('SELECT library_id FROM lib_series WHERE id = $1 AND deleted_at IS NULL', [sid]);
      if (!row || !(await seriesVisible(sid, ctx))) { skipped.push({ id: sid, reason: 'not_found' }); continue; }
      if (vaultOf(row.library_id)) { skipped.push({ id: sid, reason: row.library_id === id.data ? 'already_here' : 'in_another_vault' }); continue; }
      moved.push(sid);
    }
    if (moved.length) await q('UPDATE lib_series SET library_id = $2, library_pinned = true WHERE id = ANY($1)', [moved, id.data]);
    void logAudit('e2e.vault.move', { userId: uid(req), req, detail: { library: id.data, n: moved.length } });
    void sweepVaults(id.data).catch((e) => req.log.warn(`e2e: sealing failed: ${(e as Error)?.message || e}`));
    return { applied: moved.length, skipped };
  });

  /** Seal now (what the vault page's button and the move above start); answers when the sweep is done. */
  app.post('/api/e2e/vaults/:id/seal', async (req, reply) => {
    const id = vaultId.safeParse((req.params as { id: string }).id);
    if (!id.success) return reply.code(404).send(NOT_FOUND);
    if (!(await need(req, reply, id.data, 'editor'))) return;
    const r = await sweepVaults(id.data);
    return { ...r, status: await sealStatus(id.data) };
  });

  // ── Members ──────────────────────────────────────────────────────────────────────────────────────────────

  /** Add a member, or change their role: the owner's browser sealed the vault's private key to the member's public key. */
  app.put('/api/e2e/vaults/:id/members/:userId', async (req, reply) => {
    const p = z.object({ id: vaultId, userId: uuid }).safeParse(req.params);
    const b = z.object({ role, wrapAlg: name, wrappedKey: opaque(4096) }).safeParse(req.body ?? {});
    if (!p.success) return reply.code(404).send(NOT_FOUND);
    if (!b.success) return bad(reply);
    if (!(await need(req, reply, p.data.id, 'owner'))) return;
    if (p.data.userId === vaultOf(p.data.id)?.ownerId) return reply.code(409).send({ error: 'is_owner' });
    const target = await one('SELECT 1 FROM e2e_user_keys k JOIN users u ON u.id = k.user_id WHERE k.user_id = $1 AND NOT u.disabled', [p.data.userId]);
    if (!target) return reply.code(404).send({ error: 'no_keys' });
    await q(
      `INSERT INTO e2e_vault_members (library_id, user_id, role, wrap_alg, wrapped_key, added_by) VALUES ($1, $2, $3, $4, $5, $6)
       ON CONFLICT (library_id, user_id) DO UPDATE SET role = EXCLUDED.role, wrap_alg = EXCLUDED.wrap_alg, wrapped_key = EXCLUDED.wrapped_key`,
      [p.data.id, p.data.userId, b.data.role, b.data.wrapAlg, b.data.wrappedKey, uid(req)]);
    await loadVaults();
    void logAudit('e2e.member.put', { userId: uid(req), req, detail: { library: p.data.id, member: p.data.userId, role: b.data.role } });
    return { ok: true };
  });

  /**
   * Remove a member (the owner), or leave (anyone but the owner). The server stops serving them at once. The vault's
   * key is not rotated: that would mean re-encrypting every chapter in a browser, and a removed member who copied the
   * key would also need the server's files to use it.
   */
  app.delete('/api/e2e/vaults/:id/members/:userId', async (req, reply) => {
    const p = z.object({ id: vaultId, userId: uuid }).safeParse(req.params);
    if (!p.success) return reply.code(404).send(NOT_FOUND);
    const self = p.data.userId === uid(req);
    if (!(await need(req, reply, p.data.id, self ? 'reader' : 'owner'))) return;
    if (p.data.userId === vaultOf(p.data.id)?.ownerId) return reply.code(409).send({ error: 'is_owner' });
    await q('DELETE FROM e2e_vault_members WHERE library_id = $1 AND user_id = $2', [p.data.id, p.data.userId]);
    await loadVaults();
    void logAudit('e2e.member.remove', { userId: uid(req), req, detail: { library: p.data.id, member: p.data.userId } });
    return reply.code(204).send();
  });

  /** The caller's vault ids, for the series menu (cheap: from memory). */
  app.get('/api/e2e/mine', async (req) => ({ vaults: vaultsOf(uid(req)) }));
}
