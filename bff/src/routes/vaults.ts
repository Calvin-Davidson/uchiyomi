// End-to-end encrypted vaults (docs/VAULTS.md): all under /api/e2e, registered only with VAULTS set (server.ts).
//
// A vault is not a library. A series moved into one (lib/vaults.ts) leaves the library completely, and what the vault
// holds of it -- title, metadata, chapter list, cover, pages, each member's reading progress -- is encrypted under the
// item's key, which is sealed to the vault's public key. The owner's browser opens it (web/lib/vault.ts); the server can't.
//
// Keys: each account has a key pair whose private half is wrapped in the browser by a KEK derived from the account
// password (`kind = 'password'`). Each vault has a key pair whose private half is sealed to its owner's public key. A vault
// belongs to one account; being a server admin grants nothing here.
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import rateLimit from '@fastify/rate-limit';
import { verify } from '@node-rs/argon2';
import { z } from 'zod';
import { open, readFile } from 'fs/promises';
import { q, one, tx } from '../lib/db';
import { authenticate, userIdOf, roleOf } from '../lib/auth';
import { logAudit } from '../lib/audit';
import { seriesVisible, viewCtxFor } from '../lib/visibility';
import { CHAPTER_MAGIC, recordSpan, vaultPublicKey } from '../lib/vaultCrypto';
import { chapterPath, coverPath, jobOf, moveIn, moveOut, openManifest } from '../lib/vaults';

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const uuid = z.string().regex(UUID_RE).transform((s) => s.toLowerCase());
const vaultId = z.string().regex(/^vault_[0-9a-f]{16}$/);
/** An opaque client-made string: base64url segments joined by `.` or `:`, bounded. */
const opaque = (max: number) => z.string().min(1).max(max).regex(/^[A-Za-z0-9_\-.:]+$/);
/** An algorithm or unlock-method name: `ecdh-p256`, `ecies-p256-hkdf-aesgcm`, `password`, later `device`. */
const name = z.string().regex(/^[a-z0-9][a-z0-9.\-]{0,39}$/);
const params = z.record(z.string(), z.unknown()).refine((p) => JSON.stringify(p).length <= 4096, 'params too large');

/** Vaults one account may own. */
const MAX_OWNED = 5;

const NOT_FOUND = { error: 'not_found' } as const;
const bad = (reply: FastifyReply) => reply.code(400).send({ error: 'bad_request' });

export default async function vaultRoutes(app: FastifyInstance) {
  // server.ts registers the limiter at the root; a test that mounts this plugin bare gets it here.
  if (!app.hasDecorator('createRateLimit')) await app.register(rateLimit, { global: false });
  app.addHook('preHandler', authenticate);
  const uid = (req: FastifyRequest) => userIdOf(req);

  /** Whether the caller is in a vault, or a 404 already sent (a vault you are not in does not exist to you). */
  async function need(req: FastifyRequest, reply: FastifyReply, id: string): Promise<boolean> {
    if (await one('SELECT 1 FROM e2e_vault_members WHERE vault_id = $1 AND user_id = $2', [id, uid(req)])) return true;
    reply.code(404).send(NOT_FOUND);
    return false;
  }

  // ── Status: what the web app reads at start ─────────────────────────────────────────────────────────────

  /** Whether this account has keys, and the vaults it is in (with its sealed copy of each vault's private key). */
  app.get('/api/e2e/status', async (req) => {
    const me = uid(req);
    const [k, user] = await Promise.all([
      one<{ public_key: string }>('SELECT public_key FROM e2e_user_keys WHERE user_id = $1', [me]),
      one<{ has_password: boolean }>(`SELECT (auth_kind = 'password' AND password_login) AS has_password FROM users WHERE id = $1`, [me]),
    ]);
    const vaults = await q<{ id: string; owner_id: string; public_key: string; wrap_alg: string; wrapped_key: string }>(
      `SELECT v.id, v.owner_id, v.public_key, m.wrap_alg, m.wrapped_key
         FROM e2e_vault_members m JOIN e2e_vaults v ON v.id = m.vault_id
        WHERE m.user_id = $1 ORDER BY v.created_at`, [me]);
    return {
      enabled: true,
      hasKeys: !!k,
      publicKey: k?.public_key ?? null,
      // A vault is unlocked with the account password: an account signing in by SSO or a passwordless profile has none.
      passwordAccount: !!user?.has_password,
      vaults: vaults.map((v) => ({ id: v.id, ownerId: v.owner_id, publicKey: v.public_key, wrapAlg: v.wrap_alg, wrappedKey: v.wrapped_key })),
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

  // ── Vaults ───────────────────────────────────────────────────────────────────────────────────────────────

  /** A new vault: its key pair is made in the browser; the server gets the public half and the private half sealed to the owner. */
  app.post('/api/e2e/vaults', async (req, reply) => {
    const b = z.object({ id: vaultId, alg: name, publicKey: opaque(2048), wrapAlg: name, wrappedKey: opaque(4096) }).safeParse(req.body ?? {});
    if (!b.success) return bad(reply);
    try { vaultPublicKey(b.data.publicKey); } catch { return bad(reply); }
    const me = uid(req);
    // The browser picks the id: its sealed copy of the private key is bound to it (associated data).
    const id = b.data.id;
    const out = await tx(async (qq) => {
      if (!(await qq('SELECT 1 FROM e2e_user_keys WHERE user_id = $1', [me])).length) return 'no_keys';
      const [{ n }] = await qq<{ n: number }>('SELECT count(*)::int AS n FROM e2e_vaults WHERE owner_id = $1', [me]);
      if (n >= MAX_OWNED) return 'too_many';
      if ((await qq('SELECT 1 FROM e2e_vaults WHERE id = $1', [id])).length) return 'exists';
      await qq('INSERT INTO e2e_vaults (id, owner_id, alg, public_key) VALUES ($1, $2, $3, $4)', [id, me, b.data.alg, b.data.publicKey]);
      await qq(`INSERT INTO e2e_vault_members (vault_id, user_id, role, wrap_alg, wrapped_key, added_by) VALUES ($1, $2, 'owner', $3, $4, $2)`,
        [id, me, b.data.wrapAlg, b.data.wrappedKey]);
      return 'ok';
    });
    if (out !== 'ok') return reply.code(409).send({ error: out });
    void logAudit('e2e.vault.create', { userId: me, req, detail: { vault: id } });
    return { id };
  });

  /** One vault's items: each one's sealed key, encrypted manifest and the caller's encrypted progress. */
  app.get('/api/e2e/vaults/:id', async (req, reply) => {
    const id = vaultId.safeParse((req.params as { id: string }).id);
    if (!id.success) return reply.code(404).send(NOT_FOUND);
    if (!(await need(req, reply, id.data))) return;
    const [items, states] = await Promise.all([
      q<{ id: string; item_key: string; meta: string; chapters: number; bytes: string; created_at: Date }>(
        'SELECT id, item_key, meta, chapters, bytes, created_at FROM e2e_vault_items WHERE vault_id = $1 ORDER BY created_at DESC', [id.data]),
      q<{ item_id: string; sealed: string }>(
        `SELECT s.item_id, s.sealed FROM e2e_vault_state s JOIN e2e_vault_items i ON i.id = s.item_id
          WHERE i.vault_id = $1 AND s.user_id = $2`, [id.data, uid(req)]),
    ]);
    const state = new Map(states.map((s) => [s.item_id, s.sealed]));
    return {
      id: id.data,
      items: items.map((i) => ({ id: i.id, itemKey: i.item_key, meta: i.meta, chapters: i.chapters, bytes: Number(i.bytes), createdAt: i.created_at, state: state.get(i.id) ?? null })),
    };
  });

  /** Move a series in. It must be one the caller can see. Answers with a job to poll; the series leaves the library at its end. */
  app.post('/api/e2e/vaults/:id/series', async (req, reply) => {
    const id = vaultId.safeParse((req.params as { id: string }).id);
    const b = z.object({ seriesId: z.string().min(1).max(64) }).safeParse(req.body ?? {});
    if (!id.success) return reply.code(404).send(NOT_FOUND);
    if (!b.success) return bad(reply);
    if (!(await need(req, reply, id.data))) return;
    const ctx = await viewCtxFor(uid(req), roleOf(req));
    if (!(await seriesVisible(b.data.seriesId, ctx))) return reply.code(404).send(NOT_FOUND);
    const v = await one<{ public_key: string }>('SELECT public_key FROM e2e_vaults WHERE id = $1', [id.data]);
    if (!v) return reply.code(404).send(NOT_FOUND);
    try {
      const job = moveIn({ id: id.data, publicKey: v.public_key }, b.data.seriesId, uid(req));
      void logAudit('e2e.vault.move_in', { userId: uid(req), req, detail: { vault: id.data } });
      return reply.code(202).send({ job: job.id });
    } catch { return reply.code(409).send({ error: 'busy' }); }
  });

  /** Move an item back out: the browser sends the item key it opened, for this request only. */
  app.post('/api/e2e/vaults/:id/items/:item/restore', async (req, reply) => {
    const p = z.object({ id: vaultId, item: uuid }).safeParse(req.params);
    const b = z.object({ itemKey: z.string().regex(/^[A-Za-z0-9_-]{43}$/) }).safeParse(req.body ?? {});
    if (!p.success) return reply.code(404).send(NOT_FOUND);
    if (!b.success) return bad(reply);
    if (!(await need(req, reply, p.data.id))) return;
    const item = await one<{ id: string; meta: string }>('SELECT id, meta FROM e2e_vault_items WHERE id = $1 AND vault_id = $2', [p.data.item, p.data.id]);
    if (!item) return reply.code(404).send(NOT_FOUND);
    const raw = Buffer.from(b.data.itemKey, 'base64url');
    try { await openManifest(item, raw); } catch { raw.fill(0); return reply.code(400).send({ error: 'wrong_key' }); }
    try {
      const job = moveOut(p.data.id, item, raw, uid(req));
      void logAudit('e2e.vault.move_out', { userId: uid(req), req, detail: { vault: p.data.id } });
      return reply.code(202).send({ job: job.id });
    } catch { raw.fill(0); return reply.code(409).send({ error: 'busy' }); }
  });

  app.get('/api/e2e/jobs/:job', async (req, reply) => {
    const j = jobOf(String((req.params as { job: string }).job), uid(req));
    if (!j) return reply.code(404).send(NOT_FOUND);
    return { kind: j.kind, state: j.state, done: j.done, total: j.total, error: j.error ?? null };
  });

  /** An item the caller may read, or a 404 already sent. */
  async function itemOf(req: FastifyRequest, reply: FastifyReply): Promise<{ vault: string; item: string } | null> {
    const p = z.object({ id: vaultId, item: uuid }).safeParse(req.params);
    if (!p.success) { reply.code(404).send(NOT_FOUND); return null; }
    if (!(await need(req, reply, p.data.id))) return null;
    if (!(await one('SELECT 1 FROM e2e_vault_items WHERE id = $1 AND vault_id = $2', [p.data.item, p.data.id]))) { reply.code(404).send(NOT_FOUND); return null; }
    return { vault: p.data.id, item: p.data.item };
  }
  /** Ciphertext exactly as stored; the browser opens it. */
  const cipher = (reply: FastifyReply, b: Buffer) =>
    reply.header('content-type', 'application/octet-stream').header('cache-control', 'private, max-age=86400').header('x-content-type-options', 'nosniff').send(b);

  app.get('/api/e2e/vaults/:id/items/:item/cover', async (req, reply) => {
    const it = await itemOf(req, reply);
    if (!it) return;
    const b = await readFile(coverPath(it.vault, it.item)).catch(() => null);
    return b ? cipher(reply, b) : reply.code(404).send(NOT_FOUND);
  });

  /** One page of a chapter, read by the chapter file's plaintext offset table. Both numbers are 0-based. */
  app.get('/api/e2e/vaults/:id/items/:item/chapters/:ch/pages/:page', async (req, reply) => {
    const it = await itemOf(req, reply);
    if (!it) return;
    const n = z.object({ ch: z.coerce.number().int().min(0).max(100_000), page: z.coerce.number().int().min(0).max(100_000) }).safeParse(req.params);
    if (!n.success) return reply.code(404).send(NOT_FOUND);
    const fh = await open(chapterPath(it.vault, it.item, n.data.ch), 'r').catch(() => null);
    if (!fh) return reply.code(404).send(NOT_FOUND);
    try {
      const head = Buffer.alloc(8);
      await fh.read(head, 0, 8, 0);
      const count = head.subarray(0, 4).equals(CHAPTER_MAGIC) ? head.readUInt32BE(4) : 0;
      if (n.data.page >= count) return reply.code(404).send(NOT_FOUND);
      const table = Buffer.alloc(8 + (count + 1) * 8);
      await fh.read(table, 0, table.length, 0);
      const span = recordSpan(table, n.data.page);
      if (!span || span.end <= span.start) return reply.code(404).send(NOT_FOUND);
      const rec = Buffer.alloc(span.end - span.start);
      await fh.read(rec, 0, rec.length, span.start);
      return cipher(reply, rec);
    } finally { await fh.close(); }
  });

  /**
   * Edited details: the item's manifest, sealed again in the member's browser under the same item key (Edit details on a
   * vault series, public/vault-sw.js). The server can't read it, so it can only check its shape; a move out opens it.
   */
  // Its own body cap: the manifest lists every page's size, and a long series' runs past the server's 2 MB default.
  app.put('/api/e2e/vaults/:id/items/:item/meta', { bodyLimit: 8 * 1024 * 1024 }, async (req, reply) => {
    const it = await itemOf(req, reply);
    if (!it) return;
    const b = z.object({ sealed: opaque(8 * 1024 * 1024).regex(/^g1\./) }).safeParse(req.body ?? {});
    if (!b.success) return bad(reply);
    await q('UPDATE e2e_vault_items SET meta = $3 WHERE id = $1 AND vault_id = $2', [it.item, it.vault, b.data.sealed]);
    return { ok: true };
  });

  /** The caller's reading progress in one item, encrypted in their browser under the item key. */
  app.put('/api/e2e/vaults/:id/items/:item/state', async (req, reply) => {
    const it = await itemOf(req, reply);
    if (!it) return;
    const b = z.object({ sealed: opaque(256 * 1024) }).safeParse(req.body ?? {});
    if (!b.success) return bad(reply);
    await q(`INSERT INTO e2e_vault_state (item_id, user_id, sealed) VALUES ($1, $2, $3)
             ON CONFLICT (item_id, user_id) DO UPDATE SET sealed = EXCLUDED.sealed, updated_at = now()`, [it.item, uid(req), b.data.sealed]);
    return { ok: true };
  });
}
