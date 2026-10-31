// Fork-only: the private (end-to-end encrypted) libraries' routes (src/fork/e2e), mounted for real and driven over HTTP.
//
// The server never decrypts anything, so the "keys" and "ciphertexts" here are opaque placeholders: what is under test
// is who may read and write what, and that the server keeps the bookkeeping (key versions, chunks, rotation) whole.
// The crypto itself is web/test/e2eVault.test.ts's.
//
// Skipped automatically unless TEST_DATABASE_URL is set.
import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';

const DSN = process.env.TEST_DATABASE_URL;
const DIR = mkdtempSync(join(tmpdir(), 'uchi-e2e-'));
if (DSN) {
  process.env.DATABASE_URL = DSN;
  process.env.JWT_SECRET = process.env.JWT_SECRET || 'test-secret-at-least-16-chars';
  process.env.CONFIG_DIR = process.env.CONFIG_DIR || '/tmp/uchiyomi-test-config';
  process.env.LIBRARY_BACKEND = 'owned';
  process.env.E2E_DIR = DIR;
}
const skip = DSN ? false : 'set TEST_DATABASE_URL to run';
const USERS = ['e2e-alice', 'e2e-bob', 'e2e-carol'];

async function setup() {
  const { migrate } = await import('../src/lib/migrate');
  const { migrateE2E } = await import('../src/fork/e2e/schema');
  const { q, one } = await import('../src/lib/db');
  const routes = await import('../src/fork/e2e/routes');
  const Fastify = (await import('fastify')).default;
  const jwt = (await import('@fastify/jwt')).default;

  await migrate();
  await migrateE2E();
  await migrateE2E(); // idempotent: it runs at every boot
  await q('DELETE FROM users WHERE username = ANY($1)', [USERS]);
  const ids: Record<string, string> = {};
  for (const u of USERS) {
    ids[u] = (await one<{ id: string }>(`INSERT INTO users (username, display_name, password_hash, role, auth_kind) VALUES ($1, $1, 'x', 'user', 'password') RETURNING id`, [u]))!.id;
  }
  const app = Fastify();
  await app.register(jwt, { secret: process.env.JWT_SECRET! });
  await app.register(routes.default);
  await app.ready();
  const as = (u: string) => ({ authorization: `Bearer ${app.jwt.sign({ sub: ids[u], role: 'user' })}` });
  const json = (u: string, method: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE', url: string, payload?: unknown) =>
    app.inject({ method, url, headers: as(u), ...(payload !== undefined ? { payload: payload as object } : {}) });
  const putChunk = (u: string, item: string, n: number, body: Buffer) =>
    app.inject({ method: 'PUT', url: `/api/e2e/items/${item}/chunks/${n}`, headers: { ...as(u), 'content-type': 'application/octet-stream' }, payload: body });
  const keys = (u: string) => json(u, 'PUT', '/api/e2e/keys', { alg: 'ecdh-p256', publicKey: `pub-${u}`, wrap: { kind: 'passphrase', label: 'x', params: { kdf: 'pbkdf2-sha256', iterations: 1, salt: 'AA' }, wrapped: `g1.iv.${u}` } });
  return { app, q, one, ids, as, json, putChunk, keys, routes };
}

test('private libraries: keys, sharing, uploads, rotation and reset', { skip }, async () => {
  const { app, q, ids, json, putChunk, keys, routes } = await setup();
  try {
    // ── keys ──
    assert.equal((await app.inject({ method: 'GET', url: '/api/e2e/keys' })).statusCode, 401, 'signed out');
    assert.equal((await json('e2e-alice', 'GET', '/api/e2e/keys')).statusCode, 404, 'no keys yet');
    assert.equal((await keys('e2e-alice')).statusCode, 200);
    assert.equal((await keys('e2e-alice')).statusCode, 409, 'a key pair is never silently replaced');
    assert.equal((await keys('e2e-bob')).statusCode, 200);
    const mine = (await json('e2e-alice', 'GET', '/api/e2e/keys')).json();
    assert.equal(mine.publicKey, 'pub-e2e-alice');
    assert.equal(mine.wraps.length, 1);
    assert.equal(mine.wraps[0].kind, 'passphrase');
    assert.equal((await json('e2e-alice', 'DELETE', `/api/e2e/keys/wraps/${mine.wraps[0].id}`)).statusCode, 409, 'never the last wrap');
    // A second way to unlock (what a device key will be), then re-wrap and remove it.
    const dev = await json('e2e-alice', 'POST', '/api/e2e/keys/wraps', { kind: 'device', label: 'Laptop', params: {}, wrapped: 'g1.a.b' });
    assert.equal(dev.statusCode, 200);
    assert.equal((await json('e2e-alice', 'PUT', `/api/e2e/keys/wraps/${dev.json().id}`, { params: { v: 2 }, wrapped: 'g1.c.d' })).statusCode, 200);
    assert.equal((await json('e2e-bob', 'PUT', `/api/e2e/keys/wraps/${dev.json().id}`, { params: {}, wrapped: 'g1.c.d' })).statusCode, 404, 'not your wrap');
    assert.equal((await json('e2e-alice', 'DELETE', `/api/e2e/keys/wraps/${dev.json().id}`)).statusCode, 204);
    assert.equal((await json('e2e-alice', 'PUT', '/api/e2e/keys', { alg: 'ecdh-p256', publicKey: 'not base64!', wrap: {} })).statusCode, 400);

    // Public keys by username, only for accounts with a vault.
    assert.equal((await json('e2e-alice', 'GET', '/api/e2e/users/E2E-BOB/key')).json().userId, ids['e2e-bob']);
    assert.equal((await json('e2e-alice', 'GET', '/api/e2e/users/e2e-carol/key')).statusCode, 404);

    // ── a library ──
    const lib = randomUUID();
    assert.equal((await json('e2e-carol', 'POST', '/api/e2e/libraries', { id: randomUUID(), meta: 'g1.m.m', wrapAlg: 'ecies-p256-hkdf-aesgcm', wrappedKey: 'e1.a.b.c' })).json().error, 'no_keys');
    const made = await json('e2e-alice', 'POST', '/api/e2e/libraries', { id: lib, meta: 'g1.m.1', wrapAlg: 'ecies-p256-hkdf-aesgcm', wrappedKey: 'e1.alice.1' });
    assert.equal(made.statusCode, 200);
    assert.equal(made.json().role, 'owner');
    assert.equal(made.json().keyVersion, 1);
    assert.equal((await json('e2e-alice', 'POST', '/api/e2e/libraries', { id: lib, meta: 'g1.m.1', wrapAlg: 'x', wrappedKey: 'e1.a' })).statusCode, 409, 'ids are not reused');
    assert.equal((await json('e2e-bob', 'GET', `/api/e2e/libraries/${lib}`)).statusCode, 404, 'not a member: it does not exist');
    assert.equal((await json('e2e-bob', 'GET', '/api/e2e/libraries')).json().length, 0);

    // ── an item, chunk by chunk ──
    const item = randomUUID();
    assert.equal((await json('e2e-alice', 'POST', `/api/e2e/libraries/${lib}/items`, { id: item, keyVersion: 2, wrappedKey: 'g1.k.1', meta: 'g1.i.1' })).json().error, 'stale_key');
    assert.equal((await json('e2e-alice', 'POST', `/api/e2e/libraries/${lib}/items`, { id: item, keyVersion: 1, wrappedKey: 'g1.k.1', meta: 'g1.i.1' })).statusCode, 200);
    const c0 = Buffer.alloc(1000, 7); const c1 = Buffer.alloc(40, 9);
    assert.equal((await putChunk('e2e-alice', item, 0, c0)).statusCode, 200);
    assert.equal((await putChunk('e2e-alice', item, 1, Buffer.alloc(10))).statusCode, 400, 'shorter than any AES-GCM chunk');
    assert.equal((await putChunk('e2e-alice', item, 1, Buffer.alloc(routes.CHUNK_MAX + 1))).statusCode, 413, 'over the chunk limit');
    assert.equal((await json('e2e-alice', 'POST', `/api/e2e/items/${item}/commit`, { chunks: 2 })).json().error, 'missing_chunks');
    assert.equal((await putChunk('e2e-alice', item, 1, c1)).statusCode, 200);
    assert.equal((await putChunk('e2e-alice', item, 2, c1)).statusCode, 200);
    const done = await json('e2e-alice', 'POST', `/api/e2e/items/${item}/commit`, { chunks: 2 });
    assert.equal(done.statusCode, 200);
    assert.equal(done.json().size, 1040);
    assert.equal(done.json().state, 'ready');
    assert.equal(existsSync(join(DIR, lib, item, '2.bin')), false, 'a chunk past the committed count is dropped');
    assert.equal((await putChunk('e2e-alice', item, 0, c0)).statusCode, 409, 'a committed item is read-only');
    const got = await json('e2e-alice', 'GET', `/api/e2e/items/${item}/chunks/1`);
    assert.equal(got.statusCode, 200);
    assert.deepEqual(got.rawPayload, c1);
    assert.equal(got.headers['cache-control'], 'private, no-store');
    assert.equal((await json('e2e-alice', 'GET', `/api/e2e/items/${item}/chunks/2`)).statusCode, 404);
    assert.equal((await json('e2e-bob', 'GET', `/api/e2e/items/${item}/chunks/0`)).statusCode, 404, 'a non-member reads no chunk');

    // A pending upload: editors see it, readers do not.
    const pending = randomUUID();
    await json('e2e-alice', 'POST', `/api/e2e/libraries/${lib}/items`, { id: pending, keyVersion: 1, wrappedKey: 'g1.k.2', meta: 'g1.i.2' });

    // ── sharing ──
    const share = (version: number, role = 'reader') => json('e2e-alice', 'PUT', `/api/e2e/libraries/${lib}/members/${ids['e2e-bob']}`, { role, keyVersion: version, wrapAlg: 'ecies-p256-hkdf-aesgcm', wrappedKey: `e1.bob.${version}` });
    assert.equal((await share(2)).json().error, 'stale_key');
    assert.equal((await json('e2e-alice', 'PUT', `/api/e2e/libraries/${lib}/members/${ids['e2e-carol']}`, { role: 'reader', keyVersion: 1, wrapAlg: 'x', wrappedKey: 'e1.x' })).json().error, 'no_keys');
    assert.equal((await share(1)).statusCode, 200);
    assert.equal((await json('e2e-bob', 'PUT', `/api/e2e/libraries/${lib}/members/${ids['e2e-alice']}`, { role: 'reader', keyVersion: 1, wrapAlg: 'x', wrappedKey: 'e1.x' })).statusCode, 403, 'a reader shares nothing');
    const bobs = (await json('e2e-bob', 'GET', '/api/e2e/libraries')).json();
    assert.equal(bobs.length, 1);
    assert.equal(bobs[0].role, 'reader');
    assert.equal(bobs[0].wrappedKey, 'e1.bob.1', 'each member gets their own wrap');
    assert.deepEqual((await json('e2e-bob', 'GET', `/api/e2e/libraries/${lib}/items`)).json().map((i: any) => i.id), [item], 'a reader sees finished items only');
    assert.equal((await json('e2e-alice', 'GET', `/api/e2e/libraries/${lib}/items`)).json().length, 2);
    assert.deepEqual((await json('e2e-bob', 'GET', `/api/e2e/items/${item}/chunks/0`)).rawPayload, c0);
    assert.equal((await putChunk('e2e-bob', pending, 0, c0)).statusCode, 403, 'a reader uploads nothing');
    assert.equal((await json('e2e-bob', 'DELETE', `/api/e2e/items/${item}`)).statusCode, 403);
    assert.equal((await json('e2e-bob', 'PATCH', `/api/e2e/libraries/${lib}`, { meta: 'g1.x.y' })).statusCode, 403);
    assert.equal((await json('e2e-bob', 'DELETE', `/api/e2e/libraries/${lib}`)).statusCode, 403);
    assert.equal((await share(1, 'editor')).statusCode, 200);
    assert.equal((await json('e2e-bob', 'PATCH', `/api/e2e/items/${item}`, { meta: 'g1.renamed.1' })).statusCode, 200, 'an editor renames');
    const members = (await json('e2e-bob', 'GET', `/api/e2e/libraries/${lib}/members`)).json();
    assert.deepEqual(members.map((m: any) => [m.role, m.publicKey]), [['owner', 'pub-e2e-alice'], ['editor', 'pub-e2e-bob']]);

    // ── rotation: all members and all items, or nothing ──
    const rotate = (body: object) => json('e2e-alice', 'POST', `/api/e2e/libraries/${lib}/rotate`, { fromVersion: 1, meta: 'g1.m.2', ...body });
    const everyone = [{ userId: ids['e2e-alice'], wrapAlg: 'ecies-p256-hkdf-aesgcm', wrappedKey: 'e1.alice.2' }, { userId: ids['e2e-bob'], wrapAlg: 'ecies-p256-hkdf-aesgcm', wrappedKey: 'e1.bob.2' }];
    const allItems = [{ id: item, wrappedKey: 'g1.k.v2a' }, { id: pending, wrappedKey: 'g1.k.v2b' }];
    assert.equal((await rotate({ members: everyone.slice(0, 1), items: allItems })).json().error, 'members_changed');
    assert.equal((await rotate({ members: everyone, items: allItems.slice(0, 1) })).json().error, 'items_changed');
    assert.equal((await json('e2e-bob', 'POST', `/api/e2e/libraries/${lib}/rotate`, { fromVersion: 1, meta: 'g1.m.2', members: everyone, items: allItems })).statusCode, 403);
    const rotated = await rotate({ members: everyone, items: allItems });
    assert.equal(rotated.statusCode, 200);
    assert.equal(rotated.json().keyVersion, 2);
    assert.equal((await rotate({ members: everyone, items: allItems })).json().error, 'stale_key', 'a rotation from an old version is refused');
    const after = (await json('e2e-alice', 'GET', `/api/e2e/libraries/${lib}/items`)).json();
    assert.deepEqual(after.map((i: any) => [i.keyVersion, i.wrappedKey]).sort(), [[2, 'g1.k.v2a'], [2, 'g1.k.v2b']]);
    assert.equal((await json('e2e-bob', 'GET', `/api/e2e/libraries/${lib}`)).json().wrappedKey, 'e1.bob.2');
    assert.deepEqual((await json('e2e-bob', 'GET', `/api/e2e/items/${item}/chunks/0`)).rawPayload, c0, 'chunks are untouched by a rotation');

    // ── removing a member, and leaving ──
    assert.equal((await json('e2e-bob', 'DELETE', `/api/e2e/libraries/${lib}/members/${ids['e2e-alice']}`)).statusCode, 403);
    assert.equal((await json('e2e-alice', 'DELETE', `/api/e2e/libraries/${lib}/members/${ids['e2e-alice']}`)).json().error, 'is_owner', 'the owner cannot leave their own library');
    assert.equal((await json('e2e-alice', 'DELETE', `/api/e2e/libraries/${lib}/members/${ids['e2e-bob']}`)).statusCode, 204);
    assert.equal((await json('e2e-bob', 'GET', `/api/e2e/items/${item}/chunks/0`)).statusCode, 404, 'removed: served nothing more');
    await json('e2e-alice', 'PUT', `/api/e2e/libraries/${lib}/members/${ids['e2e-bob']}`, { role: 'reader', keyVersion: 2, wrapAlg: 'x', wrappedKey: 'e1.bob.3' });
    assert.equal((await json('e2e-bob', 'DELETE', `/api/e2e/libraries/${lib}/members/${ids['e2e-bob']}`)).statusCode, 204, 'a member may leave');

    // ── the sweep drops abandoned uploads ──
    await q(`UPDATE e2e_items SET updated_at = now() - interval '2 days' WHERE id = $1`, [pending]);
    assert.equal(await routes.sweepPendingItems(), 1);
    assert.equal((await json('e2e-alice', 'GET', `/api/e2e/libraries/${lib}/items`)).json().length, 1);

    // ── reset: owned libraries and their files go; memberships elsewhere end ──
    const bobLib = randomUUID();
    await json('e2e-bob', 'POST', '/api/e2e/libraries', { id: bobLib, meta: 'g1.m.b', wrapAlg: 'x', wrappedKey: 'e1.b' });
    await json('e2e-bob', 'PUT', `/api/e2e/libraries/${bobLib}/members/${ids['e2e-alice']}`, { role: 'reader', keyVersion: 1, wrapAlg: 'x', wrappedKey: 'e1.a' });
    assert.ok(existsSync(join(DIR, lib, item)));
    assert.equal((await json('e2e-alice', 'DELETE', '/api/e2e/keys')).statusCode, 204);
    assert.equal(existsSync(join(DIR, lib)), false, 'the owned library\'s files are gone');
    assert.equal((await json('e2e-alice', 'GET', '/api/e2e/keys')).statusCode, 404);
    assert.equal((await json('e2e-alice', 'GET', '/api/e2e/libraries')).json().length, 0);
    assert.equal((await json('e2e-bob', 'GET', `/api/e2e/libraries/${bobLib}/members`)).json().length, 1, 'alice left bob\'s library');
  } finally {
    await app.close();
    await q('DELETE FROM users WHERE username = ANY($1)', [USERS]).catch(() => {});
    const { pool } = await import('../src/lib/db');
    await pool.end();
  }
});
