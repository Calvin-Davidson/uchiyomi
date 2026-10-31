// Fork-only: e2e vaults (src/fork/e2e) on a real database: keys, a vault that is an ordinary library seen by its
// members only, moving a series in, its chapter files sealed in place, new chapters sealed before they are written,
// and the page route handing out sealed pages with the member's key.
//
// Keys are made with the browser's code (web/fork/e2e/crypto.ts, on Node's WebCrypto), so the pages served here are
// opened exactly as the service worker opens them.
//
// Skipped automatically unless TEST_DATABASE_URL is set.
import test from 'node:test';
import assert from 'node:assert/strict';
import AdmZip from 'adm-zip';
import sharp from 'sharp';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const DSN = process.env.TEST_DATABASE_URL;
const DL = mkdtempSync(join(tmpdir(), 'uchi-e2e-dl-'));
if (DSN) {
  process.env.DATABASE_URL = DSN;
  process.env.JWT_SECRET = process.env.JWT_SECRET || 'test-secret-at-least-16-chars';
  process.env.CONFIG_DIR = process.env.CONFIG_DIR || '/tmp/uchiyomi-test-config';
  process.env.CACHE_DIR = mkdtempSync(join(tmpdir(), 'uchi-e2e-cache-'));
  process.env.LIBRARY_BACKEND = 'owned';
  process.env.DL_ROOT = DL;
}
const skip = DSN ? false : 'set TEST_DATABASE_URL to run';
const USERS = ['e2e-alice', 'e2e-bob', 'e2e-carol'];
const SERIES = 's_e2e_vault_one';
const OTHER = 's_e2e_vault_two';
const FOLDER = 'E2E Src (EN)/Vault One';

const png = (w: number, colour = '#c00') => sharp({ create: { width: w, height: 50, channels: 3, background: colour } }).png().toBuffer();

async function setup() {
  const { migrate } = await import('../src/lib/migrate');
  const { migrateE2E } = await import('../src/fork/e2e/schema');
  const { loadVaults } = await import('../src/fork/e2e/vaults');
  const { q, one } = await import('../src/lib/db');
  const e2eRoutes = (await import('../src/fork/e2e/routes')).default;
  const catalogRoutes = (await import('../src/routes/catalog')).default;
  const imageRoutes = (await import('../src/routes/images')).default;
  const { IMG_COOKIE } = await import('../src/lib/auth');
  const Fastify = (await import('fastify')).default;
  const jwt = (await import('@fastify/jwt')).default;
  const cookie = (await import('@fastify/cookie')).default;
  const { hash } = await import('@node-rs/argon2');

  await migrate();
  await migrateE2E();
  await migrateE2E(); // idempotent: it runs at every boot
  await q(`DELETE FROM libraries WHERE id IN (SELECT library_id FROM e2e_vaults v JOIN users u ON u.id = v.owner_id WHERE u.username = ANY($1))`, [USERS]);
  await q('DELETE FROM lib_books WHERE series_id = ANY($1)', [[SERIES, OTHER]]);
  await q('DELETE FROM lib_series WHERE id = ANY($1)', [[SERIES, OTHER]]);
  await q('DELETE FROM users WHERE username = ANY($1)', [USERS]);
  const ids: Record<string, string> = {};
  const pw = await hash('alice-password');
  for (const u of USERS) {
    ids[u] = (await one<{ id: string }>(`INSERT INTO users (username, display_name, password_hash, role, auth_kind) VALUES ($1, $1, $2, 'user', 'password') RETURNING id`,
      [u, u === 'e2e-alice' ? pw : 'x']))!.id;
  }
  // Two series in the main library, one chapter file each on disk.
  for (const [id, folder] of [[SERIES, FOLDER], [OTHER, 'E2E Src (EN)/Vault Two']] as const) {
    await q(`INSERT INTO lib_series (id, source, title, folder, books_count) VALUES ($1, 'E2E Src (EN)', $1, $2, 1)`, [id, folder]);
    mkdirSync(join(DL, folder), { recursive: true });
    const zip = new AdmZip();
    zip.addFile('001.png', await png(10)); zip.addFile('002.png', await png(20));
    zip.addFile('ComicInfo.xml', Buffer.from('<ComicInfo><Number>1</Number></ComicInfo>'));
    writeFileSync(join(DL, folder, 'Chapter 1.cbz'), zip.toBuffer());
    await q(`INSERT INTO lib_books (id, series_id, source, file, root, number, pages) VALUES ($1, $2, 'E2E Src (EN)', $3, $4, 1, 2)`,
      [`b_${id}_1`, id, `${folder}/Chapter 1.cbz`, DL]);
  }
  await loadVaults();

  const app = Fastify();
  await app.register(cookie);
  await app.register(jwt, { secret: process.env.JWT_SECRET! });
  await app.register(e2eRoutes);
  await app.register(catalogRoutes);
  await app.register(imageRoutes);
  await app.ready();
  const bearer = (u: string) => ({ authorization: `Bearer ${app.jwt.sign({ sub: ids[u], role: 'user' })}` });
  const img = (u: string) => ({ cookie: `${IMG_COOKIE}=${app.jwt.sign({ sub: ids[u], typ: 'img' })}` });
  const json = (u: string, method: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE', url: string, payload?: unknown) =>
    app.inject({ method, url, headers: bearer(u), ...(payload !== undefined ? { payload: payload as object } : {}) });
  return { app, q, one, ids, json, img };
}

test('vaults: a members-only library whose chapters are sealed to its public key', { skip }, async () => {
  const { app, q, ids, json, img } = await setup();
  const W = await import('../../web/fork/e2e/crypto');
  const { sealZipForFolder, sweepVaults } = await import('../src/fork/e2e/seal');
  try {
    // ── keys ──
    const st0 = (await json('e2e-alice', 'GET', '/api/e2e/status')).json();
    assert.deepEqual([st0.enabled, st0.hasKeys, st0.passwordAccount, st0.vaults.length], [true, false, true, 0]);
    assert.equal((await json('e2e-alice', 'POST', '/api/e2e/verify-password', { password: 'nope' })).statusCode, 401);
    assert.equal((await json('e2e-alice', 'POST', '/api/e2e/verify-password', { password: 'alice-password' })).statusCode, 200);
    const people: Record<string, { pkcs8: Uint8Array<ArrayBuffer>; pub: string }> = {};
    for (const u of ['e2e-alice', 'e2e-bob']) {
      const id = await W.generateIdentity();
      const wrap = await W.passwordUnlocker('pw', 1000).wrap(id.pkcs8, W.ad.identity(ids[u]));
      people[u] = { pkcs8: id.pkcs8, pub: W.b64u(id.publicSpki) };
      assert.equal((await json(u, 'PUT', '/api/e2e/keys', { alg: 'ecdh-p256', publicKey: people[u].pub, wrap: { kind: 'password', ...wrap } })).statusCode, 200);
    }
    assert.equal((await json('e2e-carol', 'PUT', '/api/e2e/keys', { alg: 'ecdh-p256', publicKey: 'AAAA', wrap: { kind: 'password', params: {}, wrapped: 'x' } })).statusCode, 400, 'not a P-256 key');

    // ── a vault ──
    const VAULT = 'vault_00112233aabbccdd';
    const vk = await W.generateIdentity();
    const mk = (u: string) => W.sealTo(people[u].pub, vk.pkcs8, W.ad.vaultKey(VAULT, ids[u]));
    const made = await json('e2e-alice', 'POST', '/api/e2e/vaults', { id: VAULT, name: 'My vault', alg: 'ecdh-p256', publicKey: W.b64u(vk.publicSpki), wrapAlg: 'ecies-p256-hkdf-aesgcm', wrappedKey: await mk('e2e-alice') });
    assert.equal(made.statusCode, 200);
    assert.equal((await json('e2e-carol', 'POST', '/api/e2e/vaults', { id: 'vault_0000000000000001', name: 'x', alg: 'ecdh-p256', publicKey: W.b64u(vk.publicSpki), wrapAlg: 'x', wrappedKey: 'e1.x' })).json().error, 'no_keys');
    const libsOf = async (u: string) => (await json(u, 'GET', '/api/libraries')).json().map((l: { id: string }) => l.id);
    assert.ok((await libsOf('e2e-alice')).includes(VAULT), 'the owner sees the vault library');
    assert.ok(!(await libsOf('e2e-bob')).includes(VAULT), 'nobody else is told it exists');

    // A plain thumbnail the image cache made before the move: it must not outlive the sealing.
    assert.equal((await app.inject({ method: 'GET', url: `/img/books/b_${SERIES}_1/thumb`, headers: img('e2e-alice') })).statusCode, 200);
    const thumbKey = createHash('sha256').update(`lib-bthumb:b_${SERIES}_1`).digest('hex');
    const thumbFile = join(process.env.CACHE_DIR!, thumbKey.slice(0, 2), thumbKey.slice(2, 4), `${thumbKey}.bin`);
    assert.ok(existsSync(thumbFile), 'the cache holds a plain thumbnail');

    // ── moving a series in ──
    assert.equal((await json('e2e-bob', 'POST', `/api/e2e/vaults/${VAULT}/series`, { seriesIds: [SERIES] })).statusCode, 404, 'not a member');
    const moved = (await json('e2e-alice', 'POST', `/api/e2e/vaults/${VAULT}/series`, { seriesIds: [SERIES, 's_nope'] })).json();
    assert.equal(moved.applied, 1);
    assert.deepEqual(moved.skipped, [{ id: 's_nope', reason: 'not_found' }]);
    assert.equal((await json('e2e-alice', 'GET', `/api/series/${SERIES}`)).statusCode, 200, 'the owner reads it as a normal series');
    assert.equal((await json('e2e-bob', 'GET', `/api/series/${SERIES}`)).statusCode, 404, 'others no longer see it');
    assert.equal((await json('e2e-bob', 'GET', `/api/series/${OTHER}`)).statusCode, 200, 'the rest of the library is untouched');
    assert.equal((await app.inject({ method: 'GET', url: `/img/books/b_${SERIES}_1/page/1`, headers: img('e2e-bob') })).statusCode, 404, 'nor its pages');

    // ── its chapter file is sealed in place ──
    await sweepVaults(VAULT);
    const file = join(DL, FOLDER, 'Chapter 1.cbz');
    const onDisk = new AdmZip(readFileSync(file));
    assert.equal(onDisk.readFile('001.png')!.subarray(0, 4).toString('latin1'), 'UYE2');
    assert.match(onDisk.readAsText('ComicInfo.xml'), /<Number>1</);
    assert.ok(!existsSync(thumbFile), "the cache's plain thumbnail is gone");
    const detail = (await json('e2e-alice', 'GET', `/api/e2e/vaults/${VAULT}`)).json();
    assert.deepEqual([detail.series, detail.seal.total, detail.seal.sealed, detail.seal.failed], [1, 1, 1, 0]);

    // ── the page route hands out the sealed page and the member's key; it opens as the service worker opens it ──
    const page = await app.inject({ method: 'GET', url: `/img/books/b_${SERIES}_1/page/2?w=400`, headers: img('e2e-alice') });
    assert.equal(page.statusCode, 200);
    assert.equal(page.headers['content-type'], 'application/x-uchiyomi-e2e');
    assert.equal(page.headers['x-e2e-vault'], VAULT);
    const open = async (u: string, r: typeof page) => {
      const me = await W.importPrivate(people[u].pkcs8);
      const vpk = await W.importPrivate(await W.openFrom(me, String(r.headers['x-e2e-lk']), W.ad.vaultKey(String(r.headers['x-e2e-vault']), String(r.headers['x-e2e-user']))));
      return W.openPage(new Uint8Array(r.rawPayload), vpk, VAULT);
    };
    assert.deepEqual(Buffer.from((await open('e2e-alice', page)).bytes), await png(20), 'page 2, whole: no resize of a sealed page');
    const thumb = await app.inject({ method: 'GET', url: `/img/books/b_${SERIES}_1/thumb`, headers: img('e2e-alice') });
    assert.equal(thumb.headers['content-type'], 'application/x-uchiyomi-e2e', 'the thumbnail is the sealed first page');
    const cover = await app.inject({ method: 'GET', url: `/img/series/${SERIES}/thumb?w=800`, headers: img('e2e-alice') });
    assert.equal(cover.headers['content-type'], 'application/x-uchiyomi-e2e', 'a vault series with no cover art: its sealed first page');
    assert.deepEqual(Buffer.from((await open('e2e-alice', cover)).bytes), await png(10));
    const pages = (await json('e2e-alice', 'GET', `/api/books/b_${SERIES}_1/pages`)).json();
    assert.deepEqual(pages.map((p: { width: number }) => p.width), [10, 20], "the reader's page sizes come from the sealed headers");

    // ── sharing ──
    const share = await json('e2e-alice', 'PUT', `/api/e2e/vaults/${VAULT}/members/${ids['e2e-bob']}`, { role: 'reader', wrapAlg: 'ecies-p256-hkdf-aesgcm', wrappedKey: await mk('e2e-bob') });
    assert.equal(share.statusCode, 200);
    assert.ok((await libsOf('e2e-bob')).includes(VAULT));
    // Bob is restricted to no library at all but the vault he is in still shows.
    await q(`INSERT INTO user_libraries (user_id, library_id) VALUES ($1, '')`, [ids['e2e-bob']]);
    assert.deepEqual(await libsOf('e2e-bob'), [VAULT], 'a restricted member keeps their vaults');
    const bobsPage = await app.inject({ method: 'GET', url: `/img/books/b_${SERIES}_1/page/1`, headers: img('e2e-bob') });
    assert.equal(bobsPage.headers['x-e2e-user'], ids['e2e-bob'], "each member is sent their own copy of the vault's key");
    assert.deepEqual(Buffer.from((await open('e2e-bob', bobsPage)).bytes), await png(10));
    assert.equal((await json('e2e-bob', 'POST', `/api/e2e/vaults/${VAULT}/series`, { seriesIds: [OTHER] })).statusCode, 403, 'a reader moves nothing in');
    assert.equal((await json('e2e-bob', 'DELETE', `/api/e2e/vaults/${VAULT}`)).statusCode, 403);
    assert.equal((await json('e2e-bob', 'DELETE', `/api/e2e/vaults/${VAULT}/members/${ids['e2e-bob']}`)).statusCode, 204, 'a member may leave');
    assert.equal((await app.inject({ method: 'GET', url: `/img/books/b_${SERIES}_1/page/1`, headers: img('e2e-bob') })).statusCode, 404);
    await q('DELETE FROM user_libraries WHERE user_id = $1', [ids['e2e-bob']]);

    // ── a new chapter is sealed before it is written; one outside a vault is not ──
    const fresh = new AdmZip(); fresh.addFile('001.png', await png(12));
    assert.equal(new AdmZip(await sealZipForFolder(FOLDER, fresh)).readFile('001.png')!.subarray(0, 4).toString('latin1'), 'UYE2');
    const plain = new AdmZip(); plain.addFile('001.png', await png(12));
    assert.deepEqual(new AdmZip(await sealZipForFolder('E2E Src (EN)/Vault Two', plain)).readFile('001.png'), await png(12));

    // ── a chapter fetched from a source for a vault series lands sealed: the real downloader, a fake source ──
    const { registerAdapter } = await import('../src/lib/sources');
    const { downloadChapter } = await import('../src/lib/downloader');
    registerAdapter({
      id: 'e2e-src', name: 'E2E Src',
      async search() { return []; },
      async getSeries(sid: string) { return { sourceId: sid, source: 'e2e-src', title: 'Vault One' }; },
      async listChapters() { return [{ number: 2, title: 'Chapter 2', sourceId: 'c2', pages: 2 }]; },
      async getPageUrls() { return ['https://example.invalid/c2/1.png', 'https://example.invalid/c2/2.png']; },
      async latest() { return []; },
    } as any);
    const fetched = await png(16, '#00c');
    const realFetch = globalThis.fetch;
    globalThis.fetch = (async () => new Response(fetched, { status: 200, headers: { 'content-type': 'image/png' } })) as typeof fetch;
    try {
      const out = await downloadChapter({ sourceId: 'e2e-src', seriesFolder: FOLDER, chapter: { number: 2, title: 'Chapter 2', sourceId: 'c2', pages: 2 }, meta: { series: 'Vault One' } } as any);
      assert.equal(out?.pages, 2);
    } finally { globalThis.fetch = realFetch; }
    const ch2 = new AdmZip(readFileSync(join(DL, FOLDER, 'Chapter 2.cbz')));
    const ch2Pages = ch2.getEntries().filter((e) => /\.(png|jpe?g|webp)$/i.test(e.entryName));
    assert.equal(ch2Pages.length, 2);
    for (const e of ch2Pages) assert.equal(e.getData().subarray(0, 4).toString('latin1'), 'UYE2', `${e.entryName} is written sealed`);
    const vpk2 = await W.importPrivate(vk.pkcs8);
    assert.deepEqual(Buffer.from((await W.openPage(new Uint8Array(ch2Pages[0].getData()), vpk2, VAULT)).bytes), fetched);

    // ── deleting: only an empty vault; resetting keys: not while owning one ──
    assert.equal((await json('e2e-alice', 'DELETE', `/api/e2e/vaults/${VAULT}`)).json().error, 'not_empty');
    assert.equal((await json('e2e-alice', 'DELETE', '/api/e2e/keys')).json().error, 'owns_vaults');
    await q(`UPDATE lib_series SET deleted_at = now() WHERE id = $1`, [SERIES]);
    assert.equal((await json('e2e-alice', 'DELETE', `/api/e2e/vaults/${VAULT}`)).statusCode, 204);
    assert.ok(!(await libsOf('e2e-alice')).includes(VAULT));
    assert.equal((await q(`SELECT library_id FROM lib_series WHERE id = $1`, [SERIES]))[0].library_id, 'lib', 'a removed series goes back to the main library');
    assert.equal((await json('e2e-alice', 'DELETE', '/api/e2e/keys')).statusCode, 204);
  } finally {
    await app.close();
    await q('DELETE FROM lib_books WHERE series_id = ANY($1)', [[SERIES, OTHER]]).catch(() => {});
    await q('DELETE FROM lib_series WHERE id = ANY($1)', [[SERIES, OTHER]]).catch(() => {});
    await q('DELETE FROM users WHERE username = ANY($1)', [USERS]).catch(() => {});
    const { pool } = await import('../src/lib/db');
    await pool.end();
  }
});
