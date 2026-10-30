// Private libraries, against the real queries: a library with an owner is that account's alone, admins included. An
// admin sees on Admin → Libraries that it exists and can delete it -- which removes it completely, files and all --
// but cannot open it, edit it or give it to someone else.
//
// Skipped automatically unless TEST_DATABASE_URL is set.
import test, { before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdir, rm, writeFile, stat } from 'fs/promises';
import { tmpdir } from 'os';
import { join } from 'path';

const DSN = process.env.TEST_DATABASE_URL;
const ROOT = join(tmpdir(), `uchiyomi-pl-${process.pid}`);
if (DSN) {
  process.env.DATABASE_URL = DSN;
  process.env.JWT_SECRET = process.env.JWT_SECRET || 'test-secret-at-least-16-chars';
  process.env.CONFIG_DIR = process.env.CONFIG_DIR || '/tmp/uchiyomi-test-config';
  process.env.LIBRARY_BACKEND = 'owned';
  process.env.LIBRARY_ROOT = ROOT;
  process.env.DL_ROOT = ROOT;
}
const skip = DSN ? false : 'set TEST_DATABASE_URL to run';

const LIB_M = 'lib_pl_member', LIB_A = 'lib_pl_admin';
const S_M = 's_pl_member', S_A = 's_pl_admin';
const USERS = ['pl-owner', 'pl-other', 'pl-admin', 'pl-admin2', 'pl-restricted'];

let q: any, vis: any, owned: any, app: any;
const id: Record<string, string> = {};

before(async () => {
  if (!DSN) return;
  const { migrate } = await import('../src/lib/migrate');
  q = (await import('../src/lib/db')).q;
  vis = await import('../src/lib/visibility');
  owned = (await import('../src/lib/ownedCatalog')).owned;
  await migrate();

  await q('DELETE FROM lib_books WHERE series_id = ANY($1)', [[S_M, S_A]]);
  await q('DELETE FROM lib_series WHERE id = ANY($1)', [[S_M, S_A]]);
  await q('DELETE FROM libraries WHERE id = ANY($1)', [[LIB_M, LIB_A]]);
  await q('DELETE FROM users WHERE username = ANY($1)', [USERS]);
  for (const n of USERS) {
    id[n] = (await q(`INSERT INTO users (username, display_name, password_hash, role, auth_kind)
                      VALUES ($1,$1,'x',$2,'password') RETURNING id`, [n, n.startsWith('pl-admin') ? 'admin' : 'user']))[0].id;
  }
  // A member restricted to the default library only: owning a private library is still its grant.
  await q(`INSERT INTO libraries (id, name, path, owner_id) VALUES ($1,'Mine',$1,$2), ($3,'Admin only',$3,$4)`,
    [LIB_M, id['pl-restricted'], LIB_A, id['pl-admin']]);
  await q(`INSERT INTO user_libraries (user_id, library_id) VALUES ($1,'lib')`, [id['pl-restricted']]);
  for (const [sid, lib] of [[S_M, LIB_M], [S_A, LIB_A]] as const) {
    await q(`INSERT INTO lib_series (id, source, title, folder, books_count, library_id) VALUES ($1,'T!pl',$1,$2,1,$3)`,
      [sid, `${lib}/${sid}`, lib]);
  }
  // A downloaded chapter on disk in the member's private library.
  await mkdir(join(ROOT, LIB_M, S_M), { recursive: true });
  await writeFile(join(ROOT, LIB_M, S_M, 'ch1.cbz'), 'one');
  await q(`INSERT INTO lib_books (id, series_id, source, file, number, title, root) VALUES ('b_pl_1',$1,'T!pl',$2,1,'Chapter 1',$3)`,
    [S_M, `${LIB_M}/${S_M}/ch1.cbz`, ROOT]);

  const Fastify = (await import('fastify')).default;
  const jwt = (await import('@fastify/jwt')).default;
  app = Fastify();
  await app.register(jwt, { secret: process.env.JWT_SECRET! });
  await app.register((await import('../src/routes/admin')).default);
  await app.ready();
});

after(async () => {
  if (!DSN) return;
  await app?.close();
  await q('DELETE FROM lib_books WHERE series_id = ANY($1)', [[S_M, S_A]]).catch(() => {});
  await q('DELETE FROM lib_series WHERE id = ANY($1)', [[S_M, S_A]]).catch(() => {});
  await q('DELETE FROM libraries WHERE id = ANY($1)', [[LIB_M, LIB_A]]).catch(() => {});
  await q('DELETE FROM users WHERE username = ANY($1)', [USERS]).catch(() => {});
  await rm(ROOT, { recursive: true, force: true });
});

const ctx = (n: string) => vis.viewCtxFor(id[n], n.startsWith('pl-admin') ? 'admin' : 'user');
const sees = async (n: string, sid: string) => vis.seriesVisible(sid, await ctx(n));
const as = (n: string) => ({ authorization: `Bearer ${app.jwt.sign({ sub: id[n], role: 'admin' })}` });

test('private libraries', { skip }, async (t) => {
  await t.test('only the owner sees what is in it, admins included', async () => {
    assert.equal(await sees('pl-restricted', S_M), true, 'the owner was refused their own library');
    assert.equal(await sees('pl-owner', S_M), false);
    assert.equal(await sees('pl-other', S_M), false, 'another member saw a private library');
    assert.equal(await sees('pl-admin', S_M), false, 'an admin saw into a member\'s private library');
    assert.equal(await sees('pl-admin', S_A), true);
    assert.equal(await sees('pl-admin2', S_A), false, 'another admin saw an admin\'s private library');
  });

  await t.test('the library list does not name someone else\'s private library', async () => {
    const names = async (n: string) => (await owned.libraries(await ctx(n))).map((l: any) => l.id);
    assert.ok((await names('pl-restricted')).includes(LIB_M));
    assert.ok(!(await names('pl-other')).includes(LIB_M));
    assert.ok(!(await names('pl-admin2')).includes(LIB_A));
    assert.ok(!(await names('pl-admin2')).includes(LIB_M));
  });

  await t.test('Admin → Libraries lists it, without its folders, and it cannot be edited or given away', async () => {
    const list = (await app.inject({ method: 'GET', url: '/api/admin/libraries', headers: as('pl-admin2') })).json();
    const row = list.content.find((l: any) => l.id === LIB_A);
    assert.ok(row, 'another admin\'s private library is not listed');
    assert.equal(row.locked, true);
    assert.deepEqual(row.paths, [], 'its folders were shown');
    assert.equal(row.owner_id, id['pl-admin']);
    const patch = await app.inject({ method: 'PATCH', url: `/api/admin/libraries/${LIB_A}`, headers: as('pl-admin2'), payload: { name: 'Mine now' } });
    assert.equal(patch.statusCode, 403, 'another admin could edit it');
    const give = await app.inject({ method: 'PATCH', url: `/api/admin/libraries/${LIB_A}`, headers: as('pl-admin'), payload: { ownerId: id['pl-admin2'] } });
    assert.equal(give.statusCode, 400, 'the owner was changed');
    const unprivate = await app.inject({ method: 'PATCH', url: `/api/admin/libraries/${LIB_A}`, headers: as('pl-admin'), payload: { ownerId: null } });
    assert.equal(unprivate.statusCode, 400, 'a private library was made public');
    const same = await app.inject({ method: 'PATCH', url: `/api/admin/libraries/${LIB_A}`, headers: as('pl-admin'), payload: { name: 'Admin only', ownerId: id['pl-admin'] } });
    assert.equal(same.statusCode, 200, 'the owner could not save its settings');
  });

  await t.test('deleting it removes it completely, downloaded files included', async () => {
    const del = await app.inject({ method: 'DELETE', url: `/api/admin/libraries/${LIB_M}`, headers: as('pl-admin') });
    assert.equal(del.statusCode, 200, del.body);
    assert.equal(del.json().purged, 1);
    assert.equal((await q('SELECT 1 FROM libraries WHERE id = $1', [LIB_M])).length, 0);
    assert.equal((await q('SELECT 1 FROM lib_series WHERE id = $1', [S_M])).length, 0, 'its series went to another library');
    assert.equal((await q('SELECT 1 FROM lib_books WHERE series_id = $1', [S_M])).length, 0);
    assert.equal(await stat(join(ROOT, LIB_M, S_M, 'ch1.cbz')).then(() => true, () => false), false, 'the file is still on disk');
  });
});
