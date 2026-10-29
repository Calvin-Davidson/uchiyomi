// Private libraries, against the real queries: a library with an owner is that account's alone. Other admins still
// see one a member owns; one an admin owns is hidden from every other account, admins included -- in what they can
// read, in the library list, and in Admin → Libraries.
//
// Skipped automatically unless TEST_DATABASE_URL is set.
import test, { before, after } from 'node:test';
import assert from 'node:assert/strict';

const DSN = process.env.TEST_DATABASE_URL;
if (DSN) {
  process.env.DATABASE_URL = DSN;
  process.env.JWT_SECRET = process.env.JWT_SECRET || 'test-secret-at-least-16-chars';
  process.env.CONFIG_DIR = process.env.CONFIG_DIR || '/tmp/uchiyomi-test-config';
  process.env.LIBRARY_BACKEND = 'owned';
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

  await q('DELETE FROM lib_series WHERE id = ANY($1)', [[S_M, S_A]]);
  await q('DELETE FROM libraries WHERE id = ANY($1)', [[LIB_M, LIB_A]]);
  await q('DELETE FROM users WHERE username = ANY($1)', [USERS]);
  for (const n of USERS) {
    id[n] = (await q(`INSERT INTO users (username, display_name, password_hash, role, auth_kind)
                      VALUES ($1,$1,'x',$2,'password') RETURNING id`, [n, n.startsWith('pl-admin') ? 'admin' : 'user']))[0].id;
  }
  await q(`INSERT INTO libraries (id, name, path, owner_id) VALUES ($1,'Mine',$1,$2), ($3,'Admin only',$3,$4)`,
    [LIB_M, id['pl-owner'], LIB_A, id['pl-admin']]);
  for (const [sid, lib] of [[S_M, LIB_M], [S_A, LIB_A]] as const) {
    await q(`INSERT INTO lib_series (id, source, title, folder, books_count, library_id) VALUES ($1,'T!pl',$1,$1,1,$2)`, [sid, lib]);
  }
  // A member restricted to the default library only: owning a private library is still its grant.
  await q(`UPDATE libraries SET owner_id = $1 WHERE id = $2`, [id['pl-restricted'], LIB_M]);
  await q(`INSERT INTO user_libraries (user_id, library_id) VALUES ($1,'lib')`, [id['pl-restricted']]);

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
  await q('DELETE FROM lib_series WHERE id = ANY($1)', [[S_M, S_A]]).catch(() => {});
  await q('DELETE FROM libraries WHERE id = ANY($1)', [[LIB_M, LIB_A]]).catch(() => {});
  await q('DELETE FROM users WHERE username = ANY($1)', [USERS]).catch(() => {});
});

const ctx = (n: string) => vis.viewCtxFor(id[n], n.startsWith('pl-admin') ? 'admin' : 'user');
const sees = async (n: string, sid: string) => vis.seriesVisible(sid, await ctx(n));
const as = (n: string) => ({ authorization: `Bearer ${app.jwt.sign({ sub: id[n], role: 'admin' })}` });

test('private libraries', { skip }, async (t) => {
  await t.test('a member-owned library: its owner and admins see it, other members do not', async () => {
    // The member restricted to `lib` owns LIB_M now, so it is theirs despite their grants.
    assert.equal(await sees('pl-restricted', S_M), true, 'the owner was refused their own library');
    assert.equal(await sees('pl-owner', S_M), false, 'a previous owner kept it');
    assert.equal(await sees('pl-other', S_M), false, 'another member saw a private library');
    assert.equal(await sees('pl-admin', S_M), true, 'an admin is kept out of a member-owned private library');
  });

  await t.test('an admin-owned library: its owner alone, even among admins', async () => {
    assert.equal(await sees('pl-admin', S_A), true);
    assert.equal(await sees('pl-admin2', S_A), false, 'another admin saw an admin\'s private library');
    assert.equal(await sees('pl-other', S_A), false);
  });

  await t.test('the library list does not name someone else\'s private library', async () => {
    const names = async (n: string) => (await owned.libraries(await ctx(n))).map((l: any) => l.id);
    assert.ok((await names('pl-restricted')).includes(LIB_M));
    assert.ok(!(await names('pl-other')).includes(LIB_M));
    assert.ok(!(await names('pl-admin2')).includes(LIB_A));
    assert.ok((await names('pl-admin2')).includes(LIB_M));
  });

  await t.test('Admin → Libraries: another admin\'s private library does not exist', async () => {
    const list = (await app.inject({ method: 'GET', url: '/api/admin/libraries', headers: as('pl-admin2') })).json();
    const ids = list.content.map((l: any) => l.id);
    assert.ok(!ids.includes(LIB_A));
    assert.ok(ids.includes(LIB_M));
    assert.deepEqual(list.content.find((l: any) => l.id === LIB_M).members, [id['pl-restricted']], 'only its owner can open it');
    const patch = await app.inject({ method: 'PATCH', url: `/api/admin/libraries/${LIB_A}`, headers: as('pl-admin2'), payload: { ownerId: null } });
    assert.equal(patch.statusCode, 404, 'another admin could make it public');
    const del = await app.inject({ method: 'DELETE', url: `/api/admin/libraries/${LIB_A}`, headers: as('pl-admin2') });
    assert.equal(del.statusCode, 404);
    const own = (await app.inject({ method: 'GET', url: '/api/admin/libraries', headers: as('pl-admin') })).json();
    assert.equal(own.content.find((l: any) => l.id === LIB_A)?.owner_id, id['pl-admin']);
  });

  await t.test('making it ordinary again opens it as before', async () => {
    const res = await app.inject({ method: 'PATCH', url: `/api/admin/libraries/${LIB_M}`, headers: as('pl-admin'), payload: { ownerId: null } });
    assert.equal(res.statusCode, 200);
    assert.equal(await sees('pl-other', S_M), true);
    const bad = await app.inject({ method: 'PATCH', url: `/api/admin/libraries/${LIB_M}`, headers: as('pl-admin'),
      payload: { ownerId: '00000000-0000-4000-8000-000000000000' } });
    assert.equal(bad.statusCode, 404, 'an owner that does not exist was accepted');
  });
});
