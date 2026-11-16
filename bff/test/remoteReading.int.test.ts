import test, { before, after } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';

const DSN = process.env.TEST_DATABASE_URL;
const skip = DSN ? false : 'set TEST_DATABASE_URL to run';
if (DSN) {
  process.env.DATABASE_URL = DSN;
  process.env.JWT_SECRET = 'remote-reading-test-secret-12345';
  process.env.LIBRARY_BACKEND = 'owned';
}
let app: any, q: any, uid: string, other: string;
const digest = 'a'.repeat(64);
const path = `/api/personal/remote-books/${digest}/progress`;
const headers = (id = uid) => ({authorization:`Bearer ${app.jwt.sign({sub:id,role:'user'})}`});
const event = (page = 1, more = {}) => ({title:'Chapter 1.cbz',seriesTitle:'Remote story',page,pages:10,eventId:randomUUID(),at:Date.now(),...more});

before(async () => {
  if (!DSN) return;
  ({q} = await import('../src/lib/db'));
  await (await import('../src/lib/migrate')).migrate();
  uid = (await q("INSERT INTO users(display_name,password_hash) VALUES('Remote reader','x') RETURNING id"))[0].id;
  other = (await q("INSERT INTO users(display_name,password_hash) VALUES('Other reader','x') RETURNING id"))[0].id;
  const Fastify = (await import('fastify')).default;
  app = Fastify();
  await app.register((await import('@fastify/cookie')).default);
  await app.register((await import('@fastify/jwt')).default,{secret:process.env.JWT_SECRET!});
  await app.register((await import('@fastify/rate-limit')).default,{global:false});
  await app.register((await import('../src/routes/remoteReading')).remoteReadingRoutes);
  await app.register((await import('../src/routes/personal')).default);
  await app.ready();
});
after(async () => {
  if (!DSN) return;
  await app?.close();
  if (uid && other) await q('DELETE FROM users WHERE id=ANY($1::uuid[])',[[uid,other]]);
  await (await import('../src/lib/db')).pool.end();
});

test('remote progress authenticates, validates, resumes, and isolates accounts', {skip}, async () => {
  assert.equal((await app.inject({method:'GET',url:path})).statusCode,401);
  assert.equal((await app.inject({method:'PUT',url:path,headers:headers(),payload:event(11)})).statusCode,400);
  const write = await app.inject({method:'PUT',url:path,headers:headers(),payload:event(4)});
  assert.equal(write.statusCode,200,write.body);
  const read = await app.inject({method:'GET',url:path,headers:headers()});
  assert.equal(read.json().page,4); assert.match(read.headers['cache-control'],/no-store/);
  assert.deepEqual((await app.inject({method:'GET',url:path,headers:headers(other)})).json(),{page:1,completed:false});
  assert.equal((await q("SELECT count(*)::int n FROM lib_books WHERE id LIKE 'remote:%'"))[0].n,0,'no decrypted server library');
});

test('retry-safe activity appears in normal history and stats; completion never regresses', {skip}, async () => {
  const payload = event(10);
  for (let n=0;n<2;n++) assert.equal((await app.inject({method:'PUT',url:path,headers:headers(),payload})).statusCode,200);
  assert.equal((await q('SELECT count(*)::int n FROM reading_events WHERE user_id=$1',[uid]))[0].n,2,'retry has one receipt, one event');
  const history = await app.inject({method:'GET',url:'/api/history',headers:headers()});
  assert.equal(history.statusCode,200,history.body);
  assert.equal(history.json().content[0].book_title,'Chapter 1.cbz'); assert.equal(history.json().content[0].remote,true);
  assert.equal((await app.inject({method:'GET',url:'/api/history',headers:headers(other)})).json().content.length,0);
  const stats = await app.inject({method:'GET',url:'/api/stats',headers:headers()});
  assert.equal(stats.statusCode,200,stats.body); assert.equal(stats.json().chapters_completed,1);
  await app.inject({method:'PUT',url:path,headers:headers(),payload:event(2,{at:Date.now()-60000})});
  const position = (await app.inject({method:'GET',url:path,headers:headers()})).json();
  assert.equal(position.page,10); assert.equal(position.completed,true,'late writes cannot rewind completion');
  await app.inject({method:'PUT',url:path,headers:headers(),payload:event(3)});
  assert.equal((await app.inject({method:'GET',url:path,headers:headers()})).json().page,3,'intentional backwards turn is saved');
});

test('account Incognito saves the bookmark without recording activity', {skip}, async () => {
  const before = (await q('SELECT count(*)::int n FROM reading_events WHERE user_id=$1',[uid]))[0].n;
  await q(`INSERT INTO app_settings(user_id,data) VALUES($1,'{"incognito":true}') ON CONFLICT(user_id) DO UPDATE SET data=EXCLUDED.data`,[uid]);
  const response = await app.inject({method:'PUT',url:path,headers:headers(),payload:event(6)});
  assert.equal(response.statusCode,200,response.body); assert.equal(response.json().incognito,true);
  assert.equal((await app.inject({method:'GET',url:path,headers:headers()})).json().page,6);
  assert.equal((await q('SELECT count(*)::int n FROM reading_events WHERE user_id=$1',[uid]))[0].n,before);
  assert.equal((await q('SELECT bool_and(is_private) yes FROM reading_events WHERE user_id=$1',[uid]))[0].yes,true);
});
