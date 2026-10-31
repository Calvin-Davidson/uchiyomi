// Fork-only: the private libraries' browser crypto (web/fork/e2e/crypto.ts) and CBZ reader (web/fork/e2e/zip.ts),
// run against Node's WebCrypto, which is the same API the browser has.
import test from 'node:test';
import assert from 'node:assert/strict';
import { deflateRawSync } from 'node:zlib';
import * as C from '../fork/e2e/crypto';
import { imageEntries, zipEntries, zipRead } from '../fork/e2e/zip';

const ALICE = '11111111-1111-4111-8111-111111111111';
const BOB = '22222222-2222-4222-8222-222222222222';
const LIB = '33333333-3333-4333-8333-333333333333';
const ITEM = '44444444-4444-4444-8444-444444444444';
const enc = (s: string) => new TextEncoder().encode(s) as C.Bytes;
// Few iterations: the KDF's cost is not what is under test.
const pass = (p: string) => C.passphraseUnlocker(p, 1000);

test('a private key wrapped under a passphrase opens with it, and with nothing else', async () => {
  const id = await C.generateIdentity();
  const wrap = await pass('correct horse battery').wrap(id.pkcs8, C.ad.identity(ALICE));
  const stored: C.StoredWrap[] = [{ id: 'w1', kind: 'passphrase', label: '', ...wrap }];
  const { pkcs8, wrapId } = await C.unlockWith(pass('correct horse battery'), stored, ALICE);
  assert.deepEqual(pkcs8, id.pkcs8);
  assert.equal(wrapId, 'w1');
  await assert.rejects(C.unlockWith(pass('wrong horse battery'), stored, ALICE), /wrong_passphrase/);
  // Bound to the account: the same wrap handed to another user id does not open.
  await assert.rejects(C.unlockWith(pass('correct horse battery'), stored, BOB), /wrong_passphrase/);
  // An unlocker of another kind (a future device key) never tries a passphrase wrap.
  await assert.rejects(C.unlockWith({ ...pass('correct horse battery'), kind: 'device' }, stored, ALICE), /wrong_passphrase/);
});

test('a library key sealed to a member opens with their private key only, and only where it was sealed for', async () => {
  const alice = await C.generateIdentity();
  const bob = await C.generateIdentity();
  const lk = await C.newSymKey();
  const sealed = await C.sealTo(bob.publicSpki, lk.raw, C.ad.libraryKey(LIB, 1, BOB));
  assert.match(sealed, /^e1\./);
  const bobPriv = await C.importPrivate(bob.pkcs8);
  assert.deepEqual(await C.openFrom(bobPriv, sealed, C.ad.libraryKey(LIB, 1, BOB)), lk.raw);
  await assert.rejects(C.openFrom(await C.importPrivate(alice.pkcs8), sealed, C.ad.libraryKey(LIB, 1, BOB)));
  // Another version, library or member: refused.
  await assert.rejects(C.openFrom(bobPriv, sealed, C.ad.libraryKey(LIB, 2, BOB)));
  await assert.rejects(C.openFrom(bobPriv, sealed, C.ad.libraryKey(ITEM, 1, BOB)));
  await assert.rejects(C.openFrom(bobPriv, sealed, C.ad.libraryKey(LIB, 1, ALICE)));
});

test('the unlocked private key cannot be read back out', async () => {
  const id = await C.generateIdentity();
  const priv = await C.importPrivate(id.pkcs8);
  assert.equal(priv.extractable, false);
  await assert.rejects(crypto.subtle.exportKey('pkcs8', priv));
});

test('metadata and chunks are bound to their item, index and end', async () => {
  const ik = await C.newSymKey();
  const meta = await C.sealJson(ik.key, { name: 'Vol 1.cbz' }, C.ad.itemMeta(ITEM));
  assert.deepEqual(await C.openJson(ik.key, meta, C.ad.itemMeta(ITEM)), { name: 'Vol 1.cbz' });
  await assert.rejects(C.openJson(ik.key, meta, C.ad.itemMeta(LIB)));

  const plain = enc('page bytes');
  const chunk = await C.sealChunk(ik.key, plain, C.ad.chunk(ITEM, 0, true));
  assert.deepEqual(await C.openChunk(ik.key, chunk, C.ad.chunk(ITEM, 0, true)), plain);
  // Reordered, or presented as not the last (a file cut short), or tampered with: refused.
  await assert.rejects(C.openChunk(ik.key, chunk, C.ad.chunk(ITEM, 1, true)));
  await assert.rejects(C.openChunk(ik.key, chunk, C.ad.chunk(ITEM, 0, false)));
  const bent = chunk.slice(); bent[bent.length - 1] ^= 1;
  await assert.rejects(C.openChunk(ik.key, bent, C.ad.chunk(ITEM, 0, true)));
  // The ciphertext fits one upload under a 1 MiB proxy limit.
  const full = await C.sealChunk(ik.key, C.random(C.CHUNK_PLAIN), C.ad.chunk(ITEM, 0, true));
  assert.ok(full.length < 1024 * 1024);
});

test('an item key wrapped by the library key, and re-wrapped at a rotation', async () => {
  const lk1 = await C.newSymKey();
  const lk2 = await C.newSymKey();
  const ik = await C.newSymKey();
  const w1 = await C.sealString(lk1.key, ik.raw, C.ad.itemKey(LIB, ITEM, 1));
  const raw = await C.openString(lk1.key, w1, C.ad.itemKey(LIB, ITEM, 1));
  const w2 = await C.sealString(lk2.key, raw, C.ad.itemKey(LIB, ITEM, 2));
  assert.deepEqual(await C.openString(lk2.key, w2, C.ad.itemKey(LIB, ITEM, 2)), ik.raw);
  await assert.rejects(C.openString(lk1.key, w2, C.ad.itemKey(LIB, ITEM, 2)), 'the old library key opens nothing after a rotation');
});

test('fingerprints are stable and differ between keys', async () => {
  const a = await C.generateIdentity();
  const b = await C.generateIdentity();
  const fa = await C.fingerprint(a.publicSpki);
  assert.match(fa, /^[0-9A-F]{4}( [0-9A-F]{4}){5}$/);
  assert.equal(await C.fingerprint(C.b64u(a.publicSpki)), fa);
  assert.notEqual(await C.fingerprint(b.publicSpki), fa);
});

test('base64url round-trips any length', () => {
  for (const n of [0, 1, 2, 3, 31, 32, 33, 70_000]) {
    const b = C.random(n);
    assert.deepEqual(C.unb64u(C.b64u(b)), b);
    assert.doesNotMatch(C.b64u(b), /[+/=]/);
  }
});

/** A minimal ZIP writer, for the reader under test: one stored and some deflated entries. */
function makeZip(files: Array<{ name: string; data: Buffer; deflate: boolean }>): Uint8Array {
  const locals: Buffer[] = [];
  const centrals: Buffer[] = [];
  let offset = 0;
  for (const f of files) {
    const name = Buffer.from(f.name);
    const body = f.deflate ? deflateRawSync(f.data) : f.data;
    const lh = Buffer.alloc(30);
    lh.writeUInt32LE(0x04034b50, 0); lh.writeUInt16LE(20, 4); lh.writeUInt16LE(f.deflate ? 8 : 0, 8);
    lh.writeUInt32LE(body.length, 18); lh.writeUInt32LE(f.data.length, 22); lh.writeUInt16LE(name.length, 26);
    const ch = Buffer.alloc(46);
    ch.writeUInt32LE(0x02014b50, 0); ch.writeUInt16LE(20, 4); ch.writeUInt16LE(20, 6); ch.writeUInt16LE(f.deflate ? 8 : 0, 10);
    ch.writeUInt32LE(body.length, 20); ch.writeUInt32LE(f.data.length, 24); ch.writeUInt16LE(name.length, 28); ch.writeUInt32LE(offset, 42);
    locals.push(lh, name, body);
    centrals.push(ch, name);
    offset += lh.length + name.length + body.length;
  }
  const cd = Buffer.concat(centrals);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0); end.writeUInt16LE(files.length, 8); end.writeUInt16LE(files.length, 10);
  end.writeUInt32LE(cd.length, 12); end.writeUInt32LE(offset, 16);
  return new Uint8Array(Buffer.concat([...locals, cd, end]));
}

test('a CBZ is read in natural page order, stored and deflated alike, without macOS litter', async () => {
  const page = (n: number) => Buffer.from(`page-${n}-`.repeat(50));
  const zip = makeZip([
    { name: 'ch/10.jpg', data: page(10), deflate: true },
    { name: 'ch/2.jpg', data: page(2), deflate: false },
    { name: 'ch/1.png', data: page(1), deflate: true },
    { name: '__MACOSX/ch/._1.png', data: Buffer.from('x'), deflate: false },
    { name: 'ComicInfo.xml', data: Buffer.from('<x/>'), deflate: true },
  ]);
  const pages = imageEntries(zipEntries(zip));
  assert.deepEqual(pages.map((e) => e.name), ['ch/1.png', 'ch/2.jpg', 'ch/10.jpg']);
  assert.deepEqual(Buffer.from(await zipRead(zip, pages[0])), page(1));
  assert.deepEqual(Buffer.from(await zipRead(zip, pages[1])), page(2));
  assert.deepEqual(Buffer.from(await zipRead(zip, pages[2])), page(10));
  assert.throws(() => zipEntries(new Uint8Array(100)), /Not a ZIP/);
});
