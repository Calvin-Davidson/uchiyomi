// Fork-only: the vault's browser crypto (web/fork/e2e/crypto.ts), run against Node's WebCrypto -- the same API the
// browser has. That pages the SERVER seals open here is bff/test/e2eCrypto.test.ts's.
import test from 'node:test';
import assert from 'node:assert/strict';
import * as C from '../fork/e2e/crypto';

const ALICE = '11111111-1111-4111-8111-111111111111';
const BOB = '22222222-2222-4222-8222-222222222222';
const VAULT = 'vault_0123456789abcdef';
// Few iterations: the KDF's cost is not what is under test.
const pw = (p: string) => C.passwordUnlocker(p, 1000);

test('a private key wrapped under the account password opens with it, and with nothing else', async () => {
  const id = await C.generateIdentity();
  const wrap = await pw('correct horse battery').wrap(id.pkcs8, C.ad.identity(ALICE));
  const stored: C.StoredWrap[] = [{ id: 'w1', kind: 'password', label: '', ...wrap }];
  assert.equal(pw('x').kind, 'password');
  const { pkcs8, wrapId } = await C.unlockWith(pw('correct horse battery'), stored, ALICE);
  assert.deepEqual(pkcs8, id.pkcs8);
  assert.equal(wrapId, 'w1');
  await assert.rejects(C.unlockWith(pw('wrong horse battery'), stored, ALICE), /wrong_password/);
  // Bound to the account: the same wrap handed to another user id does not open.
  await assert.rejects(C.unlockWith(pw('correct horse battery'), stored, BOB), /wrong_password/);
  // An unlocker of another kind (a device key, later) never tries a password wrap.
  await assert.rejects(C.unlockWith({ ...pw('correct horse battery'), kind: 'device' }, stored, ALICE), /wrong_password/);
});

test("a vault's private key sealed to a member opens with their key only, for that vault and member only", async () => {
  const alice = await C.generateIdentity();
  const bob = await C.generateIdentity();
  const vault = await C.generateIdentity();
  const sealed = await C.sealTo(bob.publicSpki, vault.pkcs8, C.ad.vaultKey(VAULT, BOB));
  assert.match(sealed, /^e1\./);
  const bobPriv = await C.importPrivate(bob.pkcs8);
  assert.deepEqual(await C.openFrom(bobPriv, sealed, C.ad.vaultKey(VAULT, BOB)), vault.pkcs8);
  await assert.rejects(C.openFrom(await C.importPrivate(alice.pkcs8), sealed, C.ad.vaultKey(VAULT, BOB)));
  await assert.rejects(C.openFrom(bobPriv, sealed, C.ad.vaultKey('vault_ffffffffffffffff', BOB)));
  await assert.rejects(C.openFrom(bobPriv, sealed, C.ad.vaultKey(VAULT, ALICE)));
});

test('the unlocked private key cannot be read back out', async () => {
  const id = await C.generateIdentity();
  const priv = await C.importPrivate(id.pkcs8);
  assert.equal(priv.extractable, false);
  await assert.rejects(crypto.subtle.exportKey('pkcs8', priv));
});

test('fingerprints are stable and differ between keys', async () => {
  const a = await C.generateIdentity();
  const b = await C.generateIdentity();
  const fa = await C.fingerprint(a.publicSpki);
  assert.match(fa, /^[0-9A-F]{4}( [0-9A-F]{4}){5}$/);
  assert.equal(await C.fingerprint(C.b64u(a.publicSpki)), fa);
  assert.notEqual(await C.fingerprint(b.publicSpki), fa);
});

test('base64url round-trips any length, and random() fills more than 64 KiB', () => {
  for (const n of [0, 1, 2, 3, 31, 32, 33, 70_000]) {
    const b = C.random(n);
    assert.deepEqual(C.unb64u(C.b64u(b)), b);
    assert.doesNotMatch(C.b64u(b), /[+/=]/);
  }
  assert.ok(C.random(70_000).subarray(66_000).some((x) => x !== 0));
});

test('only a sealed page is taken for one', () => {
  assert.equal(C.isSealedPage(new TextEncoder().encode('UYE2\0\0\0\0rest')), true);
  assert.equal(C.isSealedPage(new Uint8Array([0xff, 0xd8, 0xff, 0xe0, 0, 0, 0, 0, 0])), false);
});
