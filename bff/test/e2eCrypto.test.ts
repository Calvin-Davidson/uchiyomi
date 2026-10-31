// Fork-only: what the SERVER encrypts when a series is moved into a vault (src/fork/vaults/crypto.ts, Node crypto) opens in
// the BROWSER's code (web/fork/vaults/crypto.ts, WebCrypto) -- the two halves are written separately and must agree byte
// for byte -- and a chapter file's offset table finds each page. No database.
import test from 'node:test';
import assert from 'node:assert/strict';

process.env.DATABASE_URL ||= 'postgres://unused:unused@127.0.0.1:1/unused';
process.env.JWT_SECRET ||= 'test-secret-at-least-16-chars';

const VAULT = 'vault_0123456789abcdef';
const ITEM = '33333333-3333-4333-8333-333333333333';

test("an item the server encrypts opens with the vault's private key in the browser's code, and with nothing else", async () => {
  const S = await import('../src/fork/vaults/crypto');
  const W = await import('../../web/fork/vaults/crypto');
  const vault = await W.generateIdentity();
  const other = await W.generateIdentity();
  const key = S.newItemKey(S.vaultPublicKey(W.b64u(vault.publicSpki)), VAULT, ITEM);

  const priv = await W.importPrivate(vault.pkcs8);
  const { key: ck } = await W.openItemKey(priv, VAULT, ITEM, key.sealed);
  await assert.rejects(W.openItemKey(await W.importPrivate(other.pkcs8), VAULT, ITEM, key.sealed));

  const meta = S.sealString(key.raw, Buffer.from(JSON.stringify({ title: 'Secret' })), S.ad.meta(ITEM));
  assert.deepEqual(await W.openJson(ck, meta, W.ad.meta(ITEM)), { title: 'Secret' });

  const pages = [Buffer.from('page one'), Buffer.from('page two, longer')];
  const file = S.chapterFile(pages.map((p, i) => S.sealRecord(key.raw, p, S.ad.page(ITEM, 0, i))));
  assert.equal(S.pageCountOf(file), 2);
  for (let i = 0; i < 2; i++) {
    const span = S.recordSpan(file, i)!;
    const rec = new Uint8Array(file.subarray(span.start, span.end));
    assert.equal(Buffer.from(await W.openRecord(ck, rec, W.ad.page(ITEM, 0, i))).toString(), pages[i].toString());
    // Bound to its place: page 0's record does not open as page 1.
    if (i === 0) await assert.rejects(W.openRecord(ck, rec, W.ad.page(ITEM, 0, 1)));
  }
  assert.equal(S.recordSpan(file, 2), null);

  // And the server opens what the browser writes (a member's progress, read back only in a move out).
  const state = await W.sealJson(ck, { chapters: {} }, W.ad.state(ITEM, 'u'));
  assert.deepEqual(JSON.parse(S.openString(key.raw, state, S.ad.state(ITEM, 'u')).toString()), { chapters: {} });
});
