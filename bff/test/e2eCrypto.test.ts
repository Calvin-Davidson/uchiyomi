// Fork-only: a page the SERVER seals (src/fork/e2e/crypto.ts, Node crypto) opens in the BROWSER's code
// (web/fork/e2e/crypto.ts, WebCrypto) -- the two halves are written separately and must agree byte for byte -- and the
// sealing of a whole CBZ (src/fork/e2e/seal.ts) leaves an archive every upstream reader still counts and orders.
// No database.
import test from 'node:test';
import assert from 'node:assert/strict';
import AdmZip from 'adm-zip';
import sharp from 'sharp';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

process.env.DATABASE_URL ||= 'postgres://unused:unused@127.0.0.1:1/unused';
process.env.JWT_SECRET ||= 'test-secret-at-least-16-chars';

const VAULT = 'vault_0123456789abcdef';

test("a page the server seals opens with the vault's private key in the browser's code, and with nothing else", async () => {
  const S = await import('../src/fork/e2e/crypto');
  const W = await import('../../web/fork/e2e/crypto');
  const vault = await W.generateIdentity();
  const other = await W.generateIdentity();
  const pub = S.vaultPublicKey(W.b64u(vault.publicSpki));
  const page = await sharp({ create: { width: 30, height: 70, channels: 3, background: '#c00' } }).png().toBuffer();

  const ck = S.newChapterKey(pub, VAULT);
  const sealed = S.sealPage(ck, page, { type: 'image/png', width: 30, height: 70 });
  assert.ok(S.isSealed(sealed));
  assert.deepEqual(S.sealedDims(sealed), { width: 30, height: 70 });
  assert.equal(sealed.includes(page.subarray(0, 16)), false, 'no plain bytes in the sealed page');

  const priv = await W.importPrivate(vault.pkcs8);
  const cache = new Map<string, CryptoKey>();
  const opened = await W.openPage(new Uint8Array(sealed), priv, VAULT, cache);
  assert.equal(opened.type, 'image/png');
  assert.deepEqual(Buffer.from(opened.bytes), page);
  assert.equal(cache.size, 1, 'the chapter key is opened once per chapter');

  await assert.rejects(W.openPage(new Uint8Array(sealed), await W.importPrivate(other.pkcs8), VAULT), 'another key');
  await assert.rejects(W.openPage(new Uint8Array(sealed), priv, 'vault_ffffffffffffffff'), 'another vault');
  const bent = Buffer.from(sealed); bent[bent.length - 1] ^= 1;
  await assert.rejects(W.openPage(new Uint8Array(bent), priv, VAULT), 'a changed byte');
  // A header taken onto another page's ciphertext does not open: the header is associated data.
  const other2 = S.sealPage(ck, page, { type: 'image/jpeg', width: 30, height: 70 });
  const n = sealed.readUInt32BE(4), n2 = other2.readUInt32BE(4);
  const swapped = Buffer.concat([other2.subarray(0, 8 + n2), sealed.subarray(8 + n)]);
  await assert.rejects(W.openPage(new Uint8Array(swapped), priv, VAULT));
  // The server-side ECIES opens with the browser's openFrom, as the service worker does it.
  const raw = await W.openFrom(priv, ck.sealed, W.ad.chapterKey(VAULT));
  assert.deepEqual(Buffer.from(raw), ck.raw);
});

test('sealing a CBZ seals its pages only, keeps every name, and is idempotent', async () => {
  const S = await import('../src/fork/e2e/crypto');
  const { sealZip } = await import('../src/fork/e2e/seal');
  const { cbzPages, cbzPageAt, cbzPageDims } = await import('../src/lib/library');
  const W = await import('../../web/fork/e2e/crypto');
  const vault = await W.generateIdentity();
  const pk = W.b64u(vault.publicSpki);
  const png = (w: number) => sharp({ create: { width: w, height: 40, channels: 3, background: '#0c0' } }).png().toBuffer();

  const zip = new AdmZip();
  zip.addFile('002.png', await png(20));
  zip.addFile('001.png', await png(10));
  zip.addFile('010.png', await png(30));
  zip.addFile('ComicInfo.xml', Buffer.from('<ComicInfo><Number>3</Number></ComicInfo>'));
  assert.equal(await sealZip(zip, VAULT, pk), 3);
  assert.equal(await sealZip(zip, VAULT, pk), 0, 'nothing left to seal');

  const dir = mkdtempSync(join(tmpdir(), 'uchi-e2e-'));
  const file = join(dir, 'ch.cbz');
  writeFileSync(file, zip.toBuffer());
  assert.deepEqual(await cbzPages(file), ['001.png', '002.png', '010.png'], 'the upstream reader still lists the pages in order');
  const first = await cbzPageAt(file, 0);
  assert.ok(first && S.isSealed(first.bytes));
  assert.deepEqual((await cbzPageDims(file)).map((d) => d.width), [10, 20, 30], 'sizes come from the sealed headers');
  assert.match(new AdmZip(file).readAsText('ComicInfo.xml'), /<Number>3</, 'ComicInfo stays readable for the scanner');

  const priv = await W.importPrivate(vault.pkcs8);
  const opened = await W.openPage(new Uint8Array(first!.bytes), priv, VAULT);
  assert.deepEqual(Buffer.from(opened.bytes), await png(10));
});
