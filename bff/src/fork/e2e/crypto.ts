// Fork-only: the server's half of vault encryption. The browser half is web/fork/e2e/crypto.ts; the formats must stay
// byte-compatible with it.
//
// The server touches plaintext twice, and only when a member asks it to:
//   - moving a series IN: it already holds the series in the clear, so it encrypts it under a fresh item key and seals
//     that key to the vault's PUBLIC key. After that it can't read the item back.
//   - moving a series OUT: the member's browser opens the item key and hands it over for that one request.
//
// ECIES, as the browser does it: an ephemeral P-256 key, ECDH with the recipient's public key, HKDF-SHA256 (salt = the
// ephemeral public key, uncompressed; info = the associated data), AES-256-GCM with the same associated data. Written
// `e1.<ephemeral>.<iv>.<ciphertext+tag>`, base64url.
//
// A chapter file (one per chapter, pages in reading order) keeps a plaintext offset table so a page can be served by
// byte range without the key:
//
//   "UYV3" | u32 page count | (count + 1) x u64 offsets from the start of the file | records, each iv (12) | ct+tag
import { createCipheriv, createDecipheriv, createPublicKey, diffieHellman, generateKeyPairSync, hkdfSync, randomBytes, type KeyObject } from 'crypto';

export const CHAPTER_MAGIC = Buffer.from('UYV3', 'latin1');

const s = (x: string) => Buffer.from(x, 'utf8');
/** Associated data: what each ciphertext is bound to. */
export const ad = {
  itemKey: (vaultId: string, itemId: string) => s(`uchiyomi-e2e/v3/item-key/${vaultId}/${itemId}`),
  meta: (itemId: string) => s(`uchiyomi-e2e/v3/meta/${itemId}`),
  cover: (itemId: string) => s(`uchiyomi-e2e/v3/cover/${itemId}`),
  page: (itemId: string, chapter: number, page: number) => s(`uchiyomi-e2e/v3/page/${itemId}/${chapter}/${page}`),
  state: (itemId: string, userId: string) => s(`uchiyomi-e2e/v3/state/${itemId}/${userId}`),
};

const b64u = (b: Buffer) => b.toString('base64url');

/** A vault public key (SPKI, base64url) as a KeyObject; throws on anything that is not a P-256 public key. */
export function vaultPublicKey(spkiB64u: string): KeyObject {
  const key = createPublicKey({ key: Buffer.from(spkiB64u, 'base64url'), format: 'der', type: 'spki' });
  if (key.asymmetricKeyType !== 'ec' || key.asymmetricKeyDetails?.namedCurve !== 'prime256v1') throw new Error('not a P-256 key');
  return key;
}

/** The uncompressed point (0x04 | x | y) of an EC public key: what WebCrypto exports as `raw`. */
function rawPoint(key: KeyObject): Buffer {
  const jwk = key.export({ format: 'jwk' }) as { x: string; y: string };
  return Buffer.concat([Buffer.from([4]), Buffer.from(jwk.x, 'base64url'), Buffer.from(jwk.y, 'base64url')]);
}

/** Seal `plain` so only the holder of `recipient`'s private key can open it. */
export function sealTo(recipient: KeyObject, plain: Buffer, aad: Buffer): string {
  const eph = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const epk = rawPoint(eph.publicKey);
  const shared = diffieHellman({ privateKey: eph.privateKey, publicKey: recipient });
  const key = Buffer.from(hkdfSync('sha256', shared, epk, aad, 32));
  const { iv, ct } = gcm(key, plain, aad);
  return `e1.${b64u(epk)}.${b64u(iv)}.${b64u(ct)}`;
}

function gcm(key: Buffer, plain: Buffer, aad: Buffer): { iv: Buffer; ct: Buffer } {
  const iv = randomBytes(12);
  const c = createCipheriv('aes-256-gcm', key, iv);
  c.setAAD(aad);
  return { iv, ct: Buffer.concat([c.update(plain), c.final(), c.getAuthTag()]) };
}

function ungcm(key: Buffer, iv: Buffer, ct: Buffer, aad: Buffer): Buffer {
  if (ct.length < 16) throw new Error('short ciphertext');
  const d = createDecipheriv('aes-256-gcm', key, iv);
  d.setAAD(aad);
  d.setAuthTag(ct.subarray(ct.length - 16));
  return Buffer.concat([d.update(ct.subarray(0, ct.length - 16)), d.final()]);
}

/** `iv | ct+tag`: one encrypted record (a page, a cover). */
export const sealRecord = (key: Buffer, plain: Buffer, aad: Buffer): Buffer => { const { iv, ct } = gcm(key, plain, aad); return Buffer.concat([iv, ct]); };
export const openRecord = (key: Buffer, rec: Buffer, aad: Buffer): Buffer => ungcm(key, rec.subarray(0, 12), rec.subarray(12), aad);

/** A text-safe sealed value, `g1.<iv>.<ct>`: the item's manifest and members' reading state. */
export function sealString(key: Buffer, plain: Buffer, aad: Buffer): string {
  const { iv, ct } = gcm(key, plain, aad);
  return `g1.${b64u(iv)}.${b64u(ct)}`;
}
export function openString(key: Buffer, sealed: string, aad: Buffer): Buffer {
  const [v, iv, ct] = sealed.split('.');
  if (v !== 'g1' || !iv || !ct) throw new Error('unknown ciphertext format');
  return ungcm(key, Buffer.from(iv, 'base64url'), Buffer.from(ct, 'base64url'), aad);
}

/** A new item: its random key, and that key sealed to the vault. */
export function newItemKey(vault: KeyObject, vaultId: string, itemId: string): { raw: Buffer; sealed: string } {
  const raw = randomBytes(32);
  return { raw, sealed: sealTo(vault, raw, ad.itemKey(vaultId, itemId)) };
}

/** A chapter file from its already-encrypted page records. */
export function chapterFile(records: Buffer[]): Buffer {
  const head = 8 + (records.length + 1) * 8;
  const table = Buffer.alloc(head);
  CHAPTER_MAGIC.copy(table, 0);
  table.writeUInt32BE(records.length, 4);
  let at = head;
  for (let i = 0; i <= records.length; i++) {
    table.writeBigUInt64BE(BigInt(at), 8 + i * 8);
    if (i < records.length) at += records[i].length;
  }
  return Buffer.concat([table, ...records]);
}

/** Where page `index` (0-based) sits in a chapter file, from its header (the first 8 + 8(n+1) bytes). */
export function recordSpan(header: Buffer, index: number): { start: number; end: number } | null {
  if (header.length < 8 || !header.subarray(0, 4).equals(CHAPTER_MAGIC)) return null;
  const n = header.readUInt32BE(4);
  if (index < 0 || index >= n || header.length < 8 + (n + 1) * 8) return null;
  return { start: Number(header.readBigUInt64BE(8 + index * 8)), end: Number(header.readBigUInt64BE(8 + (index + 1) * 8)) };
}

export const pageCountOf = (header: Buffer): number =>
  header.length >= 8 && header.subarray(0, 4).equals(CHAPTER_MAGIC) ? header.readUInt32BE(4) : 0;
