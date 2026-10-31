// Fork-only: the server's half of vault encryption. It can only ENCRYPT, to a vault's public key; nothing here can
// decrypt, because the server never holds a private key. The browser half is web/fork/e2e/crypto.ts (and the
// service worker's copy, web/public/e2e-sw.js); the formats must stay byte-compatible with both.
//
// ECIES, as the browser does it: an ephemeral P-256 key, ECDH with the recipient's public key (the 32-byte x
// coordinate), HKDF-SHA256 (salt = the ephemeral public key, uncompressed; info = the associated data), AES-256-GCM
// with the same associated data. Written `e1.<ephemeral>.<iv>.<ciphertext+tag>`, base64url.
//
// A sealed page is still a ZIP entry under its own name, so every upstream archive reader keeps counting and ordering
// pages as before; only its bytes change:
//
//   "UYE2" | u32 header length | header JSON | iv (12) | AES-256-GCM(chapter key, page) incl. tag
//
// The header carries what the reader needs without decrypting: the chapter key sealed to the vault (`k`), the page's
// type (`t`) and size (`w`, `h`). The whole prefix up to and including the header is the page's associated data, so
// a header cannot be swapped onto another page's ciphertext.
import { createCipheriv, createPublicKey, diffieHellman, generateKeyPairSync, hkdfSync, randomBytes, type KeyObject } from 'crypto';

export const SEALED_MAGIC = Buffer.from('UYE2', 'latin1');
export const SEALED_TYPE = 'application/x-uchiyomi-e2e';

export const ad = {
  chapterKey: (libraryId: string) => Buffer.from(`uchiyomi-e2e/v2/chapter-key/${libraryId}`, 'utf8'),
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
  const iv = randomBytes(12);
  const c = createCipheriv('aes-256-gcm', key, iv);
  c.setAAD(aad);
  const ct = Buffer.concat([c.update(plain), c.final(), c.getAuthTag()]);
  return `e1.${b64u(epk)}.${b64u(iv)}.${b64u(ct)}`;
}

export interface PageHeader { v: 2; k: string; t: string; w: number | null; h: number | null }

/** A chapter's key: random, used for every page of one file, and handed out only sealed to the vault. */
export interface ChapterKey { raw: Buffer; sealed: string }
export function newChapterKey(vault: KeyObject, libraryId: string): ChapterKey {
  const raw = randomBytes(32);
  return { raw, sealed: sealTo(vault, raw, ad.chapterKey(libraryId)) };
}

export function sealPage(ck: ChapterKey, page: Buffer, meta: { type: string; width: number | null; height: number | null }): Buffer {
  const header = Buffer.from(JSON.stringify({ v: 2, k: ck.sealed, t: meta.type, w: meta.width, h: meta.height } satisfies PageHeader), 'utf8');
  const len = Buffer.alloc(4);
  len.writeUInt32BE(header.length);
  const prefix = Buffer.concat([SEALED_MAGIC, len, header]);
  const iv = randomBytes(12);
  const c = createCipheriv('aes-256-gcm', ck.raw, iv);
  c.setAAD(prefix);
  return Buffer.concat([prefix, iv, c.update(page), c.final(), c.getAuthTag()]);
}

export const isSealed = (b: Buffer | null | undefined): boolean => !!b && b.length > 8 && b.subarray(0, 4).equals(SEALED_MAGIC);

/** A sealed page's header, or null for anything else. Never throws. */
export function pageHeader(b: Buffer | null | undefined): PageHeader | null {
  if (!isSealed(b)) return null;
  try {
    const n = b!.readUInt32BE(4);
    if (n > 64 * 1024 || 8 + n > b!.length) return null;
    const h = JSON.parse(b!.subarray(8, 8 + n).toString('utf8')) as PageHeader;
    return h && h.v === 2 && typeof h.k === 'string' ? h : null;
  } catch { return null; }
}

/** A sealed page's stored size, for the reader's layout: what lib/library.ts cbzPageDims would have measured. */
export function sealedDims(b: Buffer | null | undefined): { width: number | null; height: number | null } | null {
  const h = pageHeader(b);
  return h ? { width: h.w ?? null, height: h.h ?? null } : null;
}
