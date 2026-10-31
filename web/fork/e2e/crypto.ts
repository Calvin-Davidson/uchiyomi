// Fork-only: the browser side of end-to-end encrypted vaults, with WebCrypto. The server (bff/src/fork/e2e) stores
// public keys and what this file seals, and can read none of it. The service worker (public/e2e-sw.js) repeats the
// two operations it needs to open a page (openFrom, AES-GCM); keep the formats in step with it and with
// bff/src/fork/e2e/crypto.ts.
//
//   account password ──PBKDF2──▶ KEK ──AES-GCM──▶ member private key (ECDH P-256)        e2e_key_wraps
//   member public key ◀──ECIES── vault private key (ECDH P-256)                          e2e_vault_members
//   vault public key ◀──ECIES── chapter key (the SERVER seals it, at download)           in each sealed page
//   chapter key ──AES-GCM──▶ page                                                        the chapter file
//
// The member private key is unlocked through an `Unlocker`. `passwordUnlocker` derives the KEK from the account
// password at sign-in; this device then keeps the key under a non-extractable device key (device.ts) -- the DAK. A
// passkey or another device key would be one more Unlocker and one more e2e_key_wraps row for the SAME private key.

/** Bytes WebCrypto accepts (an ArrayBuffer-backed view: TS 5.7+ distinguishes it from a SharedArrayBuffer one). */
export type Bytes = Uint8Array<ArrayBuffer>;

const subtle = (): SubtleCrypto => {
  const s = globalThis.crypto?.subtle;
  if (!s) throw new Error('This browser has no WebCrypto here (it needs HTTPS, or localhost).');
  return s;
};
const enc = new TextEncoder();
const dec = new TextDecoder();
const utf8 = (s: string): Bytes => enc.encode(s) as Bytes;

/** `n` random bytes. getRandomValues fills at most 64 KiB per call, so larger asks are filled in pieces. */
export function random(n: number): Bytes {
  const out = new Uint8Array(n);
  for (let i = 0; i < n; i += 65_536) crypto.getRandomValues(out.subarray(i, Math.min(n, i + 65_536)));
  return out;
}

export function b64u(bytes: Uint8Array): string {
  let s = '';
  for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
export function unb64u(s: string): Bytes {
  const bin = atob(s.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((s.length + 3) % 4));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
export const newId = (): string => crypto.randomUUID();

// ── Associated data: what each ciphertext is bound to ─────────────────────────────────────────────────────────
export const ad = {
  identity: (userId: string) => utf8(`uchiyomi-e2e/v1/identity/${userId}`),
  vaultKey: (libraryId: string, userId: string) => utf8(`uchiyomi-e2e/v2/vault-key/${libraryId}/${userId}`),
  chapterKey: (libraryId: string) => utf8(`uchiyomi-e2e/v2/chapter-key/${libraryId}`),
};

// ── AES-256-GCM ─────────────────────────────────────────────────────────────────────────────────────────────────
export const importAes = (raw: Bytes, usages: KeyUsage[] = ['encrypt', 'decrypt']) =>
  subtle().importKey('raw', raw, { name: 'AES-GCM' }, false, usages);

async function gcm(key: CryptoKey, plain: Bytes, aad: Bytes): Promise<{ iv: Bytes; ct: Bytes }> {
  const iv = random(12);
  const ct = new Uint8Array(await subtle().encrypt({ name: 'AES-GCM', iv, additionalData: aad }, key, plain));
  return { iv, ct };
}
async function ungcm(key: CryptoKey, iv: Bytes, ct: Bytes, aad: Bytes): Promise<Bytes> {
  return new Uint8Array(await subtle().decrypt({ name: 'AES-GCM', iv, additionalData: aad }, key, ct));
}

/** A text-safe sealed value: `g1.<iv>.<ciphertext+tag>`. */
export async function sealString(key: CryptoKey, plain: Bytes, aad: Bytes): Promise<string> {
  const { iv, ct } = await gcm(key, plain, aad);
  return `g1.${b64u(iv)}.${b64u(ct)}`;
}
export async function openString(key: CryptoKey, sealed: string, aad: Bytes): Promise<Bytes> {
  const [v, iv, ct] = sealed.split('.');
  if (v !== 'g1' || !iv || !ct) throw new Error('Unknown ciphertext format');
  return ungcm(key, unb64u(iv), unb64u(ct), aad);
}
// ── The member's key pair ───────────────────────────────────────────────────────────────────────────────────────
export const IDENTITY_ALG = 'ecdh-p256';
const EC = { name: 'ECDH', namedCurve: 'P-256' } as const;

export interface NewIdentity { publicSpki: Bytes; pkcs8: Bytes }
export async function generateIdentity(): Promise<NewIdentity> {
  const kp = await subtle().generateKey(EC, true, ['deriveBits']) as CryptoKeyPair;
  return {
    publicSpki: new Uint8Array(await subtle().exportKey('spki', kp.publicKey)),
    pkcs8: new Uint8Array(await subtle().exportKey('pkcs8', kp.privateKey)),
  };
}
/** The unlocked private key, kept non-extractable: once unlocked, script can use it but never read it out. */
export const importPrivate = (pkcs8: Bytes) => subtle().importKey('pkcs8', pkcs8, EC, false, ['deriveBits']);
const importPublic = (spki: Bytes) => subtle().importKey('spki', spki, EC, true, []);

/** A short, human-comparable fingerprint of a public key, to check out of band that a key is who it says. */
export async function fingerprint(publicSpki: Bytes | string): Promise<string> {
  const bytes = typeof publicSpki === 'string' ? unb64u(publicSpki) : publicSpki;
  const h = new Uint8Array(await subtle().digest('SHA-256', bytes)).slice(0, 12);
  return [...h].map((b) => b.toString(16).padStart(2, '0')).join('').toUpperCase().match(/.{4}/g)!.join(' ');
}

// ── Unlockers: how the private key is wrapped at rest ───────────────────────────────────────────────────────────
export interface Unlocker {
  /** Stored as e2e_key_wraps.kind. */
  kind: string;
  wrap(pkcs8: Bytes, aad: Bytes): Promise<{ params: Record<string, unknown>; wrapped: string }>;
  unwrap(params: Record<string, unknown>, wrapped: string, aad: Bytes): Promise<Bytes>;
}

/** OWASP's 2023 floor for PBKDF2-HMAC-SHA256. Stored per wrap, so raising it later only affects new wraps. */
export const PBKDF2_ITERATIONS = 600_000;

async function passphraseKek(passphrase: string, salt: Bytes, iterations: number): Promise<CryptoKey> {
  const base = await subtle().importKey('raw', utf8(passphrase.normalize('NFKC')), 'PBKDF2', false, ['deriveKey']);
  return subtle().deriveKey({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations }, base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}

/** KEK from the account password (PBKDF2-SHA256), wrapping the private key with AES-256-GCM. */
export function passwordUnlocker(password: string, iterations = PBKDF2_ITERATIONS): Unlocker {
  return {
    kind: 'password',
    async wrap(pkcs8, aad) {
      const salt = random(16);
      const kek = await passphraseKek(password, salt, iterations);
      return { params: { kdf: 'pbkdf2-sha256', iterations, salt: b64u(salt) }, wrapped: await sealString(kek, pkcs8, aad) };
    },
    async unwrap(params, wrapped, aad) {
      if (params.kdf !== 'pbkdf2-sha256' || typeof params.salt !== 'string' || typeof params.iterations !== 'number') throw new Error('Unknown key wrap');
      const kek = await passphraseKek(password, unb64u(params.salt), params.iterations);
      return openString(kek, wrapped, aad);
    },
  };
}

export interface StoredWrap { id: string; kind: string; label: string; params: Record<string, unknown>; wrapped: string }

/** Try each stored wrap of the unlocker's kind; the first that opens wins. Throws when none does (a wrong password). */
export async function unlockWith(unlocker: Unlocker, wraps: StoredWrap[], userId: string): Promise<{ pkcs8: Bytes; wrapId: string }> {
  for (const w of wraps.filter((x) => x.kind === unlocker.kind)) {
    try { return { pkcs8: await unlocker.unwrap(w.params, w.wrapped, ad.identity(userId)), wrapId: w.id }; } catch { /* next */ }
  }
  throw new Error('wrong_password');
}

// ── ECIES: a library key, sealed to one member's public key ─────────────────────────────────────────────────────
export const WRAP_ALG = 'ecies-p256-hkdf-aesgcm';
export const VAULT_ALG = 'ecdh-p256';

async function ecdhAes(priv: CryptoKey, pub: CryptoKey, salt: Bytes, info: Bytes): Promise<CryptoKey> {
  const bits = await subtle().deriveBits({ name: 'ECDH', public: pub }, priv, 256);
  const ikm = await subtle().importKey('raw', bits, 'HKDF', false, ['deriveKey']);
  return subtle().deriveKey({ name: 'HKDF', hash: 'SHA-256', salt, info }, ikm, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}

/** `e1.<ephemeral public key>.<iv>.<ciphertext>`: only the holder of the recipient's private key can open it. */
export async function sealTo(recipientSpki: Bytes | string, plain: Bytes, aad: Bytes): Promise<string> {
  const pub = await importPublic(typeof recipientSpki === 'string' ? unb64u(recipientSpki) : recipientSpki);
  const eph = await subtle().generateKey(EC, true, ['deriveBits']) as CryptoKeyPair;
  const epk = new Uint8Array(await subtle().exportKey('raw', eph.publicKey));
  const key = await ecdhAes(eph.privateKey, pub, epk, aad);
  const { iv, ct } = await gcm(key, plain, aad);
  return `e1.${b64u(epk)}.${b64u(iv)}.${b64u(ct)}`;
}
export async function openFrom(priv: CryptoKey, sealed: string, aad: Bytes): Promise<Bytes> {
  const [v, epk, iv, ct] = sealed.split('.');
  if (v !== 'e1' || !epk || !iv || !ct) throw new Error('Unknown key envelope');
  const epkBytes = unb64u(epk);
  const pub = await subtle().importKey('raw', epkBytes, EC, false, []);
  const key = await ecdhAes(priv, pub, epkBytes, aad);
  return ungcm(key, unb64u(iv), unb64u(ct), aad);
}

// ── Sealed pages ───────────────────────────────────────────────────────────────────────────────────────────────
// "UYE2" | u32 header length (big-endian) | header JSON {v, k, t, w, h} | iv (12) | AES-GCM ciphertext+tag, where the
// associated data is everything before the iv. Written by the server (bff/src/fork/e2e/crypto.ts sealPage).

export interface PageHeader { v: 2; k: string; t: string; w: number | null; h: number | null }

export function isSealedPage(b: Uint8Array): boolean {
  return b.length > 8 && b[0] === 0x55 && b[1] === 0x59 && b[2] === 0x45 && b[3] === 0x32;
}

/** Open a sealed page with the vault's private key. `chapterKeys` caches opened chapter keys by their sealed form. */
export async function openPage(b: Bytes, vaultPriv: CryptoKey, libraryId: string, chapterKeys?: Map<string, CryptoKey>): Promise<{ type: string; bytes: Bytes }> {
  if (!isSealedPage(b)) throw new Error('not a sealed page');
  const n = new DataView(b.buffer, b.byteOffset, b.byteLength).getUint32(4);
  const header = JSON.parse(new TextDecoder().decode(b.subarray(8, 8 + n))) as PageHeader;
  let ck = chapterKeys?.get(header.k);
  if (!ck) {
    ck = await importAes(await openFrom(vaultPriv, header.k, ad.chapterKey(libraryId)), ['decrypt']);
    chapterKeys?.set(header.k, ck);
  }
  const aad = b.slice(0, 8 + n);
  const iv = b.slice(8 + n, 20 + n);
  return { type: header.t, bytes: await ungcm(ck, iv, b.slice(20 + n), aad) };
}
