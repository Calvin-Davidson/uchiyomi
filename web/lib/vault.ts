// End-to-end encrypted vaults (docs/VAULTS.md), from the web app's side: the keys, the calls to /api/e2e, and this
// device's copy of the account's private key. Three hooks are called from elsewhere, and none of them may ever break
// what they are hooked into, so each swallows its own failures:
//   vaultAfterLogin       lib/auth.tsx login()                -- the password just typed unlocks (or creates) the key
//   vaultForget           lib/auth.tsx sign-out               -- this device forgets every key
//   vaultPasswordChanged  components/ProfileAccount.tsx       -- the key is re-wrapped under the new password
// A server without VAULTS answers /api/e2e/status with a 404, and every one of them does nothing.
import { api, ApiError } from './api';
import {
  ad, b64u, random, generateIdentity, IDENTITY_ALG, importPrivate, openFrom, openItemKey, passwordUnlocker, sealTo,
  unlockWith, VAULT_ALG, WRAP_ALG, type Bytes, type StoredWrap,
} from './vaultCrypto';

// ── Wire shapes ────────────────────────────────────────────────────────────────────────────────────────────────
export interface VaultRef { id: string; ownerId: string; publicKey: string; wrapAlg: string; wrappedKey: string }
export interface VaultStatus { enabled: boolean; hasKeys: boolean; publicKey: string | null; passwordAccount: boolean; vaults: VaultRef[] }
interface KeysDoc { alg: string; publicKey: string; wraps: StoredWrap[] }
/** One series in a vault, as the server sends it: everything but the counts is ciphertext. */
export interface ItemRow { id: string; itemKey: string; meta: string; chapters: number; bytes: number; createdAt: string; state: string | null }
interface Job { kind: 'in' | 'out'; state: 'running' | 'done' | 'failed'; done: number; total: number; error: string | null }

const enc = encodeURIComponent;

/** A series that lives in a vault: the service worker (public/vault-sw.js) answers for it, under ids it made up. */
export const isVaultSeries = (id: string): boolean => id.startsWith('vlt-');

/** The server's refusal code (`{ error }`), for an ApiError. */
export function errorCode(e: unknown): string | null {
  if (!(e instanceof ApiError)) return null;
  try { return (JSON.parse(e.body) as { error?: string }).error ?? null; } catch { return null; }
}

/** The vault status, or null when the server has no vaults (VAULTS unset). */
export async function fetchStatus(): Promise<VaultStatus | null> {
  try { return await api<VaultStatus>('/api/e2e/status'); } catch (e) {
    if (e instanceof ApiError && e.status === 404) return null;
    throw e;
  }
}

const secure = (): boolean => typeof window !== 'undefined' && !!window.isSecureContext && !!globalThis.crypto?.subtle;

/** Tell the service worker (public/vault-sw.js) to open the vault again: after a move, an unlock or a sign-in. */
export function resetWorker(): void {
  try { navigator.serviceWorker?.controller?.postMessage({ e2e: 'reset' }); } catch { /* no worker */ }
}

// ── This device's copy of the private key ──────────────────────────────────────────────────────────────────────
// Kept in IndexedDB, encrypted under a device key that is a NON-EXTRACTABLE AES key: the browser can use it, no script
// can read it out, and it never leaves this device. The service worker reads the same store to open pages, so the
// database name, store and record shape are a contract with public/vault-sw.js. Holding the private key itself (wrapped)
// rather than only a non-extractable copy is what lets a password change, or a reset done elsewhere, re-wrap it here.
const DB_NAME = 'uchiyomi-e2e';
const STORE = 'device';

interface DeviceRecord { userId: string; dak: CryptoKey; iv: Bytes; ct: Bytes; publicKey: string; at: number }

function openDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const r = indexedDB.open(DB_NAME, 1);
    r.onupgradeneeded = () => { if (!r.result.objectStoreNames.contains(STORE)) r.result.createObjectStore(STORE, { keyPath: 'userId' }); };
    r.onsuccess = () => resolve(r.result);
    r.onerror = () => reject(r.error);
  });
}

async function run<T>(mode: IDBTransactionMode, fn: (s: IDBObjectStore) => IDBRequest): Promise<T> {
  const db = await openDb();
  try {
    return await new Promise<T>((resolve, reject) => {
      const req = fn(db.transaction(STORE, mode).objectStore(STORE));
      req.onsuccess = () => resolve(req.result as T);
      req.onerror = () => reject(req.error);
    });
  } finally { db.close(); }
}

/** Keep `pkcs8` on this device for `userId`, under a fresh non-extractable device key. */
async function saveDeviceKey(userId: string, pkcs8: Bytes, publicKey: string): Promise<void> {
  const dak = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  const iv = random(12);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, dak, pkcs8));
  await run('readwrite', (s) => s.put({ userId, dak, iv, ct, publicKey, at: Date.now() } satisfies DeviceRecord));
}

/** This device's copy of the private key for `userId`, or null. */
async function loadDeviceKey(userId: string): Promise<{ pkcs8: Bytes; publicKey: string } | null> {
  const rec = await run<DeviceRecord | undefined>('readonly', (s) => s.get(userId)).catch(() => undefined);
  if (!rec) return null;
  try {
    const pkcs8 = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: rec.iv }, rec.dak, rec.ct));
    return { pkcs8, publicKey: rec.publicKey };
  } catch { return null; }
}

/** Whether this device holds the key for `userId`. */
export const deviceUnlocked = async (userId: string): Promise<boolean> =>
  !!(await run<DeviceRecord | undefined>('readonly', (s) => s.get(userId)).catch(() => undefined));

// ── Keys ───────────────────────────────────────────────────────────────────────────────────────────────────────

/**
 * Unlock (or make) this account's key with its password, and keep it on this device. `verified` says the password is
 * known good (it just signed in); otherwise a first key is only made after the server confirms the password.
 * Throws Error('wrong_password') when the password does not open the key and this device holds no copy to re-wrap.
 */
export async function unlockWithPassword(userId: string, password: string, verified: boolean): Promise<void> {
  await unlockKey(userId, password, verified);
  await ensureVault(userId);
}

let ensuring: Promise<void> | null = null;
/**
 * Every password account has its own vault: made here, the first time its key is unlocked, so nobody has to "create"
 * one. Joined while running, so a sign-in and the Vault page at once make one vault, not two.
 */
export function ensureVault(userId: string): Promise<void> {
  return ensuring ??= (async () => {
    const status = await fetchStatus();
    if (!status?.publicKey || !status.passwordAccount || status.vaults.some((v) => v.ownerId === userId)) return;
    if (!(await deviceUnlocked(userId))) return;
    await createVault(userId, status.publicKey);
  })().finally(() => { ensuring = null; });
}

async function unlockKey(userId: string, password: string, verified: boolean): Promise<void> {
  const keys = await api<KeysDoc>('/api/e2e/keys').catch((e) => {
    if (e instanceof ApiError && e.status === 404) return null;
    throw e;
  });
  if (!keys) {
    if (!verified) await api('/api/e2e/verify-password', { json: { password } }).catch((e) => {
      throw errorCode(e) === 'wrong_password' ? new Error('wrong_password') : e;
    });
    const id = await generateIdentity();
    const wrap = await passwordUnlocker(password).wrap(id.pkcs8, ad.identity(userId));
    const publicKey = b64u(id.publicSpki);
    await api('/api/e2e/keys', { method: 'PUT', json: { alg: IDENTITY_ALG, publicKey, wrap: { kind: 'password', label: 'Account password', ...wrap } } });
    await saveDeviceKey(userId, id.pkcs8, publicKey);
    return;
  }
  try {
    const { pkcs8 } = await unlockWith(passwordUnlocker(password), keys.wraps, userId);
    await saveDeviceKey(userId, pkcs8, keys.publicKey);
  } catch (e) {
    // The password changed somewhere this app did not see (an admin reset it, another client). If this device still
    // holds the key, wrap it under the password that works now; otherwise the key stays locked.
    const local = await loadDeviceKey(userId);
    if (!local || local.publicKey !== keys.publicKey) throw e;
    await rewrap(userId, local.pkcs8, password, keys);
  }
}

/** Replace the password wrap with `pkcs8` wrapped under `password`. */
async function rewrap(userId: string, pkcs8: Bytes, password: string, keys: KeysDoc): Promise<void> {
  const old = keys.wraps.find((w) => w.kind === 'password');
  if (!old) throw new Error('no password wrap');
  const wrap = await passwordUnlocker(password).wrap(pkcs8, ad.identity(userId));
  await api(`/api/e2e/keys/wraps/${enc(old.id)}`, { method: 'PUT', json: wrap });
}

/** lib/auth.tsx, after a password sign-in. Never throws, never delays the sign-in. */
export function vaultAfterLogin(userId: string, password: string): void {
  if (!secure()) return;
  void (async () => {
    if (!(await fetchStatus())) return;
    await unlockWithPassword(userId, password, true);
    resetWorker();
  })().catch(() => { /* /vault offers the unlock again */ });
}

/** components/ProfileAccount.tsx, after the password changed. Never throws. */
export async function vaultPasswordChanged(userId: string | undefined, oldPassword: string, newPassword: string): Promise<void> {
  if (!userId || !secure()) return;
  try {
    const keys = await api<KeysDoc>('/api/e2e/keys');
    const local = await loadDeviceKey(userId);
    const pkcs8 = local?.publicKey === keys.publicKey ? local.pkcs8 : (await unlockWith(passwordUnlocker(oldPassword), keys.wraps, userId)).pkcs8;
    await rewrap(userId, pkcs8, newPassword, keys);
  } catch { /* no keys, or no copy here: the next sign-in on a device that has one re-wraps it */ }
}

/** lib/auth.tsx, at sign-out: this device forgets every account's key. */
export async function vaultForget(): Promise<void> {
  vaultKeys.clear();
  if (typeof indexedDB === 'undefined') return;
  await run('readwrite', (s) => s.clear()).catch(() => {});
}

// ── Vaults ─────────────────────────────────────────────────────────────────────────────────────────────────────

/** A new vault: its key pair is made here; the server gets the public half and the private half sealed to me. */
async function createVault(userId: string, myPublicKey: string): Promise<void> {
  const id = `vault_${[...random(8)].map((x) => x.toString(16).padStart(2, '0')).join('')}`;
  const kp = await generateIdentity();
  const wrappedKey = await sealTo(myPublicKey, kp.pkcs8, ad.vaultKey(id, userId));
  kp.pkcs8.fill(0);
  await api('/api/e2e/vaults', { json: { id, alg: VAULT_ALG, publicKey: b64u(kp.publicSpki), wrapAlg: WRAP_ALG, wrappedKey } });
}

export const vaultDetail = (id: string) => api<{ id: string; items: ItemRow[] }>(`/api/e2e/vaults/${enc(id)}`);
/** Move a series in; the server encrypts it and then removes it from the library. Answers a job id to poll. */
export const moveToVault = (id: string, seriesId: string) => api<{ job: string }>(`/api/e2e/vaults/${enc(id)}/series`, { json: { seriesId } });

/** Poll a job until it ends. Throws with the server's message when it failed. */
export async function waitForJob(job: string): Promise<Job> {
  for (;;) {
    const j = await api<Job>(`/api/e2e/jobs/${enc(job)}`);
    if (j.state === 'done') return j;
    if (j.state === 'failed') throw new Error(j.error || 'failed');
    await new Promise((r) => setTimeout(r, 1000));
  }
}

const vaultKeys = new Map<string, Promise<CryptoKey>>();
/** A vault's private key, opened with this device's key (once per vault per page load). */
function vaultPrivateKey(userId: string, vault: VaultRef): Promise<CryptoKey> {
  const k = `${userId}:${vault.id}:${vault.wrappedKey}`;
  let p = vaultKeys.get(k);
  if (!p) {
    p = (async () => {
      const local = await loadDeviceKey(userId);
      if (!local) throw new Error('locked');
      const mine = await importPrivate(local.pkcs8);
      local.pkcs8.fill(0);
      const pkcs8 = await openFrom(mine, vault.wrappedKey, ad.vaultKey(vault.id, userId));
      const key = await importPrivate(pkcs8);
      pkcs8.fill(0);
      return key;
    })();
    p.catch(() => vaultKeys.delete(k));
    vaultKeys.set(k, p);
  }
  return p;
}

/** Move an item back out: its key is opened here and sent to the server for this one request. */
export async function restoreItem(userId: string, vault: VaultRef, item: ItemRow): Promise<string> {
  const { raw } = await openItemKey(await vaultPrivateKey(userId, vault), vault.id, item.id, item.itemKey, true);
  try {
    return (await api<{ job: string }>(`/api/e2e/vaults/${enc(vault.id)}/items/${enc(item.id)}/restore`, { json: { itemKey: b64u(raw!) } })).job;
  } finally { raw!.fill(0); }
}
