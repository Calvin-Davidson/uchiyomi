// Fork-only: the vault, from the web app's side. Three hooks are called from upstream files (each one fork-marked line):
//   vaultAfterLogin   lib/auth.tsx login()        -- the password the person just typed unlocks (or creates) their key
//   vaultForget       lib/auth.tsx sign-out       -- this device forgets every key
//   vaultPasswordChanged components/ProfileAccount.tsx -- the key is re-wrapped under the new password
// None of them may ever break what they are hooked into: each swallows its own failures.
import { api, ApiError } from '@/lib/api';
import {
  ad, b64u, random, generateIdentity, IDENTITY_ALG, importPrivate, openFrom, openItemKey, passwordUnlocker, sealJson, sealTo,
  unlockWith, VAULT_ALG, WRAP_ALG, type Bytes, type StoredWrap,
} from './crypto';
import { forgetDeviceKeys, hasDeviceKey, loadDeviceKey, saveDeviceKey } from './device';

// ── Wire shapes ────────────────────────────────────────────────────────────────────────────────────────────────
export type Role = 'owner' | 'editor' | 'reader';
export interface VaultRef { id: string; role: Role; ownerId: string; publicKey: string; wrapAlg: string; wrappedKey: string }
export interface VaultStatus { enabled: boolean; hasKeys: boolean; publicKey: string | null; passwordAccount: boolean; vaults: VaultRef[] }
interface KeysDoc { alg: string; publicKey: string; wraps: StoredWrap[] }
export interface Member { userId: string; username: string | null; displayName: string; role: Role; publicKey: string | null }
/** One series in a vault, as the server sends it: everything but the counts is ciphertext. */
export interface ItemRow { id: string; itemKey: string; meta: string; chapters: number; bytes: number; createdAt: string; state: string | null }
export interface VaultDetail { id: string; role: Role; members: Member[]; items: ItemRow[] }
export interface Job { kind: 'in' | 'out'; state: 'running' | 'done' | 'failed'; done: number; total: number; error: string | null }

const enc = encodeURIComponent;

/** The server's refusal code (`{ error }`), for an ApiError. */
export function errorCode(e: unknown): string | null {
  if (!(e instanceof ApiError)) return null;
  try { return (JSON.parse(e.body) as { error?: string }).error ?? null; } catch { return null; }
}

/** The vault status, or null when the server has no vaults at all (E2E_LIBRARIES=0, or an upstream server). */
export async function fetchStatus(): Promise<VaultStatus | null> {
  try { return await api<VaultStatus>('/api/e2e/status'); } catch (e) {
    if (e instanceof ApiError && e.status === 404) return null;
    throw e;
  }
}

const secure = (): boolean => typeof window !== 'undefined' && !!window.isSecureContext && !!globalThis.crypto?.subtle;

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
    if (!(await hasDeviceKey(userId))) return;
    await createVault(userId, status.publicKey);
  })().finally(() => { ensuring = null; });
}

async function unlockKey(userId: string, password: string, verified: boolean): Promise<void> {
  let keys = await api<KeysDoc>('/api/e2e/keys').catch((e) => {
    if (e instanceof ApiError && e.status === 404) return null;
    throw e;
  });
  // A key with no password wrap (the first version's separate vault passphrase) that opens no vault: start over.
  if (keys && !keys.wraps.some((w) => w.kind === 'password') && !(await hasDeviceKey(userId))) {
    const status = await fetchStatus();
    if (status && !status.vaults.length) {
      await api('/api/e2e/keys', { method: 'DELETE' });
      keys = null;
    }
  }
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

/** Replace the password wrap (or add one) with `pkcs8` wrapped under `password`. */
async function rewrap(userId: string, pkcs8: Bytes, password: string, keys: KeysDoc): Promise<void> {
  const wrap = await passwordUnlocker(password).wrap(pkcs8, ad.identity(userId));
  const old = keys.wraps.find((w) => w.kind === 'password');
  if (old) await api(`/api/e2e/keys/wraps/${enc(old.id)}`, { method: 'PUT', json: wrap });
  else await api('/api/e2e/keys/wraps', { json: { kind: 'password', label: 'Account password', ...wrap } });
}

/** lib/auth.tsx, after a password sign-in. Never throws, never delays the sign-in. */
export function vaultAfterLogin(userId: string, password: string): void {
  if (!secure()) return;
  void (async () => {
    const status = await fetchStatus();
    if (!status) return;
    await unlockWithPassword(userId, password, true);
    // The service worker (public/e2e-sw.js) opens the vault again with the key this device now holds.
    try { navigator.serviceWorker?.controller?.postMessage({ e2e: 'reset' }); } catch { /* no worker */ }
  })().catch(() => { /* the vault banner offers the unlock again */ });
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

/** lib/auth.tsx, at sign-out. */
export async function vaultForget(): Promise<void> {
  await forgetDeviceKeys();
  vaultKeys.clear();
}

export const deviceUnlocked = (userId: string) => hasDeviceKey(userId);

/** This device's private key for `userId`, ready to unwrap with. */
async function myPrivateKey(userId: string): Promise<CryptoKey> {
  const local = await loadDeviceKey(userId);
  if (!local) throw new Error('locked');
  const key = await importPrivate(local.pkcs8);
  local.pkcs8.fill(0);
  return key;
}

// ── Vaults ─────────────────────────────────────────────────────────────────────────────────────────────────────

/** A new vault: its key pair is made here; the server gets the public half and the private half sealed to me. */
export async function createVault(userId: string, myPublicKey: string): Promise<string> {
  const id = `vault_${[...random(8)].map((x) => x.toString(16).padStart(2, '0')).join('')}`;
  const kp = await generateIdentity();
  const wrappedKey = await sealTo(myPublicKey, kp.pkcs8, ad.vaultKey(id, userId));
  kp.pkcs8.fill(0);
  await api('/api/e2e/vaults', { json: { id, alg: VAULT_ALG, publicKey: b64u(kp.publicSpki), wrapAlg: WRAP_ALG, wrappedKey } });
  return id;
}

export const vaultDetail = (id: string) => api<VaultDetail>(`/api/e2e/vaults/${enc(id)}`);
export const deleteVault = (id: string) => api(`/api/e2e/vaults/${enc(id)}`, { method: 'DELETE' });
/** Move a series in; the server encrypts it and then removes it from the library. Answers a job id to poll. */
export const moveToVault = (id: string, seriesId: string) => api<{ job: string }>(`/api/e2e/vaults/${enc(id)}/series`, { json: { seriesId } });
export const jobStatus = (job: string) => api<Job>(`/api/e2e/jobs/${enc(job)}`);

/** Poll a job until it ends; `onTick` sees each answer. Throws with the server's message when it failed. */
export async function waitForJob(job: string, onTick?: (j: Job) => void): Promise<Job> {
  for (;;) {
    const j = await jobStatus(job);
    onTick?.(j);
    if (j.state === 'done') return j;
    if (j.state === 'failed') throw new Error(j.error || 'failed');
    await new Promise((r) => setTimeout(r, 1000));
  }
}

const vaultKeys = new Map<string, Promise<CryptoKey>>();
/** A vault's private key, opened with this device's key (once per vault per page load). */
export function vaultPrivateKey(userId: string, vault: VaultRef): Promise<CryptoKey> {
  const k = `${userId}:${vault.id}:${vault.wrappedKey}`;
  let p = vaultKeys.get(k);
  if (!p) {
    p = (async () => {
      const pkcs8 = await openFrom(await myPrivateKey(userId), vault.wrappedKey, ad.vaultKey(vault.id, userId));
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

/** Save this member's reading progress in an item, encrypted under the item key. */
export async function saveState(userId: string, vaultId: string, itemId: string, key: CryptoKey, state: unknown): Promise<void> {
  const sealed = await sealJson(key, state, ad.state(itemId, userId));
  await api(`/api/e2e/vaults/${enc(vaultId)}/items/${enc(itemId)}/state`, { method: 'PUT', json: { sealed } });
}
