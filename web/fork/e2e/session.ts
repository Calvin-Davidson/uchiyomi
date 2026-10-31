// Fork-only: the vault, from the web app's side. Three hooks are called from upstream files (each one fork-marked line):
//   vaultAfterLogin   lib/auth.tsx login()        -- the password the person just typed unlocks (or creates) their key
//   vaultForget       lib/auth.tsx sign-out       -- this device forgets every key
//   vaultPasswordChanged components/ProfileAccount.tsx -- the key is re-wrapped under the new password
// None of them may ever break what they are hooked into: each swallows its own failures.
import { api, ApiError } from '@/lib/api';
import {
  ad, b64u, fingerprint, random, generateIdentity, IDENTITY_ALG, importPrivate, openFrom, passwordUnlocker, sealTo, unlockWith,
  VAULT_ALG, WRAP_ALG, type Bytes, type StoredWrap,
} from './crypto';
import { forgetDeviceKeys, hasDeviceKey, loadDeviceKey, saveDeviceKey } from './device';

// ── Wire shapes ────────────────────────────────────────────────────────────────────────────────────────────────
export type Role = 'owner' | 'editor' | 'reader';
export interface VaultRef { id: string; name: string; role: Role; ownerId: string; publicKey: string; wrapAlg: string; wrappedKey: string }
export interface VaultStatus { enabled: boolean; hasKeys: boolean; publicKey: string | null; passwordAccount: boolean; vaults: VaultRef[] }
interface KeysDoc { alg: string; publicKey: string; wraps: StoredWrap[] }
export interface Member { userId: string; username: string | null; displayName: string; role: Role; publicKey: string | null }
export interface VaultDetail {
  id: string; name: string; role: Role; series: number; members: Member[];
  seal: { total: number; sealed: number; failed: number; problems: Array<{ title: string; file: string; error: string }> };
}

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

/** Tell the service worker to drop the keys it has opened, after this device's keys changed. */
function tellWorker(): void {
  try { navigator.serviceWorker?.controller?.postMessage({ e2e: 'reset' }); } catch { /* no worker */ }
}

const secure = (): boolean => typeof window !== 'undefined' && !!window.isSecureContext && !!globalThis.crypto?.subtle;

// ── Keys ───────────────────────────────────────────────────────────────────────────────────────────────────────

/**
 * Unlock (or make) this account's key with its password, and keep it on this device. `verified` says the password is
 * known good (it just signed in); otherwise a first key is only made after the server confirms the password.
 * Throws Error('wrong_password') when the password does not open the key and this device holds no copy to re-wrap.
 */
export async function unlockWithPassword(userId: string, password: string, verified: boolean): Promise<void> {
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
    tellWorker();
    return;
  }
  try {
    const { pkcs8 } = await unlockWith(passwordUnlocker(password), keys.wraps, userId);
    await saveDeviceKey(userId, pkcs8, keys.publicKey);
    tellWorker();
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
  tellWorker();
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

export async function myFingerprint(status: VaultStatus): Promise<string> {
  return status.publicKey ? fingerprint(status.publicKey) : '';
}

// ── Vaults ─────────────────────────────────────────────────────────────────────────────────────────────────────

/** A new vault: its key pair is made here; the server gets the public half and the private half sealed to me. */
export async function createVault(userId: string, myPublicKey: string, name: string): Promise<string> {
  const id = `vault_${[...random(8)].map((x) => x.toString(16).padStart(2, '0')).join('')}`;
  const kp = await generateIdentity();
  const wrappedKey = await sealTo(myPublicKey, kp.pkcs8, ad.vaultKey(id, userId));
  kp.pkcs8.fill(0);
  await api('/api/e2e/vaults', { json: { id, name, alg: VAULT_ALG, publicKey: b64u(kp.publicSpki), wrapAlg: WRAP_ALG, wrappedKey } });
  return id;
}

export const vaultDetail = (id: string) => api<VaultDetail>(`/api/e2e/vaults/${enc(id)}`);
export const renameVault = (id: string, name: string) => api(`/api/e2e/vaults/${enc(id)}`, { method: 'PATCH', json: { name } });
export const deleteVault = (id: string) => api(`/api/e2e/vaults/${enc(id)}`, { method: 'DELETE' });
export const sealNow = (id: string) => api<{ sealed: number; failed: number }>(`/api/e2e/vaults/${enc(id)}/seal`, { method: 'POST', json: {} });
export const moveToVault = (id: string, seriesIds: string[]) =>
  api<{ applied: number; skipped: Array<{ id: string; reason: string }> }>(`/api/e2e/vaults/${enc(id)}/series`, { json: { seriesIds } });

/** Someone's public key and its fingerprint, to show before sharing with them. */
export async function lookupUser(username: string) {
  const u = await api<{ userId: string; username: string; displayName: string; publicKey: string }>(`/api/e2e/users/${enc(username.trim())}/key`);
  return { ...u, fingerprint: await fingerprint(u.publicKey) };
}

/** Share a vault: its private key, opened here with mine and sealed to their public key. */
export async function shareVault(userId: string, vault: VaultRef, user: { userId: string; publicKey: string }, role: Exclude<Role, 'owner'>): Promise<void> {
  const mine = await myPrivateKey(userId);
  const pkcs8 = await openFrom(mine, vault.wrappedKey, ad.vaultKey(vault.id, userId));
  const wrappedKey = await sealTo(user.publicKey, pkcs8, ad.vaultKey(vault.id, user.userId));
  pkcs8.fill(0);
  await api(`/api/e2e/vaults/${enc(vault.id)}/members/${enc(user.userId)}`, { method: 'PUT', json: { role, wrapAlg: WRAP_ALG, wrappedKey } });
}

export const removeMember = (vaultId: string, userId: string) => api(`/api/e2e/vaults/${enc(vaultId)}/members/${enc(userId)}`, { method: 'DELETE' });
export const resetKeys = async () => { await api('/api/e2e/keys', { method: 'DELETE' }); await vaultForget(); };
