// Fork-only: this device's copy of the member private key (the DAK idea): kept in IndexedDB, encrypted under a device
// key that is a NON-EXTRACTABLE AES key -- the browser can use it but no script can read it out, and it never leaves
// this device. The service worker (public/e2e-sw.js) reads the same store to open pages, so the database name, store
// and record shape here are a contract with it.
//
// Written at sign-in (the password unlocks the key once), removed at sign-out. Holding the private key itself (wrapped)
// rather than only a non-extractable copy is what lets a password change, or a password reset done elsewhere, re-wrap
// it on this device without the old password.
import { random, type Bytes } from './crypto';

export const DB_NAME = 'uchiyomi-e2e';
const STORE = 'device';

export interface DeviceRecord { userId: string; dak: CryptoKey; iv: Bytes; ct: Bytes; publicKey: string; at: number }

function open(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const r = indexedDB.open(DB_NAME, 1);
    r.onupgradeneeded = () => { if (!r.result.objectStoreNames.contains(STORE)) r.result.createObjectStore(STORE, { keyPath: 'userId' }); };
    r.onsuccess = () => resolve(r.result);
    r.onerror = () => reject(r.error);
  });
}

async function run<T>(mode: IDBTransactionMode, fn: (s: IDBObjectStore) => IDBRequest): Promise<T> {
  const db = await open();
  try {
    return await new Promise<T>((resolve, reject) => {
      const req = fn(db.transaction(STORE, mode).objectStore(STORE));
      req.onsuccess = () => resolve(req.result as T);
      req.onerror = () => reject(req.error);
    });
  } finally { db.close(); }
}

/** Keep `pkcs8` on this device for `userId`, under a fresh non-extractable device key. */
export async function saveDeviceKey(userId: string, pkcs8: Bytes, publicKey: string): Promise<void> {
  const dak = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  const iv = random(12);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, dak, pkcs8));
  await run('readwrite', (s) => s.put({ userId, dak, iv, ct, publicKey, at: Date.now() } satisfies DeviceRecord));
}

/** This device's copy of the private key for `userId`, or null. */
export async function loadDeviceKey(userId: string): Promise<{ pkcs8: Bytes; publicKey: string } | null> {
  const rec = await run<DeviceRecord | undefined>('readonly', (s) => s.get(userId)).catch(() => undefined);
  if (!rec) return null;
  try {
    const pkcs8 = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: rec.iv }, rec.dak, rec.ct));
    return { pkcs8, publicKey: rec.publicKey };
  } catch { return null; }
}

export const hasDeviceKey = async (userId: string): Promise<boolean> =>
  !!(await run<DeviceRecord | undefined>('readonly', (s) => s.get(userId)).catch(() => undefined));

/** Forget every account's key on this device (sign-out). */
export async function forgetDeviceKeys(): Promise<void> {
  if (typeof indexedDB === 'undefined') return;
  await run('readwrite', (s) => s.clear()).catch(() => {});
}
