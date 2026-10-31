// Fork-only: what the vault page does, on top of crypto.ts and the /api/e2e routes (bff/src/fork/e2e/routes.ts).
//
// The unlocked private key lives in this module only, in memory: a reload, a sign-out or `lock()` forgets it, and the
// passphrase is asked again. Library keys unwrapped with it are cached beside it under the same rule.
import { api, ApiError, getAccessToken, refreshSession } from '@/lib/api';
import {
  ad, b64u, chunkCount, CHUNK_PLAIN, fingerprint, generateIdentity, IDENTITY_ALG, importPrivate, newId, newSymKey,
  openChunk, openFrom, openJson, openString, passphraseUnlocker, sealChunk, sealJson, sealString, sealTo, symKeyOf,
  unlockWith, WRAP_ALG, type Bytes, type StoredWrap, type SymKey,
} from './crypto';

// ── Wire shapes ────────────────────────────────────────────────────────────────────────────────────────────────
export interface KeysDoc { alg: string; publicKey: string; createdAt: string; wraps: StoredWrap[] }
export type Role = 'owner' | 'editor' | 'reader';
interface LibraryRow { id: string; ownerId: string; keyVersion: number; meta: string; role: Role; memberKeyVersion: number; wrapAlg: string; wrappedKey: string; items: number; createdAt: string }
interface ItemRow { id: string; libraryId: string; keyVersion: number; wrappedKey: string; meta: string; chunks: number; size: number; state: 'pending' | 'ready'; createdAt: string }
export interface MemberRow { userId: string; username: string | null; displayName: string; role: Role; keyVersion: number; alg: string | null; publicKey: string | null }
export interface UserKey { userId: string; username: string; displayName: string; alg: string; publicKey: string }

export interface LibraryMeta { name: string; description?: string }
export interface ItemMeta { name: string; type: string; size: number; lastModified?: number }

export interface OpenLibrary { id: string; ownerId: string; role: Role; keyVersion: number; items: number; createdAt: string; meta: LibraryMeta }
export interface OpenItem { id: string; libraryId: string; state: 'pending' | 'ready'; chunks: number; createdAt: string; meta: ItemMeta | null; row: ItemRow }

// ── Session ────────────────────────────────────────────────────────────────────────────────────────────────────
interface Session { userId: string; priv: CryptoKey; publicKey: string }
let session: Session | null = null;
const libKeys = new Map<string, { version: number; key: SymKey }>();

export const unlockedFor = (userId: string | undefined | null): boolean => !!session && session.userId === userId;
export function lock(): void { session = null; libKeys.clear(); }
function me(): Session {
  if (!session) throw new Error('locked');
  return session;
}

// ── HTTP ───────────────────────────────────────────────────────────────────────────────────────────────────────
const enc = encodeURIComponent;

/** A signed-in request with a binary body or answer, refreshed once on a bare 401 like lib/api.ts does. */
async function binary(path: string, init: { method: string; body?: Bytes }, retry = true): Promise<Response> {
  const headers = new Headers();
  const t = getAccessToken();
  if (t) headers.set('authorization', `Bearer ${t}`);
  if (init.body) headers.set('content-type', 'application/octet-stream');
  const res = await fetch(path, { method: init.method, headers, body: init.body, credentials: 'include' });
  if (res.status === 401 && retry && (await refreshSession()).kind === 'authed') return binary(path, init, false);
  if (!res.ok) throw new ApiError(res.status, await res.text().catch(() => ''));
  return res;
}

/** The server's refusal code (`{ error }`), for an ApiError. */
export function errorCode(e: unknown): string | null {
  if (!(e instanceof ApiError)) return null;
  try { return (JSON.parse(e.body) as { error?: string }).error ?? null; } catch { return null; }
}

// ── Keys ───────────────────────────────────────────────────────────────────────────────────────────────────────
/** The caller's stored keys, or null before they set up a vault. */
export async function fetchKeys(): Promise<KeysDoc | null> {
  try { return await api<KeysDoc>('/api/e2e/keys'); } catch (e) {
    if (e instanceof ApiError && e.status === 404) return null;
    throw e;
  }
}

/** Make a key pair, wrap its private half under the passphrase, store both. Leaves the vault unlocked. */
export async function setupVault(userId: string, passphrase: string): Promise<void> {
  const id = await generateIdentity();
  const wrap = await passphraseUnlocker(passphrase).wrap(id.pkcs8, ad.identity(userId));
  const publicKey = b64u(id.publicSpki);
  await api('/api/e2e/keys', { method: 'PUT', json: { alg: IDENTITY_ALG, publicKey, wrap: { kind: 'passphrase', label: 'Vault passphrase', ...wrap } } });
  session = { userId, priv: await importPrivate(id.pkcs8), publicKey };
  libKeys.clear();
}

/** Unlock with the passphrase. Throws Error('wrong_passphrase') when no wrap opens. */
export async function unlockVault(userId: string, passphrase: string, keys?: KeysDoc | null): Promise<void> {
  const doc = keys ?? (await fetchKeys());
  if (!doc) throw new Error('no_keys');
  const { pkcs8 } = await unlockWith(passphraseUnlocker(passphrase), doc.wraps, userId);
  session = { userId, priv: await importPrivate(pkcs8), publicKey: doc.publicKey };
  pkcs8.fill(0);
  libKeys.clear();
}

/** Re-wrap the private key under a new passphrase, replacing the wrap the old one opened. */
export async function changePassphrase(userId: string, oldPassphrase: string, newPassphrase: string): Promise<void> {
  const doc = await fetchKeys();
  if (!doc) throw new Error('no_keys');
  const { pkcs8, wrapId } = await unlockWith(passphraseUnlocker(oldPassphrase), doc.wraps, userId);
  const wrap = await passphraseUnlocker(newPassphrase).wrap(pkcs8, ad.identity(userId));
  pkcs8.fill(0);
  await api(`/api/e2e/keys/wraps/${enc(wrapId)}`, { method: 'PUT', json: wrap });
}

/** Forget the key pair: every library this account owns is deleted, and it leaves every other one. */
export async function resetVault(): Promise<void> {
  await api('/api/e2e/keys', { method: 'DELETE' });
  lock();
}

export const myFingerprint = () => fingerprint(me().publicKey);

// ── Libraries ──────────────────────────────────────────────────────────────────────────────────────────────────
async function libraryKey(row: Pick<LibraryRow, 'id' | 'memberKeyVersion' | 'wrappedKey' | 'wrapAlg'>): Promise<SymKey> {
  const s = me();
  const cached = libKeys.get(row.id);
  if (cached && cached.version === row.memberKeyVersion) return cached.key;
  if (row.wrapAlg !== WRAP_ALG) throw new Error(`Unsupported key wrap ${row.wrapAlg}`);
  const raw = await openFrom(s.priv, row.wrappedKey, ad.libraryKey(row.id, row.memberKeyVersion, s.userId));
  const key = await symKeyOf(raw);
  libKeys.set(row.id, { version: row.memberKeyVersion, key });
  return key;
}

async function openLibrary(row: LibraryRow): Promise<OpenLibrary> {
  const key = await libraryKey(row);
  const meta = await openJson<LibraryMeta>(key.key, row.meta, ad.libraryMeta(row.id, row.keyVersion));
  return { id: row.id, ownerId: row.ownerId, role: row.role, keyVersion: row.keyVersion, items: row.items, createdAt: row.createdAt, meta };
}

/** Every library this account is in, decrypted. One that cannot be opened is reported, not hidden. */
export async function listLibraries(): Promise<Array<OpenLibrary | { id: string; error: string }>> {
  const rows = await api<LibraryRow[]>('/api/e2e/libraries');
  return Promise.all(rows.map((r) => openLibrary(r).catch((e) => ({ id: r.id, error: (e as Error).message || 'cannot open' }))));
}

export async function getLibrary(id: string): Promise<OpenLibrary> {
  return openLibrary(await api<LibraryRow>(`/api/e2e/libraries/${enc(id)}`));
}

export async function createLibrary(meta: LibraryMeta): Promise<OpenLibrary> {
  const s = me();
  const id = newId();
  const key = await newSymKey();
  const wrappedKey = await sealTo(s.publicKey, key.raw, ad.libraryKey(id, 1, s.userId));
  const sealedMeta = await sealJson(key.key, meta, ad.libraryMeta(id, 1));
  const row = await api<LibraryRow>('/api/e2e/libraries', { json: { id, meta: sealedMeta, wrapAlg: WRAP_ALG, wrappedKey } });
  libKeys.set(id, { version: 1, key });
  return openLibrary(row);
}

export async function renameLibrary(lib: OpenLibrary, meta: LibraryMeta): Promise<void> {
  const key = await libraryKey(await api<LibraryRow>(`/api/e2e/libraries/${enc(lib.id)}`));
  await api(`/api/e2e/libraries/${enc(lib.id)}`, { method: 'PATCH', json: { meta: await sealJson(key.key, meta, ad.libraryMeta(lib.id, lib.keyVersion)) } });
}

export async function deleteLibrary(id: string): Promise<void> {
  await api(`/api/e2e/libraries/${enc(id)}`, { method: 'DELETE' });
  libKeys.delete(id);
}

// ── Members ────────────────────────────────────────────────────────────────────────────────────────────────────
export const listMembers = (libId: string) => api<MemberRow[]>(`/api/e2e/libraries/${enc(libId)}/members`);

/** Someone's public key and its fingerprint, to show before sharing with them. */
export async function lookupUser(username: string): Promise<UserKey & { fingerprint: string }> {
  const u = await api<UserKey>(`/api/e2e/users/${enc(username.trim())}/key`);
  return { ...u, fingerprint: await fingerprint(u.publicKey) };
}

/** Share (or change a role): the library key, wrapped to the member's public key. */
export async function shareWith(libId: string, user: { userId: string; publicKey: string }, role: Exclude<Role, 'owner'>): Promise<void> {
  const row = await api<LibraryRow>(`/api/e2e/libraries/${enc(libId)}`);
  const key = await libraryKey(row);
  const wrappedKey = await sealTo(user.publicKey, key.raw, ad.libraryKey(libId, row.keyVersion, user.userId));
  await api(`/api/e2e/libraries/${enc(libId)}/members/${enc(user.userId)}`, { method: 'PUT', json: { role, keyVersion: row.keyVersion, wrapAlg: WRAP_ALG, wrappedKey } });
}

/**
 * A new library key for everyone still in the library, every item key re-wrapped under it. Run after removing a
 * member, so a library key they may have kept opens nothing the library holds from then on.
 */
export async function rotateLibraryKey(libId: string): Promise<void> {
  const row = await api<LibraryRow>(`/api/e2e/libraries/${enc(libId)}`);
  const old = await libraryKey(row);
  const [members, items] = await Promise.all([listMembers(libId), api<ItemRow[]>(`/api/e2e/libraries/${enc(libId)}/items`)]);
  const meta = await openJson<LibraryMeta>(old.key, row.meta, ad.libraryMeta(libId, row.keyVersion));
  const next = row.keyVersion + 1;
  const fresh = await newSymKey();
  const body = {
    fromVersion: row.keyVersion,
    meta: await sealJson(fresh.key, meta, ad.libraryMeta(libId, next)),
    members: await Promise.all(members.map(async (m) => {
      if (!m.publicKey) throw new Error(`${m.displayName} has no vault key`);
      return { userId: m.userId, wrapAlg: WRAP_ALG, wrappedKey: await sealTo(m.publicKey, fresh.raw, ad.libraryKey(libId, next, m.userId)) };
    })),
    items: await Promise.all(items.map(async (i) => {
      const raw = await openString(old.key, i.wrappedKey, ad.itemKey(libId, i.id, i.keyVersion));
      return { id: i.id, wrappedKey: await sealString(fresh.key, raw, ad.itemKey(libId, i.id, next)) };
    })),
  };
  await api(`/api/e2e/libraries/${enc(libId)}/rotate`, { json: body });
  libKeys.set(libId, { version: next, key: fresh });
}

/** Remove a member and rotate the key. Leaving is the same call with your own id, without the rotation. */
export async function removeMember(libId: string, userId: string, rotate = true): Promise<void> {
  await api(`/api/e2e/libraries/${enc(libId)}/members/${enc(userId)}`, { method: 'DELETE' });
  if (rotate) await rotateLibraryKey(libId);
  else libKeys.delete(libId);
}

// ── Items ──────────────────────────────────────────────────────────────────────────────────────────────────────
async function itemKey(lib: OpenLibrary, row: ItemRow): Promise<SymKey> {
  // A rotation (here or by the owner elsewhere) moves every item to the new key version at once: fetch its wrap.
  const cached = libKeys.get(lib.id);
  const lk = cached && cached.version === row.keyVersion
    ? cached.key
    : await libraryKey(await api<LibraryRow>(`/api/e2e/libraries/${enc(lib.id)}`));
  return symKeyOf(await openString(lk.key, row.wrappedKey, ad.itemKey(lib.id, row.id, row.keyVersion)));
}

export async function listItems(lib: OpenLibrary): Promise<OpenItem[]> {
  const rows = await api<ItemRow[]>(`/api/e2e/libraries/${enc(lib.id)}/items`);
  return Promise.all(rows.map(async (r) => {
    let meta: ItemMeta | null = null;
    try { meta = await openJson<ItemMeta>((await itemKey(lib, r)).key, r.meta, ad.itemMeta(r.id)); } catch { /* shown as unreadable */ }
    return { id: r.id, libraryId: r.libraryId, state: r.state, chunks: r.chunks, createdAt: r.createdAt, meta, row: r };
  }));
}

/** Encrypt a file in the browser and upload it chunk by chunk. `onProgress` gets 0..1. */
export async function uploadFile(lib: OpenLibrary, file: File, onProgress?: (f: number) => void): Promise<void> {
  const row = await api<LibraryRow>(`/api/e2e/libraries/${enc(lib.id)}`);
  const lk = await libraryKey(row);
  const id = newId();
  const ik = await newSymKey();
  const meta: ItemMeta = { name: file.name, type: file.type || guessType(file.name), size: file.size, lastModified: file.lastModified };
  await api(`/api/e2e/libraries/${enc(lib.id)}/items`, { json: {
    id, keyVersion: row.keyVersion,
    wrappedKey: await sealString(lk.key, ik.raw, ad.itemKey(lib.id, id, row.keyVersion)),
    meta: await sealJson(ik.key, meta, ad.itemMeta(id)),
  } });
  const count = chunkCount(file.size);
  for (let n = 0; n < count; n++) {
    const plain = new Uint8Array(await file.slice(n * CHUNK_PLAIN, (n + 1) * CHUNK_PLAIN).arrayBuffer());
    const sealed = await sealChunk(ik.key, plain, ad.chunk(id, n, n === count - 1));
    await binary(`/api/e2e/items/${enc(id)}/chunks/${n}`, { method: 'PUT', body: sealed });
    onProgress?.((n + 1) / count);
  }
  await api(`/api/e2e/items/${enc(id)}/commit`, { json: { chunks: count } });
}

/** Download and decrypt an item. A chunk out of place, missing or altered fails the whole file. */
export async function downloadItem(lib: OpenLibrary, item: OpenItem, onProgress?: (f: number) => void): Promise<Blob> {
  const ik = await itemKey(lib, item.row);
  const parts: Bytes[] = [];
  for (let n = 0; n < item.chunks; n++) {
    const sealed = new Uint8Array(await (await binary(`/api/e2e/items/${enc(item.id)}/chunks/${n}`, { method: 'GET' })).arrayBuffer());
    parts.push(await openChunk(ik.key, sealed, ad.chunk(item.id, n, n === item.chunks - 1)));
    onProgress?.((n + 1) / item.chunks);
  }
  return new Blob(parts, { type: item.meta?.type || 'application/octet-stream' });
}

export async function renameItem(lib: OpenLibrary, item: OpenItem, name: string): Promise<void> {
  if (!item.meta) throw new Error('unreadable');
  const ik = await itemKey(lib, item.row);
  await api(`/api/e2e/items/${enc(item.id)}`, { method: 'PATCH', json: { meta: await sealJson(ik.key, { ...item.meta, name }, ad.itemMeta(item.id)) } });
}

export const deleteItem = (id: string) => api(`/api/e2e/items/${enc(id)}`, { method: 'DELETE' });

export function guessType(name: string): string {
  const ext = name.toLowerCase().split('.').pop() || '';
  return ({
    cbz: 'application/vnd.comicbook+zip', zip: 'application/zip', pdf: 'application/pdf', epub: 'application/epub+zip',
    jpg: 'image/jpeg', jpeg: 'image/jpeg', png: 'image/png', webp: 'image/webp', gif: 'image/gif', avif: 'image/avif',
  } as Record<string, string>)[ext] || 'application/octet-stream';
}
