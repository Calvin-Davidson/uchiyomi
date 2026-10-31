// Fork-only: a vault's items, opened in the browser. The server sends ciphertext only (bff/src/fork/e2e/routes.ts): each
// item's key sealed to the vault, its manifest and this member's progress encrypted under that key, and its cover and
// pages as `iv | ciphertext` records. Everything here is decrypted with the vault's private key from this device.
import { apiResponse } from '@/lib/api';
import { ad, openItemKey, openJson, openRecord, type Bytes } from './crypto';
import { saveState, vaultDetail, vaultPrivateKey, type ItemRow, type VaultDetail, type VaultRef } from './session';

/** bff/src/fork/e2e/move.ts Manifest. */
export interface Manifest {
  v: 3;
  title: string;
  folder: string;
  source: string;
  summary: string | null;
  author: string | null;
  status: string | null;
  genres: string[];
  web: string | null;
  movedAt: string;
  chapters: Array<{ number: number; title: string | null; publishedAt: string | null; pages: Array<{ t: string; w: number | null; h: number | null }> }>;
}
export interface ChapterState { page: number; completed: boolean; at: string }
export interface ItemState { chapters: Record<string, ChapterState> }

export interface OpenItem { row: ItemRow; key: CryptoKey; manifest: Manifest; state: ItemState }
export interface OpenVault { detail: VaultDetail; items: OpenItem[]; failed: number }

const enc = encodeURIComponent;

/** Every item of a vault, opened. An item that does not open (a damaged row) is counted, not thrown. */
export async function openVault(userId: string, vault: VaultRef): Promise<OpenVault> {
  const [detail, priv] = await Promise.all([vaultDetail(vault.id), vaultPrivateKey(userId, vault)]);
  let failed = 0;
  const items = (await Promise.all(detail.items.map(async (row): Promise<OpenItem | null> => {
    try {
      const { key } = await openItemKey(priv, vault.id, row.id, row.itemKey);
      const manifest = await openJson<Manifest>(key, row.meta, ad.meta(row.id));
      const state = row.state ? await openJson<ItemState>(key, row.state, ad.state(row.id, userId)).catch(() => ({ chapters: {} })) : { chapters: {} };
      return { row, key, manifest, state };
    } catch { failed++; return null; }
  }))).filter((x): x is OpenItem => !!x);
  items.sort((a, b) => a.manifest.title.localeCompare(b.manifest.title));
  return { detail, items, failed };
}

async function fetchRecord(path: string): Promise<Bytes> {
  return new Uint8Array(await (await apiResponse(path)).arrayBuffer());
}

/** An object URL for the item's cover, or null when it has none. The caller revokes it. */
export async function coverUrl(vaultId: string, item: OpenItem): Promise<string | null> {
  const rec = await fetchRecord(`/api/e2e/vaults/${enc(vaultId)}/items/${enc(item.row.id)}/cover`).catch(() => null);
  if (!rec) return null;
  return URL.createObjectURL(new Blob([await openRecord(item.key, rec, ad.cover(item.row.id))], { type: 'image/webp' }));
}

/** An object URL for one page (both 0-based). The caller revokes it. */
export async function pageUrl(vaultId: string, item: OpenItem, chapter: number, page: number): Promise<string> {
  const rec = await fetchRecord(`/api/e2e/vaults/${enc(vaultId)}/items/${enc(item.row.id)}/chapters/${chapter}/pages/${page}`);
  const bytes = await openRecord(item.key, rec, ad.page(item.row.id, chapter, page));
  return URL.createObjectURL(new Blob([bytes], { type: item.manifest.chapters[chapter]?.pages[page]?.t || 'image/jpeg' }));
}

/** Record where this member is in a chapter. Mutates `item.state`, then saves it encrypted. */
export async function notePosition(userId: string, vaultId: string, item: OpenItem, chapter: number, page: number): Promise<void> {
  const total = item.manifest.chapters[chapter]?.pages.length ?? 0;
  const prev = item.state.chapters[chapter];
  const completed = !!prev?.completed || (total > 0 && page >= total - 1);
  item.state.chapters[chapter] = { page, completed, at: new Date().toISOString() };
  await saveState(userId, vaultId, item.row.id, item.key, item.state);
}

/** The chapter to continue with: the last one touched if unfinished, else the first unread one after it. */
export function continueAt(item: OpenItem): { chapter: number; page: number } {
  const entries = Object.entries(item.state.chapters).map(([k, v]) => ({ ch: Number(k), ...v }));
  if (!entries.length) return { chapter: 0, page: 0 };
  const last = entries.sort((a, b) => b.at.localeCompare(a.at))[0];
  if (!last.completed) return { chapter: last.ch, page: last.page };
  const next = Math.min(last.ch + 1, item.manifest.chapters.length - 1);
  return { chapter: next, page: next === last.ch ? last.page : 0 };
}
