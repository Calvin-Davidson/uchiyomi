// Fork-only: which libraries are vaults, and who is in each -- held in memory, so the visibility rule
// (lib/visibility.ts visible(), one fork-marked line) can apply it synchronously on every query it builds.
//
// The rule: a vault is seen by its members only. Not by other members of the household, and not by an admin either
// (an admin holds no key, so the pages would be noise to them anyway). Background work (SYSTEM_CTX, userId null) sees
// everything, as it does for every other library: the scanner, the updater and the downloader must keep a vault's
// series up to date exactly like any other series.
//
// This module imports nothing but the database, because lib/visibility.ts imports it.
import { q } from '../../lib/db';

export interface VaultInfo { libraryId: string; ownerId: string; publicKey: string; members: Map<string, 'owner' | 'editor' | 'reader'> }

let vaults = new Map<string, VaultInfo>();
let loaded = false;

/** (Re)read every vault and its members. Called at boot and after anything that changes them. */
export async function loadVaults(): Promise<void> {
  const rows = await q<{ library_id: string; owner_id: string; public_key: string; user_id: string | null; role: 'owner' | 'editor' | 'reader' | null }>(
    `SELECT v.library_id, v.owner_id, v.public_key, m.user_id, m.role
       FROM e2e_vaults v LEFT JOIN e2e_vault_members m ON m.library_id = v.library_id`);
  const next = new Map<string, VaultInfo>();
  for (const r of rows) {
    let v = next.get(r.library_id);
    if (!v) next.set(r.library_id, v = { libraryId: r.library_id, ownerId: r.owner_id, publicKey: r.public_key, members: new Map() });
    if (r.user_id && r.role) v.members.set(r.user_id, r.role);
  }
  vaults = next;
  loaded = true;
}

export const vaultsLoaded = (): boolean => loaded;
export const anyVaults = (): boolean => vaults.size > 0;
export const vaultOf = (libraryId: string | null | undefined): VaultInfo | null => (libraryId ? vaults.get(libraryId) ?? null : null);
export const allVaults = (): VaultInfo[] => [...vaults.values()];

/** Vault libraries this viewer may NOT see. Empty for background work, and while there are no vaults. */
export function vaultsHiddenFrom(userId: string | null | undefined): string[] {
  if (!userId || !vaults.size) return [];
  return [...vaults.values()].filter((v) => !v.members.has(userId)).map((v) => v.libraryId);
}

/** Vault libraries this viewer is a member of. */
export function vaultsOf(userId: string | null | undefined): string[] {
  if (!userId || !vaults.size) return [];
  return [...vaults.values()].filter((v) => v.members.has(userId)).map((v) => v.libraryId);
}

/**
 * A viewer's library grants with their vaults added. An account restricted to some libraries (user_libraries rows)
 * still sees the vaults it is a member of; an unrestricted one (null) stays unrestricted.
 */
export function withVaults(libraryIds: readonly string[] | null, userId: string | null): readonly string[] | null {
  if (!libraryIds) return libraryIds;
  const mine = vaultsOf(userId).filter((id) => !libraryIds.includes(id));
  return mine.length ? [...libraryIds, ...mine] : libraryIds;
}

/**
 * The SQL clause visible() adds: the series is not in a vault this viewer is outside of. `add` is visible()'s
 * placeholder maker. Null when there is nothing to hide, so most queries are exactly what upstream builds.
 */
export function vaultClause(alias: string, userId: string | null, add: (v: unknown) => string): string | null {
  const hidden = vaultsHiddenFrom(userId);
  return hidden.length ? `${alias}.library_id <> ALL(${add(hidden)}::text[])` : null;
}
