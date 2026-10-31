'use client';
// Fork-only: the Library page (app/library/page.tsx) run as the Vault. /vault renders that same page (VaultRoute.tsx),
// and its fork-marked lines ask this hook what to call itself, where its URL lives, and which library it shows.
// Everywhere else the answer is the Library's own, so the page is unchanged there.
import { usePathname } from 'next/navigation';
import { useVaultStatus } from './hooks';

export interface Shelf {
  /** The page's address, for the filters it keeps in the URL. */
  base: string;
  /** The heading, or null for the Library's own (translated) one. */
  title: string | null;
  /** The library it is fixed to, or null to read `?lib=`. */
  lib: string | null;
}

export function useShelf(): Shelf {
  const path = usePathname() || '';
  const { data } = useVaultStatus();
  if (!path.startsWith('/vault')) return { base: '/library', title: null, lib: null };
  return { base: '/vault/', title: 'Vault', lib: data?.vaults[0]?.id ?? 'vault' };
}
