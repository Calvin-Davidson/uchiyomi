'use client';
// The vault's small pieces of UI (docs/VAULTS.md), for the components that show it:
//   useVaultNav()   components/Sidebar.tsx      -- "Vault" under Library
//   useVaultMenu()  components/SeriesMenu.tsx   -- "Move to vault" / "Move out of vault" on a series card
//   useShelf()      app/library/page.tsx, components/LibraryFilters.tsx -- the Library page run as the Vault at /vault
// Each answers nothing when the server has no vaults (VAULTS unset).
import { useEffect, useState } from 'react';
import { usePathname } from 'next/navigation';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { useAuth } from './auth';
import { IcLock } from '@/components/icons';
import { useToast } from '@/components/Toast';
import { t as tr } from './i18n';
import type { Series } from './types';
import { deviceUnlocked, fetchStatus, moveToVault, resetWorker, restoreItem, vaultDetail, waitForJob, type VaultStatus } from './vault';

export const STATUS_KEY = ['e2e-status'] as const;

/** The vault status for the signed-in account; null when the server has no vaults. */
export function useVaultStatus() {
  const { user, status } = useAuth();
  return useQuery<VaultStatus | null>({
    queryKey: [...STATUS_KEY, user?.id ?? ''],
    queryFn: fetchStatus,
    enabled: status === 'authed' && !!user?.id,
    staleTime: 60_000,
    retry: false,
  });
}

/** Whether this device holds the account's key (re-checked when the status changes). */
export function useDeviceUnlocked(): boolean | null {
  const { user } = useAuth();
  const { data } = useVaultStatus();
  const [on, setOn] = useState<boolean | null>(null);
  useEffect(() => {
    if (!user?.id || !data?.hasKeys) { setOn(null); return; }
    let live = true;
    deviceUnlocked(user.id).then((v) => live && setOn(v)).catch(() => live && setOn(false));
    return () => { live = false; };
  }, [user?.id, data]);
  return on;
}

export interface Shelf {
  /** The page's address, for the filters it keeps in the URL. */
  base: string;
  /** The heading, or null for the Library's own (translated) one. */
  title: string | null;
  /** The library it is fixed to, or null to read `?lib=`. Vault series have no sources, so no source filters either. */
  lib: string | null;
}

/** What the Library page is at this address: itself, or the Vault (app/vault/page.tsx). */
export function useShelf(): Shelf {
  const path = usePathname() || '';
  const { data } = useVaultStatus();
  if (!path.startsWith('/vault')) return { base: '/library', title: null, lib: null };
  return { base: '/vault/', title: tr('Vault'), lib: data?.vaults[0]?.id ?? 'vault' };
}

/** The Sidebar's item: the Vault, which is the Library filtered to it (or the unlock, until this device has the key). */
export function useVaultNav(): { href: string; label: string; Icon: typeof IcLock; match: (p: string) => boolean } | null {
  const { data } = useVaultStatus();
  if (!data?.enabled || (!data.vaults.length && !data.passwordAccount)) return null;
  // Sidebar says its items' labels through tr().
  return { href: '/vault/', label: 'Vault', Icon: IcLock, match: (p) => p.startsWith('/vault') };
}

/** On a series card: "Move to vault", or "Move out of vault" for a series that is in one. */
export function useVaultMenu(series: Series, settle: () => void): Array<{ label: string; onSelect: () => Promise<void> }> {
  const { user } = useAuth();
  const { data } = useVaultStatus();
  const qc = useQueryClient();
  const toast = useToast();
  const name = series.metadata?.title || series.name;
  const why = (e: unknown) => ((e as Error)?.message ? `: ${(e as Error).message}` : '');
  const done = () => { resetWorker(); settle(); void qc.invalidateQueries(); };
  const home = data?.vaults.find((v) => v.id === series.libraryId);
  if (home) {
    if (!user) return [];
    return [{
      label: tr('Move out of vault'),
      onSelect: async () => {
        if (!window.confirm(`${tr('Move “{name}” out of the vault?', { name })}

${tr('Its chapters are decrypted on the server and written back to the library as a new series. Progress you made in the vault is not carried over.')}`)) return;
        try {
          const itemId = series.id.replace(/^vlt-/, '');
          const row = (await vaultDetail(home.id)).items.find((i) => i.id === itemId);
          if (!row) throw new Error('not found');
          const job = await restoreItem(user.id, home, row);
          toast(tr('Decrypting “{name}”…', { name }), 'success');
          await waitForJob(job);
          toast(tr('“{name}” is back in the library.', { name }), 'success');
          done();
        } catch (e) { toast(tr('Could not move it out') + why(e), 'error'); }
      },
    }];
  }
  const v = data?.vaults[0]; // one vault per account
  if (!v) return [];
  return [{
    label: tr('Move to vault'),
    onSelect: async () => {
      if (!window.confirm(`${tr('Move “{name}” into your vault?', { name })}

${tr('It is encrypted (title, details, chapters, your progress) and then removed from the library, so only you can read it. You can move it back out from its menu in the Vault.')}`)) return;
      try {
        const { job } = await moveToVault(v.id, series.id);
        toast(tr('Encrypting “{name}”…', { name }), 'success');
        await waitForJob(job);
        toast(tr('“{name}” is in your vault.', { name }), 'success');
        done();
      } catch (e) { toast(tr('Could not move it to the vault') + why(e), 'error'); }
    },
  }];
}
