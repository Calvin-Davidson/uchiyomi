'use client';
// Fork-only: the vault's small pieces of UI that upstream components mount, one fork-marked line each:
//   useVaultNav()        components/Sidebar.tsx   -- "Vault" under Library
//   useVaultMenu()       components/SeriesMenu.tsx -- "Move to vault" / "Move out of vault" on a series card
// Plain English: the upstream locale catalogue is not touched by the fork.
import { useEffect, useState } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { useAuth } from '@/lib/auth';
import { IcLock } from '@/components/icons';
import { useToast } from '@/components/Toast';
import type { Series } from '@/lib/types';
import { deviceUnlocked, fetchStatus, moveToVault, restoreItem, vaultDetail, waitForJob, type VaultStatus } from './session';

export const STATUS_KEY = ['e2e-status'] as const;

/** The vault status for the signed-in account; null when the server has no vaults (feature off, or upstream). */
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

/** Tell the service worker (public/e2e-sw.js) to open the vault again: after a move, an unlock or a sign-in. */
export function resetWorker(): void {
  try { navigator.serviceWorker?.controller?.postMessage({ e2e: 'reset' }); } catch { /* no worker */ }
}

/** The Sidebar's item: the Vault, which is the Library filtered to it (or the unlock, until this device has the key). */
export function useVaultNav(): { href: string; label: string; Icon: typeof IcLock; match: (p: string) => boolean } | null {
  const { data } = useVaultStatus();
  if (!data?.enabled || (!data.vaults.length && !data.passwordAccount)) return null;
  return {
    href: '/vault/',
    label: 'Vault',
    Icon: IcLock,
    match: (p) => p.startsWith('/vault'),
  };
}

/** On a series card: "Move to vault", or "Move out of vault" for a series that is in one. */
export function useVaultMenu(series: Series, settle: () => void): Array<{ label: string; onSelect: () => Promise<void> }> {
  const { user } = useAuth();
  const { data } = useVaultStatus();
  const qc = useQueryClient();
  const toast = useToast();
  const name = series.metadata?.title || series.name;
  const done = () => { resetWorker(); settle(); void qc.invalidateQueries(); };
  const home = data?.vaults.find((v) => v.id === series.libraryId);
  if (home) {
    if (home.role === 'reader' || !user) return [];
    return [{
      label: 'Move out of vault',
      onSelect: async () => {
        if (!window.confirm(`Move “${name}” out of the vault?

Its chapters are decrypted on the server and written back to the library as a new series. Progress you made in the vault is not carried over.`)) return;
        try {
          const itemId = series.id.replace(/^vlt-/, '');
          const row = (await vaultDetail(home.id)).items.find((i) => i.id === itemId);
          if (!row) throw new Error('not found');
          const job = await restoreItem(user.id, home, row);
          toast(`Decrypting “${name}”…`, 'success');
          await waitForJob(job);
          toast(`“${name}” is back in the library.`, 'success');
          done();
        } catch (e) { toast(`Could not move it out${(e as Error)?.message ? `: ${(e as Error).message}` : ''}`, 'error'); }
      },
    }];
  }
  const vaults = (data?.vaults ?? []).filter((v) => v.role !== 'reader');
  return vaults.map((v, i) => ({
    label: vaults.length > 1 ? `Move to vault ${i + 1}` : 'Move to vault',
    onSelect: async () => {
      if (!window.confirm(`Move “${name}” into your vault?

It is encrypted (title, details, chapters, your progress) and then removed from the library, so only you can read it. You can move it back out from its menu in the Vault.`)) return;
      try {
        const { job } = await moveToVault(v.id, series.id);
        toast(`Encrypting “${name}”…`, 'success');
        await waitForJob(job);
        toast(`“${name}” is in your vault.`, 'success');
        done();
      } catch (e) { toast(`Could not move it to the vault${(e as Error)?.message ? `: ${(e as Error).message}` : ''}`, 'error'); }
    },
  }));
}
