'use client';
// Fork-only: the vault's small pieces of UI that upstream components mount, one fork-marked line each:
//   useVaultNav()        components/Sidebar.tsx   -- "Vault" under Library
//   useVaultMenu()       components/SeriesMenu.tsx -- "Move to vault" on a series card
//   <VaultBanner />      components/AppShell.tsx  -- "your vault is locked on this device", with the password field
// Plain English: the upstream locale catalogue is not touched by the fork.
import { useEffect, useState, type FormEvent } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { useAuth } from '@/lib/auth';
import { IcLock } from '@/components/icons';
import { useToast } from '@/components/Toast';
import type { Series } from '@/lib/types';
import { deviceUnlocked, errorCode, fetchStatus, moveToVault, unlockWithPassword, type VaultStatus } from './session';

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

/** The Sidebar's item: the vault library itself when there is one, else the page that makes one. */
export function useVaultNav(): { href: string; label: string; Icon: typeof IcLock; match: (p: string) => boolean; sub?: { text: string; href: string } } | null {
  const { data } = useVaultStatus();
  if (!data?.enabled || (!data.vaults.length && !data.passwordAccount)) return null;
  const first = data.vaults[0];
  return {
    href: first ? `/library/?lib=${encodeURIComponent(first.id)}` : '/vault/',
    label: 'Vault',
    Icon: IcLock,
    match: (p) => p.startsWith('/vault'),
    sub: first ? { text: 'Manage vault', href: '/vault/' } : undefined,
  };
}

/** "Move to vault" for a series outside every vault, for each vault the account may add to. */
export function useVaultMenu(series: Series, settle: () => void): Array<{ label: string; onSelect: () => Promise<void> }> {
  const { data } = useVaultStatus();
  const qc = useQueryClient();
  const toast = useToast();
  if (!data?.vaults.length || data.vaults.some((v) => v.id === series.libraryId)) return [];
  return data.vaults.filter((v) => v.role !== 'reader').map((v) => ({
    label: data.vaults.length > 1 ? `Move to vault: ${v.name}` : 'Move to vault',
    onSelect: async () => {
      const name = series.metadata?.title || series.name;
      if (!window.confirm(`Move “${name}” into ${v.name}?\n\nOnly the vault's members will see it, and its chapters will be encrypted. This cannot be undone.`)) return;
      try {
        const r = await moveToVault(v.id, [series.id]);
        toast(r.applied ? `Moved to ${v.name}. Its chapters are being encrypted.` : 'That series could not be moved', r.applied ? 'success' : 'error');
        settle();
        qc.invalidateQueries({ queryKey: ['libraries'] });
      } catch { toast('Could not move it to the vault', 'error'); }
    },
  }));
}

/** A thin bar over every page while this account is in a vault this device cannot open: one password field. */
export function VaultBanner() {
  const { user } = useAuth();
  const { data } = useVaultStatus();
  const unlocked = useDeviceUnlocked();
  const qc = useQueryClient();
  const [pw, setPw] = useState('');
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState('');
  if (!user?.id || !data?.vaults.length || unlocked !== false) return null;
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (!pw || busy) return;
    setBusy(true); setErr('');
    try {
      await unlockWithPassword(user.id, pw, false);
      setPw('');
      await qc.invalidateQueries({ queryKey: STATUS_KEY });
      // Pages the reader already asked for came back as "locked" placeholders: load them again.
      window.location.reload();
    } catch (e2) {
      setErr((e2 as Error)?.message === 'wrong_password' || errorCode(e2) === 'wrong_password' ? 'Wrong password' : 'Could not unlock');
    } finally { setBusy(false); }
  };
  return (
    <form data-vault-banner onSubmit={submit}
      className="flex flex-wrap items-center justify-center gap-2 bg-ink-800 px-4 py-1.5 text-[11px] text-fog-300 lg:ps-[calc(var(--rail-w)+1rem)]">
      <IcLock width={12} height={12} aria-hidden className="shrink-0" />
      <span className="min-w-0">Your vault is locked on this device. Enter your account password to read it.</span>
      <input type="password" autoComplete="current-password" value={pw} onChange={(e) => setPw(e.target.value)} aria-label="Account password"
        className="h-6 w-40 rounded-md border border-ink-600 bg-ink-900 px-2 text-[11px] text-fog-100" />
      <button type="submit" disabled={!pw || busy} className="btn-key h-6 shrink-0 px-2 text-[11px] disabled:opacity-50">{busy ? 'Unlocking…' : 'Unlock'}</button>
      {err && <span className="text-red-400">{err}</span>}
    </form>
  );
}
