'use client';
// /vault (docs/VAULTS.md). Once this device can open the vault, it is the ordinary Library page fixed to the vault
// (lib/useVault.ts useShelf; the service worker, public/vault-sw.js, answers for its series). Until then, the unlock with
// the account password. The vault belongs to one account and is never shared.
import { useCallback, useEffect, useState } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import LibraryPage from '@/app/library/page';
import { useAuth } from '@/lib/auth';
import { ensureVault, errorCode, resetWorker, unlockWithPassword, type VaultStatus } from '@/lib/vault';
import { STATUS_KEY, useDeviceUnlocked, useVaultStatus } from '@/lib/useVault';

export default function VaultPage() {
  const { data } = useVaultStatus();
  const unlocked = useDeviceUnlocked();
  return data?.vaults.length && unlocked ? <LibraryPage /> : <Locked />;
}

const msg = (e: unknown): string => {
  const code = errorCode(e);
  const m = (e as Error)?.message;
  if (m === 'wrong_password' || code === 'wrong_password') return 'That is not your account password.';
  if (m === 'locked') return 'Your vault is locked on this device. Unlock it with your password first.';
  return code ? code.replace(/_/g, ' ') : m || 'Something went wrong';
};

/** /vault while this device cannot open the vault yet: the unlock. */
function Locked() {
  const { user } = useAuth();
  const { data: status, isLoading, refetch } = useVaultStatus();
  const unlocked = useDeviceUnlocked();
  const qc = useQueryClient();
  const refresh = useCallback(async () => {
    resetWorker();
    await qc.invalidateQueries({ queryKey: STATUS_KEY });
    await qc.invalidateQueries({ queryKey: ['libraries'] });
    await refetch();
  }, [qc, refetch]);
  const vault = status?.vaults[0];

  if (!user || isLoading) return <Shell><div className="skeleton mt-4 h-40 rounded-2xl" /></Shell>;
  if (!status) return <Shell><p className="mt-6 text-sm text-fog-400">Vaults are switched off on this server.</p></Shell>;
  if (!vault || unlocked === false) return <Shell><Unlock userId={user.id} status={status} unlocked={!!unlocked} hasVault={!!vault} onDone={refresh} /></Shell>;
  return <Shell><div className="skeleton mt-4 h-40 rounded-2xl" /></Shell>; // an unlocked vault is the Library (VaultPage)
}

function Shell({ children }: { children: React.ReactNode }) {
  return (
    <div className="min-h-screen-d px-4 pb-24 lg:px-0">
      <header className="safe-top pb-2 pt-2 lg:pt-6">
        <h1 className="font-display text-2xl font-bold lg:text-3xl">Vault</h1>
      </header>
      {children}
    </div>
  );
}

/** No key on this device yet (or no vault yet): the one password field. The vault is made by itself once unlocked. */
function Unlock({ userId, status, unlocked, hasVault, onDone }: { userId: string; status: VaultStatus; unlocked: boolean; hasVault: boolean; onDone: () => Promise<void> }) {
  const [pw, setPw] = useState('');
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState('');
  const ready = status.hasKeys && unlocked;
  useEffect(() => {
    if (!ready || hasVault || !status.passwordAccount) return;
    ensureVault(userId).then(onDone).catch((e) => setErr(msg(e)));
  }, [ready, hasVault, status.passwordAccount, userId, onDone]);
  if (!status.passwordAccount && !hasVault) {
    return <p className="mt-6 max-w-xl text-sm text-fog-400">A vault is unlocked with your account password, and this account signs in without one (single sign-on or a profile). Ask an admin to give it a password to use a vault.</p>;
  }
  if (ready) return err ? <p className="mt-6 text-sm text-red-400">{err}</p> : <div className="skeleton mt-4 h-40 rounded-2xl" />;
  const unlock = async () => {
    if (!pw || busy) return;
    setBusy(true); setErr('');
    try { await unlockWithPassword(userId, pw, false); setPw(''); await onDone(); } catch (e) { setErr(msg(e)); } finally { setBusy(false); }
  };
  return (
    <form className="mt-4 max-w-lg rounded-2xl border border-ink-700 bg-ink-850 p-5" onSubmit={(e) => { e.preventDefault(); void unlock(); }}>
      <h2 className="font-display text-lg font-semibold">Unlock your vault on this device</h2>
      <p className="mt-1 text-sm text-fog-400">Enter your account password once. Signing in with it does this by itself from now on.</p>
      <input type="password" autoComplete="current-password" className="field mt-3 max-w-none" placeholder="Your account password" value={pw} onChange={(e) => setPw(e.target.value)} />
      {err && <p className="mt-2 text-xs text-red-400">{err}</p>}
      <button type="submit" className="btn-accent mt-4 w-full py-2.5 text-sm disabled:opacity-50" disabled={!pw || busy}>{busy ? 'Unlocking…' : 'Unlock'}</button>
    </form>
  );
}
