'use client';
// Fork-only: /vault/manage (and /vault while it is locked) -- what is particular to the vault: unlocking it on this device, its members, deleting it. Its
// series are read at /vault, the ordinary Library page fixed to the vault (shelf.ts; the service worker,
// public/e2e-sw.js, answers for it). Mounted by web/app/vault/manage/page.tsx and VaultRoute.tsx.
//
// Plain English on purpose: the upstream locale catalogue is not touched by the fork.
import Link from 'next/link';
import { useCallback, useEffect, useState } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { useAuth } from '@/lib/auth';
import { useToast } from '@/components/Toast';
import * as S from './session';
import { resetWorker, STATUS_KEY, useDeviceUnlocked, useVaultStatus } from './hooks';
import { fingerprint } from './crypto';

const msg = (e: unknown): string => {
  const code = S.errorCode(e);
  const m = (e as Error)?.message;
  if (m === 'wrong_password' || code === 'wrong_password') return 'That is not your account password.';
  if (m === 'locked') return 'Your vault is locked on this device. Unlock it with your password first.';
  if (code === 'not_empty') return 'The vault still holds series. Move them out first.';
  if (code === 'owns_vaults') return 'Delete the vaults you own first.';
  if (code === 'no_keys') return 'That account has not set up a vault yet (it needs to sign in once with its password).';
  return code ? code.replace(/_/g, ' ') : m || 'Something went wrong';
};

export default function VaultPage() {
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
  if (unlocked === null) return <Shell><div className="skeleton mt-4 h-40 rounded-2xl" /></Shell>;
  return <Shell><VaultSettings userId={user.id} vault={vault} onChange={refresh} /></Shell>;
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
function Unlock({ userId, status, unlocked, hasVault, onDone }: { userId: string; status: S.VaultStatus; unlocked: boolean; hasVault: boolean; onDone: () => Promise<void> }) {
  const [pw, setPw] = useState('');
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState('');
  const ready = status.hasKeys && unlocked;
  useEffect(() => {
    if (!ready || hasVault || !status.passwordAccount) return;
    S.ensureVault(userId).then(onDone).catch((e) => setErr(msg(e)));
  }, [ready, hasVault, status.passwordAccount, userId, onDone]);
  if (!status.passwordAccount && !hasVault) {
    return <p className="mt-6 max-w-xl text-sm text-fog-400">A vault is unlocked with your account password, and this account signs in without one (single sign-on or a profile). Ask an admin to give it a password to use a vault.</p>;
  }
  if (ready) return err ? <p className="mt-6 text-sm text-red-400">{err}</p> : <div className="skeleton mt-4 h-40 rounded-2xl" />;
  const unlock = async () => {
    if (!pw || busy) return;
    setBusy(true); setErr('');
    try { await S.unlockWithPassword(userId, pw, false); setPw(''); await onDone(); } catch (e) { setErr(msg(e)); } finally { setBusy(false); }
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

function VaultSettings({ userId, vault, onChange }: { userId: string; vault: S.VaultRef; onChange: () => Promise<void> }) {
  const { data: detail, refetch } = useQuery({ queryKey: ['e2e-vault', vault.id], queryFn: () => S.vaultDetail(vault.id) });
  const [fp, setFp] = useState('');
  const [busy, setBusy] = useState(false);
  const toast = useToast();
  const owner = vault.role === 'owner';
  useEffect(() => {
    const me = detail?.members.find((m) => m.userId === userId)?.publicKey;
    if (me) fingerprint(me).then(setFp).catch(() => {});
  }, [detail, userId]);
  const run = async (fn: () => Promise<unknown>) => {
    setBusy(true);
    try { await fn(); } catch (e) { toast(msg(e), 'error'); } finally { setBusy(false); }
  };
  const reload = async () => { await refetch(); await onChange(); };
  if (!detail) return <div className="skeleton mt-4 h-40 rounded-2xl" />;
  return (
    <section className="mt-4 max-w-2xl rounded-2xl border border-ink-700 bg-ink-850 p-5">
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-sm text-fog-300">{detail.items.length} series · {vault.role}</span>
        <Link href="/vault/" className="btn-accent ms-auto px-3.5 py-2 text-sm">Open vault</Link>
      </div>
      <p className="mt-2 text-sm text-fog-400">
        Series in the vault are encrypted: titles, details, chapters and progress. The server stores them but can&apos;t read
        them; this device opens them. Use <b>Move to vault</b> on a series card to add one, and <b>Move out of vault</b> on
        its card in the Vault to take it back out.
      </p>
      <h3 className="mt-5 border-t border-ink-700 pt-4 text-sm font-semibold text-fog-100">Members</h3>
      <Members userId={userId} vault={vault} members={detail.members} busy={busy} run={run} reload={reload} onLeft={onChange} />
      {owner && detail.items.length === 0 && (
        <button className="btn-key btn-key-danger mt-4 px-3 text-sm" disabled={busy} onClick={() => run(async () => {
          if (!window.confirm('Delete this vault? It is empty.')) return;
          await S.deleteVault(vault.id); await onChange();
        })}>Delete vault</button>
      )}
      {fp && <p className="mt-4 text-2xs text-fog-500">Your key fingerprint: <span className="font-mono text-fog-300">{fp}</span></p>}
    </section>
  );
}

function Members({ userId, vault, members, busy, run, reload, onLeft }: {
  userId: string; vault: S.VaultRef; members: S.Member[]; busy: boolean;
  run: (fn: () => Promise<unknown>) => Promise<void>; reload: () => Promise<unknown>; onLeft: () => Promise<void>;
}) {
  const [username, setUsername] = useState('');
  const [role, setRole] = useState<'reader' | 'editor'>('reader');
  const [found, setFound] = useState<Awaited<ReturnType<typeof S.lookupUser>> | null>(null);
  const owner = vault.role === 'owner';
  return (
    <div className="mt-4">
      <ul className="divide-y divide-ink-700">
        {members.map((m) => (
          <li key={m.userId} className="flex items-center gap-2 py-2 text-sm">
            <span className="min-w-0 flex-1 truncate">{m.displayName}{m.username ? <span className="text-fog-500"> @{m.username}</span> : null}</span>
            <span className="text-2xs text-fog-500">{m.role}</span>
            {owner && m.role !== 'owner' && (
              <button className="btn-key btn-key-danger px-2 text-xs" disabled={busy} onClick={() => run(async () => { await S.removeMember(vault.id, m.userId); await reload(); })}>Remove</button>
            )}
            {!owner && m.userId === userId && (
              <button className="btn-key btn-key-danger px-2 text-xs" disabled={busy} onClick={() => run(async () => {
                if (!window.confirm('Leave this vault?')) return;
                await S.removeMember(vault.id, userId); await onLeft();
              })}>Leave</button>
            )}
          </li>
        ))}
      </ul>
      {owner && (
        <div className="mt-3">
          <p className="text-xs text-fog-500">Share with someone in this household. They must have signed in once with their password since vaults were turned on.</p>
          <div className="mt-2 flex gap-2">
            <input className="field max-w-none flex-1" placeholder="Username" value={username} onChange={(e) => { setUsername(e.target.value); setFound(null); }} />
            <select className="field w-28" value={role} onChange={(e) => setRole(e.target.value as 'reader' | 'editor')}>
              <option value="reader">Reader</option>
              <option value="editor">Editor</option>
            </select>
            <button className="btn-key px-3 text-sm" disabled={!username.trim() || busy} onClick={() => run(async () => setFound(await S.lookupUser(username)))}>Find</button>
          </div>
          {found && (
            <div className="mt-3 rounded-xl border border-ink-700 p-3 text-sm">
              <div>{found.displayName} <span className="text-fog-500">@{found.username}</span></div>
              <div className="mt-1 text-2xs text-fog-500">Key fingerprint: <span className="font-mono text-fog-300">{found.fingerprint}</span></div>
              <p className="mt-1 text-2xs text-fog-500">Compare it with the one on their Vault page to be sure the key is theirs.</p>
              <button className="btn-accent mt-2 px-3.5 py-2 text-sm" disabled={busy || found.userId === userId} onClick={() => run(async () => {
                await S.shareVault(userId, vault, found, role);
                setFound(null); setUsername('');
                await reload();
              })}>Share as {role}</button>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
