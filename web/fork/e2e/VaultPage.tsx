'use client';
// Fork-only: /vault -- making a vault and managing it. The vault itself is an ordinary library (the Sidebar's "Vault"
// opens it in the Library); this page is only for what is particular to it: its members, and how far its chapters are
// encrypted. Mounted by web/app/vault/page.tsx, which only re-exports this.
//
// Plain English on purpose: the upstream locale catalogue is not touched by the fork.
import Link from 'next/link';
import { useCallback, useEffect, useState } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { useAuth } from '@/lib/auth';
import { useToast } from '@/components/Toast';
import * as S from './session';
import { STATUS_KEY, useDeviceUnlocked, useVaultStatus } from './hooks';
import { fingerprint } from './crypto';

const msg = (e: unknown): string => {
  const code = S.errorCode(e);
  const m = (e as Error)?.message;
  if (m === 'wrong_password' || code === 'wrong_password') return 'That is not your account password.';
  if (m === 'locked') return 'Your vault is locked on this device. Unlock it with your password first.';
  if (code === 'not_empty') return 'The vault still holds series. Remove them from the library first.';
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
    await qc.invalidateQueries({ queryKey: STATUS_KEY });
    await qc.invalidateQueries({ queryKey: ['libraries'] });
    await refetch();
  }, [qc, refetch]);

  return (
    <div className="min-h-screen-d px-4 pb-24 lg:px-0">
      <header className="safe-top pb-2 pt-2 lg:pt-6">
        <h1 className="font-display text-2xl font-bold lg:text-3xl">Vault</h1>
        <p className="mt-0.5 max-w-2xl text-xs text-fog-500">
          A private library. It works like any other (follow series, fetch chapters from your sources, read), but only its
          members see it, and its chapters are encrypted with the vault&apos;s key. The server can add chapters, but cannot read them.
        </p>
      </header>
      {!user || isLoading ? <div className="skeleton mt-4 h-40 rounded-2xl" />
        : !status ? <p className="mt-6 text-sm text-fog-400">Vaults are switched off on this server.</p>
        : !status.vaults.length ? <CreateVault userId={user.id} status={status} unlocked={!!unlocked} onDone={refresh} />
        : status.vaults.map((v) => <VaultCard key={v.id} userId={user.id} vault={v} onChange={refresh} />)}
    </div>
  );
}

function PasswordField({ value, onChange }: { value: string; onChange: (v: string) => void }) {
  return <input type="password" autoComplete="current-password" className="field mt-3 max-w-none" placeholder="Your account password" value={value} onChange={(e) => onChange(e.target.value)} />;
}

/** No vault yet: it is made by itself once this device holds the key; until then, the one password field. */
function CreateVault({ userId, status, unlocked, onDone }: { userId: string; status: S.VaultStatus; unlocked: boolean; onDone: () => Promise<void> }) {
  const [pw, setPw] = useState('');
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState('');
  const ready = status.hasKeys && unlocked;
  useEffect(() => {
    if (!ready || !status.passwordAccount) return;
    S.ensureVault(userId).then(onDone).catch((e) => setErr(msg(e)));
  }, [ready, status.passwordAccount, userId, onDone]);
  if (!status.passwordAccount) {
    return <p className="mt-6 max-w-xl text-sm text-fog-400">A vault is unlocked with your account password, and this account signs in without one (single sign-on or a profile). Ask an admin to give it a password to use a vault.</p>;
  }
  if (ready) return err ? <p className="mt-6 text-sm text-red-400">{err}</p> : <div className="skeleton mt-4 h-40 rounded-2xl" />;
  const unlock = async () => {
    if (!pw || busy) return;
    setBusy(true); setErr('');
    try { await S.unlockWithPassword(userId, pw, false); await onDone(); } catch (e) { setErr(msg(e)); } finally { setBusy(false); }
  };
  return (
    <section className="mt-4 max-w-lg rounded-2xl border border-ink-700 bg-ink-850 p-5">
      <h2 className="font-display text-lg font-semibold">Unlock your vault on this device</h2>
      <p className="mt-1 text-sm text-fog-400">
        This device was signed in before your vault existed. Enter your account password once; signing in with it does this
        by itself from now on.
      </p>
      <PasswordField value={pw} onChange={setPw} />
      {err && <p className="mt-2 text-xs text-red-400">{err}</p>}
      <button className="btn-accent mt-4 w-full py-2.5 text-sm disabled:opacity-50" disabled={!pw || busy} onClick={unlock}>
        {busy ? 'Unlocking…' : 'Unlock'}
      </button>
    </section>
  );
}

function VaultCard({ userId, vault, onChange }: { userId: string; vault: S.VaultRef; onChange: () => Promise<void> }) {
  const [detail, setDetail] = useState<S.VaultDetail | null>(null);
  const [fp, setFp] = useState('');
  const [busy, setBusy] = useState(false);
  const toast = useToast();
  const owner = vault.role === 'owner';
  const load = useCallback(() => S.vaultDetail(vault.id).then(setDetail).catch((e) => toast(msg(e), 'error')), [vault.id, toast]);
  useEffect(() => { void load(); }, [load]);
  useEffect(() => {
    const me = detail?.members.find((m) => m.userId === userId)?.publicKey;
    if (me) fingerprint(me).then(setFp).catch(() => {});
  }, [detail, userId]);
  const run = async (fn: () => Promise<unknown>) => {
    setBusy(true);
    try { await fn(); } catch (e) { toast(msg(e), 'error'); } finally { setBusy(false); }
  };
  const seal = detail?.seal;

  return (
    <section className="mt-4 rounded-2xl border border-ink-700 bg-ink-850 p-5">
      <div className="flex flex-wrap items-center gap-2">
        <h2 className="font-display text-lg font-semibold">{vault.name}</h2>
        <span className="text-2xs text-fog-500">{vault.role}</span>
        <div className="ms-auto flex flex-wrap gap-2">
          <Link href={`/library/?lib=${encodeURIComponent(vault.id)}`} className="btn-accent px-3.5 py-2 text-sm">Open</Link>
          {owner && (
            <button className="btn-key px-3 text-sm" disabled={busy} onClick={() => run(async () => {
              const name = window.prompt('Vault name', vault.name)?.trim();
              if (name) { await S.renameVault(vault.id, name); await onChange(); }
            })}>Rename</button>
          )}
          {owner && (
            <button className="btn-key btn-key-danger px-3 text-sm" disabled={busy} onClick={() => run(async () => {
              if (!window.confirm(`Delete the vault “${vault.name}”? It must be empty.`)) return;
              await S.deleteVault(vault.id); await onChange();
            })}>Delete</button>
          )}
        </div>
      </div>
      <p className="mt-2 text-sm text-fog-400">
        Add series as usual, then choose <b>Move to vault</b> on the series card. From then on, every chapter fetched for it
        is encrypted before it is written to disk.
      </p>

      {seal && (
        <div className="mt-4 rounded-xl border border-ink-700 p-3 text-sm">
          <div className="flex flex-wrap items-center gap-2">
            <span>{detail!.series} series · {seal.sealed} of {seal.total} chapter files encrypted{seal.failed ? ` · ${seal.failed} could not be` : ''}</span>
            {vault.role !== 'reader' && (
              <button className="btn-key ms-auto px-3 text-xs" disabled={busy} onClick={() => run(async () => { await S.sealNow(vault.id); await load(); })}>
                {busy ? 'Encrypting…' : 'Encrypt now'}
              </button>
            )}
          </div>
          {seal.problems.length > 0 && (
            <ul className="mt-2 space-y-0.5 text-2xs text-amber-300">
              {seal.problems.map((p, i) => (
                <li key={i}>{p.title}: {p.file.split('/').pop()} ({p.error === 'unsupported_format' ? 'only CBZ chapters can be encrypted'
                  : p.error === 'read_only' ? 'the file is read-only to the server' : p.error})</li>
              ))}
            </ul>
          )}
        </div>
      )}

      {detail && <Members userId={userId} vault={vault} members={detail.members} busy={busy} run={run} reload={load} onLeft={onChange} />}
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
    <div className="mt-5 border-t border-ink-700 pt-4">
      <h3 className="text-sm font-semibold text-fog-100">Members</h3>
      <ul className="mt-2 divide-y divide-ink-700">
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
