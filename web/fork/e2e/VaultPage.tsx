'use client';
// Fork-only: /vault -- the vault's own library, series page and reader, plus its members. Mounted by
// web/app/vault/page.tsx, which only re-exports this.
//
// Nothing a vault holds is in the server's library, so nothing here reads upstream APIs: the list, the details, the
// pages and the progress all come from /api/e2e as ciphertext and are opened in this tab (items.ts). Where the page is
// is in the URL: ?item=<id> for a series, &ch=<n> (0-based) for the reader.
//
// Plain English on purpose: the upstream locale catalogue is not touched by the fork.
import { Suspense, useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { useAuth } from '@/lib/auth';
import { useToast } from '@/components/Toast';
import * as S from './session';
import { STATUS_KEY, useDeviceUnlocked, useVaultStatus } from './hooks';
import { fingerprint } from './crypto';
import { continueAt, coverUrl, notePosition, openVault, pageUrl, type OpenItem, type OpenVault } from './items';

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
  return <Suspense fallback={<div className="skeleton m-4 h-40 rounded-2xl" />}><Vault /></Suspense>;
}

function Vault() {
  const { user } = useAuth();
  const { data: status, isLoading, refetch } = useVaultStatus();
  const unlocked = useDeviceUnlocked();
  const qc = useQueryClient();
  const refresh = useCallback(async () => {
    await qc.invalidateQueries({ queryKey: STATUS_KEY });
    await refetch();
  }, [qc, refetch]);
  const vault = status?.vaults[0];

  if (!user || isLoading) return <Shell><div className="skeleton mt-4 h-40 rounded-2xl" /></Shell>;
  if (!status) return <Shell><p className="mt-6 text-sm text-fog-400">Vaults are switched off on this server.</p></Shell>;
  if (!vault || unlocked === false) return <Shell><Unlock userId={user.id} status={status} unlocked={!!unlocked} hasVault={!!vault} onDone={refresh} /></Shell>;
  if (unlocked === null) return <Shell><div className="skeleton mt-4 h-40 rounded-2xl" /></Shell>;
  return <VaultView userId={user.id} vault={vault} onChange={refresh} />;
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

function VaultView({ userId, vault, onChange }: { userId: string; vault: S.VaultRef; onChange: () => Promise<void> }) {
  const sp = useSearchParams();
  const router = useRouter();
  const { data, error, refetch } = useQuery<OpenVault>({
    queryKey: ['e2e-vault', userId, vault.id, vault.wrappedKey],
    queryFn: () => openVault(userId, vault),
    staleTime: 5 * 60_000,
    retry: false,
  });
  const itemId = sp.get('item');
  const ch = sp.get('ch');
  const item = data?.items.find((i) => i.row.id === itemId) ?? null;
  const go = useCallback((q: Record<string, string | number | null>) => {
    const u = new URLSearchParams();
    for (const [k, v] of Object.entries(q)) if (v !== null) u.set(k, String(v));
    const s = u.toString();
    router.push(s ? `/vault/?${s}` : '/vault/');
  }, [router]);

  if (error) return <Shell><p className="mt-6 text-sm text-red-400">{msg(error)}</p></Shell>;
  if (!data) return <Shell><div className="skeleton mt-4 h-40 rounded-2xl" /></Shell>;
  if (item && ch !== null) {
    return <Reader userId={userId} vaultId={vault.id} item={item} chapter={Number(ch)} start={Number(sp.get('p') || 0)}
      onChapter={(c) => go({ item: item.row.id, ch: c })} onClose={() => go({ item: item.row.id })} />;
  }
  if (item) {
    return <SeriesView userId={userId} vault={vault} role={data.detail.role} item={item} onBack={() => go({})}
      onRead={(c, p) => go({ item: item.row.id, ch: c, p: p || null })} onGone={async () => { await refetch(); go({}); }} />;
  }
  return (
    <Shell>
      <p className="max-w-2xl text-xs text-fog-500">
        Series you move here are encrypted: titles, details, chapters and progress. The server stores them but can&apos;t
        read them; this device opens them. To add one, choose <b>Move to vault</b> on its card in the Library.
      </p>
      {data.failed > 0 && <p className="mt-3 text-xs text-amber-300">{data.failed} series could not be opened.</p>}
      {data.items.length === 0 ? (
        <p className="mt-8 text-sm text-fog-400">Nothing here yet.</p>
      ) : (
        <div className="mt-4 grid grid-cols-3 gap-3 sm:grid-cols-4 md:grid-cols-5 lg:grid-cols-6 2xl:grid-cols-8">
          {data.items.map((it) => <Tile key={it.row.id} vaultId={vault.id} item={it} onOpen={() => go({ item: it.row.id })} />)}
        </div>
      )}
      <VaultSettings userId={userId} vault={vault} detail={data.detail} onChange={async () => { await refetch(); await onChange(); }} />
    </Shell>
  );
}

/** An object URL that is revoked when the component lets go of it. */
function useObjectUrl(make: () => Promise<string | null>, deps: unknown[]): string | null {
  const [url, setUrl] = useState<string | null>(null);
  useEffect(() => {
    let live = true, made: string | null = null;
    make().then((u) => { made = u; if (live) setUrl(u); else if (u) URL.revokeObjectURL(u); }).catch(() => {});
    return () => { live = false; if (made) URL.revokeObjectURL(made); setUrl(null); };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);
  return url;
}

function Cover({ vaultId, item, className }: { vaultId: string; item: OpenItem; className?: string }) {
  const url = useObjectUrl(() => coverUrl(vaultId, item), [vaultId, item.row.id]);
  return (
    <div className={`aspect-[2/3] overflow-hidden rounded-xl bg-ink-800 ${className ?? ''}`}>
      {url && <img src={url} alt="" className="h-full w-full object-cover" />}
    </div>
  );
}

function Tile({ vaultId, item, onOpen }: { vaultId: string; item: OpenItem; onOpen: () => void }) {
  const read = Object.values(item.state.chapters).filter((c) => c.completed).length;
  const total = item.manifest.chapters.length;
  return (
    <button className="group min-w-0 text-start" onClick={onOpen}>
      <Cover vaultId={vaultId} item={item} className="transition group-hover:opacity-90" />
      <div className="mt-1.5 line-clamp-2 text-xs font-medium text-fog-100">{item.manifest.title}</div>
      <div className="text-2xs text-fog-500">{read ? `${read} / ${total} read` : `${total} chapter${total === 1 ? '' : 's'}`}</div>
    </button>
  );
}

function SeriesView({ userId, vault, role, item, onBack, onRead, onGone }: {
  userId: string; vault: S.VaultRef; role: S.Role; item: OpenItem; onBack: () => void; onRead: (ch: number, page: number) => void; onGone: () => Promise<void>;
}) {
  const m = item.manifest;
  const toast = useToast();
  const [moving, setMoving] = useState<string | null>(null);
  const next = continueAt(item);
  const started = Object.keys(item.state.chapters).length > 0;
  const moveOut = async () => {
    if (!window.confirm(`Move “${m.title}” out of the vault?\n\nIts chapters are decrypted on the server and written back to the library as a new series. Your vault progress for it is not carried over.`)) return;
    try {
      setMoving('Starting…');
      const job = await S.restoreItem(userId, vault, item.row);
      await S.waitForJob(job, (j) => setMoving(j.total ? `Decrypting ${j.done} / ${j.total}…` : 'Decrypting…'));
      toast(`“${m.title}” is back in the library.`, 'success');
      await onGone();
    } catch (e) { toast(`Could not move it out: ${msg(e)}`, 'error'); } finally { setMoving(null); }
  };
  return (
    <div className="min-h-screen-d px-4 pb-24 lg:px-0">
      <div className="safe-top pt-2 lg:pt-6"><button className="text-xs text-fog-400 hover:text-fog-100" onClick={onBack}>← Vault</button></div>
      <div className="mt-3 flex flex-col gap-5 sm:flex-row">
        <Cover vaultId={vault.id} item={item} className="w-40 shrink-0 self-start" />
        <div className="min-w-0 flex-1">
          <h1 className="font-display text-2xl font-bold lg:text-3xl">{m.title}</h1>
          <div className="mt-1 text-xs text-fog-500">{[m.author, m.status, m.genres.join(', ')].filter(Boolean).join(' · ')}</div>
          {m.summary && <p className="mt-3 max-w-3xl whitespace-pre-line text-sm text-fog-300">{m.summary}</p>}
          <div className="mt-4 flex flex-wrap gap-2">
            {m.chapters.length > 0 && (
              <button className="btn-accent px-4 py-2 text-sm" onClick={() => onRead(next.chapter, next.page)}>
                {started ? `Continue · Chapter ${m.chapters[next.chapter]?.number}` : 'Start reading'}
              </button>
            )}
            {role !== 'reader' && (
              <button className="btn-key px-3 text-sm disabled:opacity-50" disabled={!!moving} onClick={moveOut}>{moving ?? 'Move out of vault'}</button>
            )}
          </div>
        </div>
      </div>
      <ul className="mt-6 divide-y divide-ink-700 rounded-2xl border border-ink-700">
        {m.chapters.map((c, i) => ({ c, i })).reverse().map(({ c, i }) => {
          const st = item.state.chapters[i];
          return (
            <li key={i}>
              <button className="flex w-full items-center gap-3 px-4 py-2.5 text-start text-sm hover:bg-ink-800" onClick={() => onRead(i, st && !st.completed ? st.page : 0)}>
                <span className={`min-w-0 flex-1 truncate ${st?.completed ? 'text-fog-500' : 'text-fog-100'}`}>
                  Chapter {c.number}{c.title ? ` · ${c.title}` : ''}
                </span>
                <span className="shrink-0 text-2xs text-fog-500">
                  {st?.completed ? 'Read' : st ? `Page ${st.page + 1} / ${c.pages.length}` : `${c.pages.length} pages`}
                </span>
              </button>
            </li>
          );
        })}
      </ul>
    </div>
  );
}

/** A page box sized from the manifest before the image is there, decrypted once it nears the screen. */
function Page({ vaultId, item, chapter, page, near, onSeen }: { vaultId: string; item: OpenItem; chapter: number; page: number; near: boolean; onSeen: (p: number) => void }) {
  const dims = item.manifest.chapters[chapter]?.pages[page];
  const url = useObjectUrl(() => (near ? pageUrl(vaultId, item, chapter, page) : Promise.resolve(null)), [vaultId, item.row.id, chapter, page, near]);
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    const io = new IntersectionObserver(([e]) => { if (e.isIntersecting) onSeen(page); }, { threshold: 0.5 });
    io.observe(el);
    return () => io.disconnect();
  }, [page, onSeen]);
  const ratio = dims?.w && dims?.h ? `${dims.w} / ${dims.h}` : '2 / 3';
  return (
    <div ref={ref} data-page={page} className="mx-auto w-full max-w-3xl bg-ink-900" style={{ aspectRatio: url ? undefined : ratio }}>
      {url ? <img src={url} alt={`Page ${page + 1}`} className="block w-full" /> : <div className="flex h-full items-center justify-center text-xs text-fog-600">{page + 1}</div>}
    </div>
  );
}

/** A long-strip reader: pages one under the other, decrypted a few at a time around where you are. */
function Reader({ userId, vaultId, item, chapter, start, onChapter, onClose }: {
  userId: string; vaultId: string; item: OpenItem; chapter: number; start: number; onChapter: (c: number) => void; onClose: () => void;
}) {
  const ch = item.manifest.chapters[chapter];
  const [at, setAt] = useState(start);
  const saved = useRef(-1);
  const scroller = useRef<HTMLDivElement>(null);
  useEffect(() => {
    setAt(start);
    saved.current = -1;
    requestAnimationFrame(() => scroller.current?.querySelector(`[data-page="${start}"]`)?.scrollIntoView());
  }, [chapter, start]);
  // Saved a moment after the page settles, and once more on the way out.
  useEffect(() => {
    const t = setTimeout(() => {
      if (saved.current === at) return;
      saved.current = at;
      void notePosition(userId, vaultId, item, chapter, at).catch(() => {});
    }, 1500);
    return () => clearTimeout(t);
  }, [at, userId, vaultId, item, chapter]);
  useEffect(() => {
    const key = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose(); };
    window.addEventListener('keydown', key);
    return () => window.removeEventListener('keydown', key);
  }, [onClose]);
  const onSeen = useCallback((p: number) => setAt(p), []);
  const pages = useMemo(() => ch?.pages.map((_, i) => i) ?? [], [ch]);
  if (!ch) return null;
  const last = chapter >= item.manifest.chapters.length - 1;
  return (
    <div ref={scroller} className="fixed inset-0 z-50 overflow-y-auto bg-ink-950">
      <div className="sticky top-0 z-10 flex items-center gap-3 bg-ink-950/90 px-4 py-2 text-xs text-fog-300 backdrop-blur">
        <button onClick={onClose} className="hover:text-fog-100">✕</button>
        <span className="min-w-0 flex-1 truncate">{item.manifest.title} · Chapter {ch.number}</span>
        <span>{at + 1} / {ch.pages.length}</span>
      </div>
      {pages.map((p) => <Page key={`${chapter}:${p}`} vaultId={vaultId} item={item} chapter={chapter} page={p} near={Math.abs(p - at) <= 4} onSeen={onSeen} />)}
      <div className="flex justify-center gap-3 py-10">
        {chapter > 0 && <button className="btn-key px-4 py-2 text-sm" onClick={() => onChapter(chapter - 1)}>Previous chapter</button>}
        {!last ? <button className="btn-accent px-4 py-2 text-sm" onClick={() => { void notePosition(userId, vaultId, item, chapter, ch.pages.length - 1).catch(() => {}); onChapter(chapter + 1); }}>Next chapter</button>
          : <button className="btn-key px-4 py-2 text-sm" onClick={() => { void notePosition(userId, vaultId, item, chapter, ch.pages.length - 1).catch(() => {}); onClose(); }}>Done</button>}
      </div>
    </div>
  );
}

function VaultSettings({ userId, vault, detail, onChange }: { userId: string; vault: S.VaultRef; detail: S.VaultDetail; onChange: () => Promise<void> }) {
  const [fp, setFp] = useState('');
  const [busy, setBusy] = useState(false);
  const toast = useToast();
  const owner = vault.role === 'owner';
  useEffect(() => {
    const me = detail.members.find((m) => m.userId === userId)?.publicKey;
    if (me) fingerprint(me).then(setFp).catch(() => {});
  }, [detail, userId]);
  const run = async (fn: () => Promise<unknown>) => {
    setBusy(true);
    try { await fn(); } catch (e) { toast(msg(e), 'error'); } finally { setBusy(false); }
  };
  return (
    <details className="mt-10 max-w-2xl rounded-2xl border border-ink-700 bg-ink-850 p-5">
      <summary className="cursor-pointer text-sm font-semibold text-fog-100">Members and settings</summary>
      <Members userId={userId} vault={vault} members={detail.members} busy={busy} run={run} reload={onChange} onLeft={onChange} />
      {owner && detail.items.length === 0 && (
        <button className="btn-key btn-key-danger mt-4 px-3 text-sm" disabled={busy} onClick={() => run(async () => {
          if (!window.confirm('Delete this vault? It is empty.')) return;
          await S.deleteVault(vault.id); await onChange();
        })}>Delete vault</button>
      )}
      {fp && <p className="mt-4 text-2xs text-fog-500">Your key fingerprint: <span className="font-mono text-fog-300">{fp}</span></p>}
    </details>
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
