'use client';
// Fork-only: the private (end-to-end encrypted) libraries page, at /vault. Mounted by web/app/vault/page.tsx, which
// only re-exports this, so the fork's UI stays under web/fork/ and out of the upstream files.
//
// Plain English strings on purpose: the upstream catalogue (lib/i18n.ts + eight locale files) is not touched by the
// fork. Everything is decrypted on this device; the server sees ciphertext only (vault.ts, crypto.ts).
import { useCallback, useEffect, useRef, useState } from 'react';
import { useAuth } from '@/lib/auth';
import { Modal } from '@/components/ConfirmDialog';
import { OnBody } from '@/components/ui';
import { useToast } from '@/components/Toast';
import * as V from './vault';
import { imageEntries, imageType, zipEntries, zipRead } from './zip';

const PASSPHRASE_MIN = 10;

type Phase = { kind: 'loading' } | { kind: 'error'; message: string } | { kind: 'setup' } | { kind: 'locked'; keys: V.KeysDoc } | { kind: 'open' };

const msg = (e: unknown): string => {
  const code = V.errorCode(e);
  if (code) return code.replace(/_/g, ' ');
  const m = (e as Error)?.message || String(e);
  return m === 'wrong_passphrase' ? 'That passphrase does not unlock this vault.' : m;
};
const bytes = (n: number): string => (n < 1024 ? `${n} B` : n < 1024 ** 2 ? `${(n / 1024).toFixed(0)} KB` : n < 1024 ** 3 ? `${(n / 1024 ** 2).toFixed(1)} MB` : `${(n / 1024 ** 3).toFixed(2)} GB`);

export default function VaultPage() {
  const { user } = useAuth();
  const userId = user?.id;
  const [phase, setPhase] = useState<Phase>({ kind: 'loading' });

  const load = useCallback(async () => {
    if (!userId) return;
    if (V.unlockedFor(userId)) return setPhase({ kind: 'open' });
    V.lock();
    try {
      const keys = await V.fetchKeys();
      setPhase(keys ? { kind: 'locked', keys } : { kind: 'setup' });
    } catch (e) { setPhase({ kind: 'error', message: msg(e) }); }
  }, [userId]);
  useEffect(() => { void load(); }, [load]);

  return (
    <div className="min-h-screen-d px-4 pb-24 lg:px-0">
      <header className="safe-top flex items-center gap-3 pb-2 pt-2 lg:pt-6">
        <div className="min-w-0">
          <h1 className="font-display text-2xl font-bold lg:text-3xl">Private libraries</h1>
          <p className="mt-0.5 text-xs text-fog-500">End-to-end encrypted. Files are encrypted on this device before upload; the server cannot read them.</p>
        </div>
        {phase.kind === 'open' && (
          <button className="btn-key ms-auto shrink-0 px-3 text-sm" onClick={() => { V.lock(); void load(); }}>Lock</button>
        )}
      </header>
      {!userId || phase.kind === 'loading' ? <div className="skeleton mt-4 h-40 rounded-2xl" />
        : phase.kind === 'error' ? <p className="mt-6 text-sm text-red-400">{phase.message}</p>
        : phase.kind === 'setup' ? <SetupForm userId={userId} onDone={() => setPhase({ kind: 'open' })} />
        : phase.kind === 'locked' ? <UnlockForm userId={userId} keys={phase.keys} onDone={() => setPhase({ kind: 'open' })} onReset={load} />
        : <Libraries userId={userId} onReset={load} />}
    </div>
  );
}

// ── Setup / unlock ─────────────────────────────────────────────────────────────────────────────────────────────

function SetupForm({ userId, onDone }: { userId: string; onDone: () => void }) {
  const [p1, setP1] = useState('');
  const [p2, setP2] = useState('');
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const ok = p1.length >= PASSPHRASE_MIN && p1 === p2;
  const submit = async () => {
    if (!ok || busy) return;
    setBusy(true); setErr(null);
    try { await V.setupVault(userId, p1); onDone(); } catch (e) { setErr(msg(e)); } finally { setBusy(false); }
  };
  return (
    <section className="mt-4 max-w-lg rounded-2xl border border-ink-700 bg-ink-850 p-5">
      <h2 className="font-display text-lg font-semibold">Set up your vault</h2>
      <p className="mt-1 text-sm text-fog-400">
        Choose a vault passphrase. It never leaves this device: it unlocks your private key, which opens your private libraries.
      </p>
      <p className="mt-2 text-sm text-amber-300">
        Nobody can recover it, not even the server admin. Lose it and your private libraries are gone for good.
      </p>
      <input type="password" autoComplete="new-password" className="field mt-4 max-w-none" placeholder={`Passphrase (at least ${PASSPHRASE_MIN} characters)`} value={p1} onChange={(e) => setP1(e.target.value)} />
      <input type="password" autoComplete="new-password" className="field mt-2 max-w-none" placeholder="Repeat passphrase" value={p2} onChange={(e) => setP2(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && submit()} />
      {p2 && p1 !== p2 && <p className="mt-2 text-xs text-red-400">The passphrases differ.</p>}
      {err && <p className="mt-2 text-xs text-red-400">{err}</p>}
      <button className="btn-accent mt-4 w-full py-2.5 text-sm disabled:opacity-50" disabled={!ok || busy} onClick={submit}>{busy ? 'Creating keys…' : 'Create vault'}</button>
    </section>
  );
}

function UnlockForm({ userId, keys, onDone, onReset }: { userId: string; keys: V.KeysDoc; onDone: () => void; onReset: () => void }) {
  const [p, setP] = useState('');
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [resetting, setResetting] = useState(false);
  const submit = async () => {
    if (!p || busy) return;
    setBusy(true); setErr(null);
    try { await V.unlockVault(userId, p, keys); onDone(); } catch (e) { setErr(msg(e)); } finally { setBusy(false); }
  };
  return (
    <section className="mt-4 max-w-lg rounded-2xl border border-ink-700 bg-ink-850 p-5">
      <h2 className="font-display text-lg font-semibold">Unlock your vault</h2>
      <input type="password" autoComplete="current-password" autoFocus className="field mt-4 max-w-none" placeholder="Vault passphrase" value={p} onChange={(e) => setP(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && submit()} />
      {err && <p className="mt-2 text-xs text-red-400">{err}</p>}
      <button className="btn-accent mt-4 w-full py-2.5 text-sm disabled:opacity-50" disabled={!p || busy} onClick={submit}>{busy ? 'Unlocking…' : 'Unlock'}</button>
      <button className="mt-4 text-xs text-fog-500 underline hover:text-fog-300" onClick={() => setResetting(true)}>Forgot the passphrase?</button>
      {resetting && <ResetDialog onClose={() => setResetting(false)} onDone={onReset} />}
    </section>
  );
}

function ResetDialog({ onClose, onDone }: { onClose: () => void; onDone: () => void }) {
  const [typed, setTyped] = useState('');
  const [busy, setBusy] = useState(false);
  const toast = useToast();
  return (
    <Modal title="Reset vault" onClose={onClose}>
      <p className="text-sm text-fog-300">
        This deletes your key pair and every private library you own, with all its files. You leave the libraries others shared
        with you. It cannot be undone.
      </p>
      <p className="mt-3 text-xs text-fog-500">Type RESET to confirm.</p>
      <input className="field mt-1 max-w-none" value={typed} onChange={(e) => setTyped(e.target.value)} />
      <button className="btn-accent mt-4 w-full bg-red-600 py-2.5 text-sm disabled:opacity-50" disabled={typed !== 'RESET' || busy}
        onClick={async () => {
          setBusy(true);
          try { await V.resetVault(); onClose(); onDone(); } catch (e) { toast(msg(e), 'error'); } finally { setBusy(false); }
        }}>Delete everything</button>
    </Modal>
  );
}

// ── Library list ───────────────────────────────────────────────────────────────────────────────────────────────

function Libraries({ userId, onReset }: { userId: string; onReset: () => void }) {
  const [libs, setLibs] = useState<Array<V.OpenLibrary | { id: string; error: string }> | null>(null);
  const [open, setOpen] = useState<V.OpenLibrary | null>(null);
  const [creating, setCreating] = useState(false);
  const [settings, setSettings] = useState(false);
  const [fp, setFp] = useState('');
  const toast = useToast();
  const reload = useCallback(async () => {
    try { setLibs(await V.listLibraries()); } catch (e) { toast(msg(e), 'error'); setLibs([]); }
  }, [toast]);
  useEffect(() => { void reload(); V.myFingerprint().then(setFp).catch(() => {}); }, [reload]);

  if (open) return <LibraryView userId={userId} lib={open} onBack={() => { setOpen(null); void reload(); }} />;

  return (
    <>
      <div className="mt-4 flex items-center gap-2">
        <button className="btn-accent px-3.5 py-2 text-sm" onClick={() => setCreating(true)}>New private library</button>
        <button className="btn-key ms-auto px-3 text-sm" onClick={() => setSettings(true)}>Vault settings</button>
      </div>
      {fp && <p className="mt-2 text-2xs text-fog-500">Your key fingerprint: <span className="font-mono text-fog-300">{fp}</span></p>}
      {!libs ? <div className="skeleton mt-4 h-32 rounded-2xl" />
        : libs.length === 0 ? <p className="mt-8 text-sm text-fog-400">No private libraries yet. Create one, then add CBZ, images or any file to it.</p>
        : (
          <div className="mt-4 grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
            {libs.map((l) => 'error' in l ? (
              <div key={l.id} className="rounded-2xl border border-red-900/60 bg-ink-850 p-4 text-sm text-red-300">A library that cannot be opened ({l.error}).</div>
            ) : (
              <button key={l.id} onClick={() => setOpen(l)} className="rounded-2xl border border-ink-700 bg-ink-850 p-4 text-start transition hover:border-ink-500">
                <div className="font-display text-base font-semibold text-fog-100">{l.meta.name}</div>
                {l.meta.description && <div className="mt-0.5 line-clamp-2 text-xs text-fog-400">{l.meta.description}</div>}
                <div className="mt-2 text-2xs text-fog-500">{l.items} file{l.items === 1 ? '' : 's'} · {l.role}{l.ownerId !== userId ? ' · shared with you' : ''}</div>
              </button>
            ))}
          </div>
        )}
      {creating && <LibraryForm title="New private library" onClose={() => setCreating(false)}
        onSave={async (meta) => { const l = await V.createLibrary(meta); setCreating(false); setOpen(l); }} />}
      {settings && <SettingsDialog userId={userId} onClose={() => setSettings(false)} onReset={onReset} />}
    </>
  );
}

function LibraryForm({ title, initial, onClose, onSave }: { title: string; initial?: V.LibraryMeta; onClose: () => void; onSave: (m: V.LibraryMeta) => Promise<void> }) {
  const [name, setName] = useState(initial?.name ?? '');
  const [description, setDescription] = useState(initial?.description ?? '');
  const [busy, setBusy] = useState(false);
  const toast = useToast();
  const save = async () => {
    if (!name.trim() || busy) return;
    setBusy(true);
    try { await onSave({ name: name.trim(), ...(description.trim() ? { description: description.trim() } : {}) }); } catch (e) { toast(msg(e), 'error'); } finally { setBusy(false); }
  };
  return (
    <Modal title={title} onClose={onClose}>
      <input className="field max-w-none" autoFocus placeholder="Name" value={name} onChange={(e) => setName(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && save()} />
      <input className="field mt-2 max-w-none" placeholder="Description (optional)" value={description} onChange={(e) => setDescription(e.target.value)} />
      <p className="mt-2 text-2xs text-fog-500">The name and description are encrypted too.</p>
      <button className="btn-accent mt-4 w-full py-2.5 text-sm disabled:opacity-50" disabled={!name.trim() || busy} onClick={save}>Save</button>
    </Modal>
  );
}

function SettingsDialog({ userId, onClose, onReset }: { userId: string; onClose: () => void; onReset: () => void }) {
  const [oldP, setOldP] = useState('');
  const [p1, setP1] = useState('');
  const [p2, setP2] = useState('');
  const [busy, setBusy] = useState(false);
  const [resetting, setResetting] = useState(false);
  const toast = useToast();
  const ok = oldP && p1.length >= PASSPHRASE_MIN && p1 === p2;
  return (
    <Modal title="Vault settings" onClose={onClose}>
      <h3 className="text-sm font-semibold text-fog-100">Change passphrase</h3>
      <p className="mt-1 text-xs text-fog-500">Re-encrypts your private key under the new passphrase. Your libraries are not touched.</p>
      <input type="password" autoComplete="current-password" className="field mt-3 max-w-none" placeholder="Current passphrase" value={oldP} onChange={(e) => setOldP(e.target.value)} />
      <input type="password" autoComplete="new-password" className="field mt-2 max-w-none" placeholder={`New passphrase (at least ${PASSPHRASE_MIN} characters)`} value={p1} onChange={(e) => setP1(e.target.value)} />
      <input type="password" autoComplete="new-password" className="field mt-2 max-w-none" placeholder="Repeat new passphrase" value={p2} onChange={(e) => setP2(e.target.value)} />
      <button className="btn-accent mt-3 w-full py-2.5 text-sm disabled:opacity-50" disabled={!ok || busy}
        onClick={async () => {
          setBusy(true);
          try { await V.changePassphrase(userId, oldP, p1); toast('Passphrase changed', 'success'); onClose(); } catch (e) { toast(msg(e), 'error'); } finally { setBusy(false); }
        }}>Change passphrase</button>
      <h3 className="mt-6 text-sm font-semibold text-red-300">Reset vault</h3>
      <p className="mt-1 text-xs text-fog-500">Deletes your keys and every private library you own.</p>
      <button className="btn-key btn-key-danger mt-2 px-3 text-sm" onClick={() => setResetting(true)}>Reset vault…</button>
      {resetting && <ResetDialog onClose={() => setResetting(false)} onDone={() => { onClose(); onReset(); }} />}
    </Modal>
  );
}

// ── One library ────────────────────────────────────────────────────────────────────────────────────────────────

function LibraryView({ userId, lib: initial, onBack }: { userId: string; lib: V.OpenLibrary; onBack: () => void }) {
  const [lib, setLib] = useState(initial);
  const [items, setItems] = useState<V.OpenItem[] | null>(null);
  const [uploads, setUploads] = useState<Array<{ name: string; progress: number }>>([]);
  const [reading, setReading] = useState<V.OpenItem | null>(null);
  const [members, setMembers] = useState(false);
  const [editing, setEditing] = useState(false);
  const fileInput = useRef<HTMLInputElement>(null);
  const toast = useToast();
  const canEdit = lib.role !== 'reader';

  const reload = useCallback(async () => {
    try {
      const fresh = await V.getLibrary(lib.id);
      setLib(fresh);
      setItems(await V.listItems(fresh));
    } catch (e) { toast(msg(e), 'error'); setItems([]); }
  }, [lib.id, toast]);
  useEffect(() => { void reload(); }, [reload]);

  const upload = async (files: FileList | null) => {
    if (!files?.length) return;
    const list = [...files];
    setUploads(list.map((f) => ({ name: f.name, progress: 0 })));
    for (let i = 0; i < list.length; i++) {
      try {
        await V.uploadFile(lib, list[i], (p) => setUploads((u) => u.map((x, j) => (j === i ? { ...x, progress: p } : x))));
      } catch (e) { toast(`${list[i].name}: ${msg(e)}`, 'error'); }
    }
    setUploads([]);
    void reload();
  };

  const download = async (item: V.OpenItem) => {
    try {
      const blob = await V.downloadItem(lib, item);
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url; a.download = item.meta?.name || 'file';
      a.click();
      setTimeout(() => URL.revokeObjectURL(url), 30_000);
    } catch (e) { toast(msg(e), 'error'); }
  };

  return (
    <>
      <div className="mt-4 flex flex-wrap items-center gap-2">
        <button className="btn-key px-3 text-sm" onClick={onBack}>← All libraries</button>
        <h2 className="min-w-0 truncate font-display text-xl font-semibold">{lib.meta.name}</h2>
        <span className="text-2xs text-fog-500">{lib.role}</span>
        <div className="ms-auto flex gap-2">
          {canEdit && <button className="btn-accent px-3.5 py-2 text-sm" onClick={() => fileInput.current?.click()}>Add files</button>}
          <button className="btn-key px-3 text-sm" onClick={() => setMembers(true)}>Members</button>
          {canEdit && <button className="btn-key px-3 text-sm" onClick={() => setEditing(true)}>Rename</button>}
          {lib.role === 'owner' && (
            <button className="btn-key btn-key-danger px-3 text-sm" onClick={async () => {
              if (!window.confirm(`Delete “${lib.meta.name}” and every file in it? This cannot be undone.`)) return;
              try { await V.deleteLibrary(lib.id); onBack(); } catch (e) { toast(msg(e), 'error'); }
            }}>Delete</button>
          )}
        </div>
      </div>
      {lib.meta.description && <p className="mt-1 text-sm text-fog-400">{lib.meta.description}</p>}
      <input ref={fileInput} type="file" multiple hidden onChange={(e) => { void upload(e.target.files); e.target.value = ''; }} />

      {uploads.length > 0 && (
        <div className="mt-4 space-y-2 rounded-2xl border border-ink-700 bg-ink-850 p-3">
          {uploads.map((u, i) => (
            <div key={i} className="text-xs text-fog-300">
              <div className="flex justify-between"><span className="truncate">Encrypting and uploading {u.name}</span><span>{Math.round(u.progress * 100)}%</span></div>
              <div className="mt-1 h-1 overflow-hidden rounded bg-ink-700"><div className="h-full bg-accent" style={{ width: `${u.progress * 100}%` }} /></div>
            </div>
          ))}
        </div>
      )}

      {!items ? <div className="skeleton mt-4 h-32 rounded-2xl" />
        : items.length === 0 ? <p className="mt-8 text-sm text-fog-400">{canEdit ? 'Empty. Add CBZ files, images or anything else; they are encrypted before they leave this device.' : 'Nothing here yet.'}</p>
        : (
          <ul className="mt-4 divide-y divide-ink-700 rounded-2xl border border-ink-700 bg-ink-850">
            {items.map((it) => (
              <li key={it.id} className="flex items-center gap-3 px-4 py-3">
                <button className="min-w-0 flex-1 text-start" disabled={!it.meta || it.state !== 'ready'} onClick={() => setReading(it)}>
                  <div className="truncate text-sm text-fog-100">{it.meta?.name ?? 'Unreadable file'}</div>
                  <div className="text-2xs text-fog-500">
                    {it.meta ? bytes(it.meta.size) : ''}{it.state === 'pending' ? ' · upload unfinished' : ''} · {new Date(it.createdAt).toLocaleDateString()}
                  </div>
                </button>
                {it.state === 'ready' && it.meta && <button className="btn-key px-3 text-xs" onClick={() => download(it)}>Save</button>}
                {canEdit && it.meta && it.state === 'ready' && (
                  <button className="btn-key px-3 text-xs" onClick={async () => {
                    const name = window.prompt('New name', it.meta!.name)?.trim();
                    if (!name) return;
                    try { await V.renameItem(lib, it, name); void reload(); } catch (e) { toast(msg(e), 'error'); }
                  }}>Rename</button>
                )}
                {canEdit && (
                  <button className="btn-key btn-key-danger px-3 text-xs" onClick={async () => {
                    if (!window.confirm(`Delete “${it.meta?.name ?? 'this file'}”?`)) return;
                    try { await V.deleteItem(it.id); void reload(); } catch (e) { toast(msg(e), 'error'); }
                  }}>Delete</button>
                )}
              </li>
            ))}
          </ul>
        )}

      {reading && <Reader lib={lib} item={reading} onClose={() => setReading(null)} onSave={() => download(reading)} />}
      {members && <MembersDialog userId={userId} lib={lib} onClose={() => { setMembers(false); void reload(); }} onLeft={onBack} />}
      {editing && <LibraryForm title="Rename library" initial={lib.meta} onClose={() => setEditing(false)}
        onSave={async (meta) => { await V.renameLibrary(lib, meta); setEditing(false); void reload(); }} />}
    </>
  );
}

// ── Members ────────────────────────────────────────────────────────────────────────────────────────────────────

function MembersDialog({ userId, lib, onClose, onLeft }: { userId: string; lib: V.OpenLibrary; onClose: () => void; onLeft: () => void }) {
  const [rows, setRows] = useState<V.MemberRow[] | null>(null);
  const [username, setUsername] = useState('');
  const [role, setRole] = useState<'reader' | 'editor'>('reader');
  const [found, setFound] = useState<(V.UserKey & { fingerprint: string }) | null>(null);
  const [busy, setBusy] = useState(false);
  const toast = useToast();
  const owner = lib.role === 'owner';
  const reload = useCallback(() => V.listMembers(lib.id).then(setRows).catch((e) => toast(msg(e), 'error')), [lib.id, toast]);
  useEffect(() => { void reload(); }, [reload]);

  const run = async (fn: () => Promise<void>) => {
    setBusy(true);
    try { await fn(); } catch (e) { toast(msg(e), 'error'); } finally { setBusy(false); }
  };

  return (
    <Modal title="Members" onClose={onClose} wide>
      {!rows ? <div className="skeleton h-20 rounded-xl" /> : (
        <ul className="divide-y divide-ink-700">
          {rows.map((m) => (
            <li key={m.userId} className="flex items-center gap-2 py-2 text-sm">
              <span className="min-w-0 flex-1 truncate">{m.displayName}{m.username ? <span className="text-fog-500"> @{m.username}</span> : null}</span>
              <span className="text-2xs text-fog-500">{m.role}</span>
              {owner && m.role !== 'owner' && (
                <button className="btn-key btn-key-danger px-2 text-xs" disabled={busy} onClick={() => run(async () => {
                  await V.removeMember(lib.id, m.userId, true);
                  toast('Removed, and the library key was rotated', 'success');
                  await reload();
                })}>Remove</button>
              )}
              {!owner && m.userId === userId && (
                <button className="btn-key btn-key-danger px-2 text-xs" disabled={busy} onClick={() => run(async () => {
                  if (!window.confirm('Leave this library? You will need to be invited again.')) return;
                  await V.removeMember(lib.id, userId, false);
                  onLeft();
                })}>Leave</button>
              )}
            </li>
          ))}
        </ul>
      )}
      {owner && (
        <div className="mt-5 border-t border-ink-700 pt-4">
          <h3 className="text-sm font-semibold text-fog-100">Share with someone</h3>
          <p className="mt-1 text-xs text-fog-500">They need to have set up their own vault. The library key is encrypted to their public key on this device.</p>
          <div className="mt-2 flex gap-2">
            <input className="field max-w-none flex-1" placeholder="Username" value={username} onChange={(e) => { setUsername(e.target.value); setFound(null); }} />
            <select className="field w-28" value={role} onChange={(e) => setRole(e.target.value as 'reader' | 'editor')}>
              <option value="reader">Reader</option>
              <option value="editor">Editor</option>
            </select>
            <button className="btn-key px-3 text-sm" disabled={!username.trim() || busy} onClick={() => run(async () => {
              try { setFound(await V.lookupUser(username)); } catch (e) {
                throw V.errorCode(e) === 'not_found' ? new Error('No account with that username has set up a vault.') : e;
              }
            })}>Find</button>
          </div>
          {found && (
            <div className="mt-3 rounded-xl border border-ink-700 p-3 text-sm">
              <div>{found.displayName} <span className="text-fog-500">@{found.username}</span></div>
              <div className="mt-1 text-2xs text-fog-500">Key fingerprint: <span className="font-mono text-fog-300">{found.fingerprint}</span></div>
              <p className="mt-1 text-2xs text-fog-500">Check it with them (it shows on their vault page) to be sure the key is theirs.</p>
              <button className="btn-accent mt-2 px-3.5 py-2 text-sm" disabled={busy || found.userId === userId} onClick={() => run(async () => {
                await V.shareWith(lib.id, found, role);
                setFound(null); setUsername('');
                await reload();
              })}>Share as {role}</button>
            </div>
          )}
        </div>
      )}
    </Modal>
  );
}

// ── Reader ─────────────────────────────────────────────────────────────────────────────────────────────────────

const isArchive = (m: V.ItemMeta) => /zip|comicbook/.test(m.type) || /\.(cbz|zip)$/i.test(m.name);

function Reader({ lib, item, onClose, onSave }: { lib: V.OpenLibrary; item: V.OpenItem; onClose: () => void; onSave: () => void }) {
  const [progress, setProgress] = useState(0);
  const [pages, setPages] = useState<string[] | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [other, setOther] = useState(false);

  useEffect(() => {
    let dead = false;
    const urls: string[] = [];
    (async () => {
      const meta = item.meta!;
      if (!meta.type.startsWith('image/') && !isArchive(meta)) { setOther(true); return; }
      const blob = await V.downloadItem(lib, item, (p) => !dead && setProgress(p));
      if (meta.type.startsWith('image/')) { urls.push(URL.createObjectURL(blob)); }
      else {
        const buf = new Uint8Array(await blob.arrayBuffer());
        for (const e of imageEntries(zipEntries(buf))) {
          if (dead) return;
          urls.push(URL.createObjectURL(new Blob([await zipRead(buf, e)], { type: imageType(e.name) })));
        }
        if (!urls.length) throw new Error('No images in this archive.');
      }
      if (!dead) setPages([...urls]);
    })().catch((e) => !dead && setErr(msg(e)));
    return () => { dead = true; urls.forEach((u) => URL.revokeObjectURL(u)); };
  }, [lib, item]);

  return (
    // On <body>: the page sits in a stacking context, under the top bar, and an overlay inside it would too.
    // data-lenis-prevent: the app's smooth scroller would otherwise scroll the page behind instead of the pages.
    <OnBody>
    <div className="fixed inset-0 z-[80] overflow-y-auto bg-black" role="dialog" aria-label={item.meta?.name} data-lenis-prevent>
      <div className="sticky top-0 z-10 flex items-center gap-2 bg-black/80 px-3 py-2 backdrop-blur">
        <span className="min-w-0 flex-1 truncate text-sm text-fog-200">{item.meta?.name}</span>
        <button className="btn-key px-3 text-xs" onClick={onSave}>Save decrypted</button>
        <button className="btn-key px-3 text-xs" onClick={onClose}>Close</button>
      </div>
      {err ? <p className="p-6 text-sm text-red-400">{err}</p>
        : other ? <p className="p-6 text-sm text-fog-300">This file type is not shown here. Use “Save decrypted” to open it on this device.</p>
        : !pages ? <p className="p-6 text-sm text-fog-400">Decrypting… {Math.round(progress * 100)}%</p>
        : (
          <div className="mx-auto flex max-w-3xl flex-col">
            {pages.map((src, i) => <img key={i} src={src} alt={`Page ${i + 1}`} className="w-full" loading="lazy" />)}
          </div>
        )}
    </div>
    </OnBody>
  );
}
