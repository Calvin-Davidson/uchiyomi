'use client';
import Link from 'next/link';
import { useEffect, useRef, useState } from 'react';
import { useAuth } from '@/lib/auth';
import { api, getCurrentUser } from '@/lib/api';
import { useQueryClient } from '@tanstack/react-query';
import { deviceId } from '@/lib/device';
import { incognitoRef } from '@/lib/incognito';
import { remoteDigest, resumeRemotePage } from '@/lib/remoteReading';
import { cloudProvider, connectionKey, deviceProvider, parseConnections, type ProviderKind, type RemoteConnection, type RemoteEntry, type RemoteProvider } from '@/lib/remoteLibrary';
import { devicePages } from '@/lib/remoteArchive';

const names: Record<ProviderKind, string> = { device: 'Device file provider / synced folder', 'google-drive': 'Google Drive', dropbox: 'Dropbox' };
const field = 'w-full rounded-lg border border-ink-700 bg-ink-900 p-3';

export default function RemoteLibraryPage() {
  const { user, status } = useAuth();
  if (!user || status !== 'authed') return <p className="p-6">Sign in to open your remote libraries.</p>;
  return <RemoteLibraries key={user.id} owner={user.id} />;
}

function RemoteLibraries({ owner }: { owner: string }) {
  const queries = useQueryClient();
  const [reading, setReading] = useState<{digest:string;title:string;seriesTitle:string} | null>(null);
  const [syncStatus, setSyncStatus] = useState('');
  const queue = useRef(Promise.resolve());
  const failed = useRef<Array<() => Promise<void>>>([]);
  const lastTurn = useRef('');
  const [connections, setConnections] = useState<RemoteConnection[]>([]);
  const [provider, setProvider] = useState<ProviderKind>('device');
  const [name, setName] = useState(''), [root, setRoot] = useState(''), [token, setToken] = useState('');
  const [reconnect, setReconnect] = useState<string | null>(null);
  const [active, setActive] = useState<RemoteConnection | null>(null);
  const [entries, setEntries] = useState<RemoteEntry[]>([]);
  const [trail, setTrail] = useState<{ id: string; name: string }[]>([]);
  const [pages, setPages] = useState<{ name: string; url: string }[]>([]);
  const [book, setBook] = useState(''), [page, setPage] = useState(0);
  const [busy, setBusy] = useState(false), [error, setError] = useState('');
  const adapter = useRef<RemoteProvider | null>(null), operation = useRef<AbortController | null>(null);
  const urls = useRef<string[]>([]), mounted = useRef(true);
  const fileInput = useRef<HTMLInputElement>(null), folderInput = useRef<HTMLInputElement>(null);
  function revokePages() { for (const url of urls.current) URL.revokeObjectURL(url); urls.current = []; }
  function lock() {
    operation.current?.abort(); adapter.current = null; revokePages();
    setPages([]); setEntries([]); setActive(null); setTrail([]); setToken(''); setBusy(false); setBook('');
    setReading(null); lastTurn.current = '';
  }
  useEffect(() => {
    mounted.current = true;
    try { setConnections(parseConnections(localStorage.getItem(connectionKey(owner)))); }
    catch { setError('Device storage is unavailable. Connections will last for this visit only.'); }
    const changed = () => lock();
    window.addEventListener('yomi-account-changed', changed);
    return () => {
      mounted.current = false; operation.current?.abort(); adapter.current = null; revokePages();
      window.removeEventListener('yomi-account-changed', changed);
    };
  }, [owner]);
  function save(next: RemoteConnection[]) {
    if (getCurrentUser() !== owner) return;
    setConnections(next);
    try { localStorage.setItem(connectionKey(owner), JSON.stringify(next)); }
    catch { setError('Could not remember this connection on this device.'); }
  }
  async function run(work: (signal: AbortSignal, current: () => boolean) => Promise<void>) {
    operation.current?.abort();
    const controller = new AbortController(); operation.current = controller;
    const current = () => mounted.current && !controller.signal.aborted && getCurrentUser() === owner;
    if (!current()) return;
    setBusy(true); setError('');
    try { await work(controller.signal, current); }
    catch (e) { if (current()) setError(e instanceof Error ? e.message : 'Could not open the library.'); }
    finally { if (current()) setBusy(false); }
  }
  function connect(files?: File[]) {
    const config: RemoteConnection = { id: reconnect || crypto.randomUUID(), name: name.trim() || names[provider], provider, root: provider === 'device' ? '' : root.trim() || (provider === 'google-drive' ? 'root' : '') };
    if (!reconnect && connections.length >= 30) { setError('Remove a connection before adding another (maximum 30).'); return; }
    const secret = token; setToken('');
    void run(async (signal, current) => {
      const nextAdapter = provider === 'device' ? deviceProvider(files || []) : cloudProvider(provider, secret);
      const listing = await nextAdapter.list(config.root, signal);
      if (!current()) return;
      revokePages(); setPages([]); setBook(''); adapter.current = nextAdapter;
      setActive(config); setEntries(listing); setTrail([{ id: config.root, name: config.name }]);
      save([...connections.filter(c => c.id !== config.id), config]); setReconnect(null);
    });
  }
  function browse(entry: RemoteEntry, backIndex?: number) {
    const source = adapter.current;
    if (!source) return;
    void run(async (signal, current) => {
      if (entry.folder) {
        const listing = await source.list(entry.id, signal);
        if (!current()) return;
        setEntries(listing); setTrail(backIndex === undefined ? [...trail, entry] : trail.slice(0, backIndex + 1));
      } else {
        const file = await source.read(entry.id, signal);
        if (!current()) return;
        const digest = await remoteDigest(file);
        if (!current()) return;
        const position = await api<{page:number;completed:boolean}>(`/api/personal/remote-books/${digest}/progress`, {signal,expectedOwnerId:owner});
        if (!current()) return;
        const decoded = await devicePages(file, entry.name, signal);
        if (!current()) return;
        revokePages();
        const nextPages = decoded.map(p => ({ name: p.name, url: URL.createObjectURL(p.blob) }));
        urls.current = nextPages.map(p => p.url); setPages(nextPages); setPage(resumeRemotePage(position.page,decoded.length)); setBook(entry.name);
        setReading({digest,title:entry.name,seriesTitle:trail.at(-1)?.name || active?.name || 'Remote library'}); lastTurn.current = '';
      }
    });
  }
  // Record only a successfully displayed page, not a failed decode or a rapid turn past an unloaded image.
  function recordPage() {
    if (!reading || getCurrentUser() !== owner) return;
    const turn = `${reading.digest}:${page}`;
    if (lastTurn.current === turn) return;
    lastTurn.current = turn;
    const payload = {...reading,page:page+1,pages:pages.length,eventId:crypto.randomUUID(),at:Date.now(),deviceId:deviceId(),incognito:incognitoRef.current};
    const {digest,...json} = payload;
    const send = async () => {
      await api(`/api/personal/remote-books/${digest}/progress`,{method:'PUT',json,expectedOwnerId:owner});
      if (mounted.current && getCurrentUser() === owner) {
        void queries.invalidateQueries({queryKey:['history']});
        void queries.invalidateQueries({predicate:q=>typeof q.queryKey[0]==='string' && q.queryKey[0].startsWith('stats')});
      }
    };
    setSyncStatus('Saving reading progress…');
    queue.current = queue.current.then(async () => {
      try { await send(); }
      catch { if (getCurrentUser() === owner) failed.current.push(send); }
      if (mounted.current && getCurrentUser() === owner) setSyncStatus(failed.current.length ? 'Progress could not sync. Retry before leaving this page.' : 'Reading progress saved');
    });
  }
  function retryProgress() {
    const pending = failed.current.splice(0);
    setSyncStatus('Saving reading progress…');
    queue.current = queue.current.then(async () => {
      for (const send of pending) try { await send(); } catch { if (getCurrentUser() === owner) failed.current.push(send); }
      if (mounted.current && getCurrentUser() === owner) setSyncStatus(failed.current.length ? 'Progress could not sync. Retry before leaving this page.' : 'Reading progress saved');
    });
  }
  return <main className="mx-auto max-w-5xl space-y-6 p-4 pb-28 lg:p-8">
    <Link href="/library/" className="text-accent">← Library</Link>
    <h1 className="font-display text-3xl font-bold">Remote libraries</h1>
    <p className="text-fog-300">Files, encryption keys, and provider credentials stay on your device. Uchiyomi syncs book and folder titles, reading position, completion, and activity to your account for history and statistics. Incognito keeps your place without recording activity.</p>
    <p className="text-sm text-fog-400">Connections are remembered for your account in this browser only. Credentials and selected files last only until you lock or leave this page. This is separate from the shared library, downloads, and trackers.</p>
    {error && <p role="alert" className="rounded-xl border border-red-400 p-3">{error}</p>}
    {syncStatus && <p role="status">{syncStatus} {failed.current.length > 0 && <button className="btn-key" onClick={retryProgress}>Retry progress sync</button>}</p>}
    {busy && <p role="status">Opening on this device… <button className="btn-key" onClick={() => { operation.current?.abort(); setBusy(false); }}>Cancel</button></p>}
    {!!connections.length && <section aria-label="Saved connections" className="space-y-2">{connections.map(c => <div key={c.id} className="flex flex-wrap items-center gap-3 rounded-xl border border-ink-700 p-3">
      <span className="min-w-0 flex-1 break-words">{c.name} <small className="text-fog-400">{names[c.provider]}</small></span>
      <button className="btn-key" disabled={busy} onClick={() => { lock(); setProvider(c.provider); setName(c.name); setRoot(c.root); setReconnect(c.id); }}>Reconnect</button>
      <button className="btn-key" disabled={busy} onClick={() => { if (active?.id === c.id) lock(); if (reconnect === c.id) setReconnect(null); save(connections.filter(item => item.id !== c.id)); }}>Forget</button>
    </div>)}</section>}
    {!active && <section className="space-y-4 rounded-2xl border border-ink-700 p-5" aria-label="Connect library">
      <h2 className="text-xl font-semibold">{reconnect ? 'Reconnect library' : 'Connect a library'}</h2>
      <label className="block">Library name<input className={field} value={name} maxLength={120} onChange={e => setName(e.target.value)} placeholder="My manga" /></label>
      <label className="block">Connection<select className={field} value={provider} onChange={e => { setProvider(e.target.value as ProviderKind); setRoot(''); setToken(''); setReconnect(null); }}>
        {Object.entries(names).map(([id, label]) => <option key={id} value={id}>{label}</option>)}
      </select></label>
      {provider === 'device' ? <>
        <p>For Proton Drive, use its app to make your library available on this device, then select the synced folder or choose files from your device’s file picker. Proton’s client handles decryption locally. The same setup works with Google Drive, Dropbox, and other file providers.</p>
        <p className="text-sm text-fog-400">This is device-file access, not a direct Proton account connection. Make online-only files available locally first. Folder selection depends on your browser; selecting files is the fallback.</p>
        <input ref={fileInput} type="file" multiple accept=".cbz,.zip,.png,.jpg,.jpeg,.webp,.gif,.avif" hidden onChange={e => { if (e.target.files?.length) connect(Array.from(e.target.files)); e.target.value = ''; }} />
        <input ref={folderInput} type="file" multiple {...{ webkitdirectory: '' }} hidden onChange={e => { if (e.target.files?.length) connect(Array.from(e.target.files)); e.target.value = ''; }} />
        <div className="flex flex-wrap gap-3"><button disabled={busy} className="btn-key" onClick={() => folderInput.current?.click()}>Choose synced folder</button><button disabled={busy} className="btn-key" onClick={() => fileInput.current?.click()}>Choose files</button></div>
      </> : <form className="space-y-4" onSubmit={e => { e.preventDefault(); connect(); }}>
        <p>Advanced connection: supply a short-lived OAuth access token from your own provider application with read access. Requests go directly to {names[provider]}. Reconnect when the token expires. This does not add end-to-end encryption to ordinary cloud files.</p>
        <label className="block">{provider === 'google-drive' ? 'Folder ID (blank for root)' : 'Folder path (blank for root)'}<input className={field} value={root} maxLength={2048} onChange={e => setRoot(e.target.value)} /></label>
        <label className="block">Access token<input className={field} type="password" autoComplete="off" spellCheck={false} value={token} onChange={e => setToken(e.target.value)} required /></label>
        <button disabled={busy} className="btn-key" type="submit">Connect read-only</button>
      </form>}
      {reconnect && <button className="btn-key" onClick={() => { setReconnect(null); setName(''); setRoot(''); setToken(''); }}>Add a different library</button>}
    </section>}
    {active && <section className="space-y-4" aria-label="Remote files">
      <div className="flex flex-wrap items-center justify-between gap-3"><h2 className="text-xl font-semibold">{active.name}</h2><button className="btn-key" onClick={lock}>Lock library</button></div>
      {pages.length ? <>
        <div className="flex flex-wrap items-center gap-3">
          <button className="btn-key" onClick={() => { revokePages(); setPages([]); setBook(''); }}>Close book</button><span className="break-all">{book}</span>
          <button className="btn-key" disabled={page === 0} onClick={() => setPage(p => p - 1)}>Previous</button><span aria-live="polite">{page + 1} / {pages.length}</span>
          <button className="btn-key" disabled={page === pages.length - 1} onClick={() => setPage(p => p + 1)}>Next</button>
        </div><img key={pages[page].url} src={pages[page].url} alt={`Page ${page + 1}`} className="mx-auto max-w-full" onLoad={recordPage} onError={() => setError('This image could not be displayed. Reading progress was not advanced.')} />
      </> : <>
        <nav aria-label="Folder" className="flex flex-wrap gap-2">{trail.map((item, i) => <button key={i} disabled={busy} className="btn-key" onClick={() => browse({ ...item, folder: true }, i)}>{item.name} /</button>)}</nav>
        {!entries.length && <p>No CBZ or image files here. Choose another folder.</p>}
        <ul className="divide-y divide-ink-700">{entries.map(entry => <li key={entry.id}><button disabled={busy} className="w-full break-all p-3 text-start hover:bg-ink-800" onClick={() => browse(entry)}>{entry.folder ? '📁 ' : '📖 '}{entry.name}</button></li>)}</ul>
      </>}
    </section>}
    <p className="text-sm text-fog-400">Read-only: CBZ/ZIP and images, up to 128 MiB per file. CBR, PDF, EPUB, automatic syncing, and cloud uploads are not supported by this device reader. “Forget” removes the saved connection here; it never deletes provider files.</p>
  </main>;
}
