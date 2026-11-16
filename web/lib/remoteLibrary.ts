/** Device-only providers. Never import the server API client here or proxy file bytes through the BFF. */
export type RemoteEntry = { id: string; name: string; folder: boolean };
export interface RemoteProvider {
  list(folder: string, signal: AbortSignal): Promise<RemoteEntry[]>;
  read(id: string, signal: AbortSignal): Promise<Blob>;
}
export type ProviderKind = 'google-drive' | 'dropbox' | 'device';
export type RemoteConnection = { id: string; name: string; provider: ProviderKind; root: string };
export const MAX_FILE_BYTES = 128 * 1024 * 1024;
export const readableFile = (name: string) => /\.(cbz|zip|png|jpe?g|webp|gif|avif)$/i.test(name);
export const sortEntries = (entries: RemoteEntry[]) => entries.sort((a, b) =>
  Number(b.folder) - Number(a.folder) || a.name.localeCompare(b.name, undefined, { numeric: true }));

/** Stream with a hard cap; Content-Length is only an early rejection, never trusted. */
export async function boundedBlob(response: Response, limit = MAX_FILE_BYTES, signal?: AbortSignal): Promise<Blob> {
  if (!response.ok) throw new Error(response.status === 401 ? 'Connection expired. Reconnect to your provider.' : 'The provider could not read this file.');
  if (Number(response.headers.get('content-length')) > limit) { await response.body?.cancel(); throw new Error('File is too large.'); }
  if (!response.body) throw new Error('The provider returned no file.');
  const reader = response.body.getReader();
  const abort = () => { void reader.cancel().catch(() => {}); };
  signal?.addEventListener('abort', abort, { once: true });
  const parts: Uint8Array<ArrayBuffer>[] = [];
  let size = 0;
  try {
    for (;;) {
      signal?.throwIfAborted();
      const { done, value } = await reader.read();
      signal?.throwIfAborted();
      if (done) break;
      size += value.byteLength;
      if (size > limit) throw new Error('File is too large.');
      parts.push(new Uint8Array(value));
    }
  } finally { signal?.removeEventListener('abort', abort); await reader.cancel().catch(() => {}); reader.releaseLock(); }
  return new Blob(parts);
}

export function cloudProvider(kind: Exclude<ProviderKind, 'device'>, token: string, request: typeof fetch = fetch): RemoteProvider {
  if (!token.trim() || /[\r\n]/.test(token)) throw new Error('Enter a valid provider access token.');
  // Fixed origins, no redirects, no Uchiyomi cookies, no persistent browser HTTP cache.
  const call = (url: string, signal: AbortSignal, init: RequestInit = {}) => request(url, {
    ...init, signal, credentials: 'omit', cache: 'no-store', redirect: 'error', referrerPolicy: 'no-referrer',
    headers: { ...init.headers, Authorization: `Bearer ${token.trim()}` },
  });
  const json = async (response: Response) => {
    if (!response.ok) throw new Error(response.status === 401 ? 'Connection expired. Reconnect to your provider.' : 'Provider request failed. Check the folder and read permissions.');
    return JSON.parse(await (await boundedBlob(response, 4 * 1024 * 1024)).text());
  };
  if (kind === 'google-drive') return {
    async list(folder, signal) {
      if (!/^[\w-]+$/.test(folder)) throw new Error('Enter a Google Drive folder ID (or root).');
      const entries: RemoteEntry[] = [];
      const seen = new Set<string>();
      let page = '';
      do {
        if (seen.has(page) || seen.size >= 100) throw new Error('Provider pagination did not finish. Choose a smaller folder.');
        seen.add(page);
        const query = new URLSearchParams({ q: `'${folder}' in parents and trashed = false`, fields: 'nextPageToken,files(id,name,mimeType)', pageSize: '1000' });
        if (page) query.set('pageToken', page);
        const data = await json(await call(`https://www.googleapis.com/drive/v3/files?${query}`, signal));
        entries.push(...data.files.map((f: any) => ({ id: f.id, name: f.name, folder: f.mimeType === 'application/vnd.google-apps.folder' })));
        page = data.nextPageToken || '';
        if (entries.length > 10000) throw new Error('This folder is too large. Choose a smaller library folder.');
      } while (page);
      return sortEntries(entries.filter(e => e.folder || readableFile(e.name)));
    },
    async read(id, signal) { return boundedBlob(await call(`https://www.googleapis.com/drive/v3/files/${encodeURIComponent(id)}?alt=media`, signal)); },
  };
  return {
    async list(folder, signal) {
      const entries: RemoteEntry[] = [];
      const seen = new Set<string>();
      let cursor = '';
      do {
        if (seen.has(cursor) || seen.size >= 100) throw new Error('Provider pagination did not finish. Choose a smaller folder.');
        seen.add(cursor);
        const data = await json(await call(`https://api.dropboxapi.com/2/files/list_folder${cursor ? '/continue' : ''}`, signal, {
          method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(cursor ? { cursor } : { path: folder, recursive: false, limit: 1000 }),
        }));
        entries.push(...data.entries.filter((f: any) => f['.tag'] !== 'deleted').map((f: any) => ({ id: f.id, name: f.name, folder: f['.tag'] === 'folder' })));
        cursor = data.has_more ? data.cursor : '';
        if (entries.length > 10000) throw new Error('This folder is too large. Choose a smaller library folder.');
      } while (cursor);
      return sortEntries(entries.filter(e => e.folder || readableFile(e.name)));
    },
    async read(id, signal) {
      // Dropbox requires ASCII-safe JSON in this header, including for Unicode paths.
      const arg = JSON.stringify({ path: id }).replace(/[\u007f-\uffff]/g, c => `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`);
      return boundedBlob(await call('https://content.dropboxapi.com/2/files/download', signal, { method: 'POST', headers: { 'Dropbox-API-Arg': arg } }));
    },
  };
}

/** OS file providers (including Proton) decrypt locally before granting these read-only File objects. */
export function deviceProvider(files: File[]): RemoteProvider {
  const byPath = new Map(files.map(f => [f.webkitRelativePath || f.name, f]));
  return {
    async list(folder, signal) {
      signal.throwIfAborted();
      const entries = new Map<string, RemoteEntry>();
      const prefix = folder ? `${folder}/` : '';
      for (const [path] of byPath) {
        if (!path.startsWith(prefix)) continue;
        const rest = path.slice(prefix.length), name = rest.split('/')[0];
        const isFolder = rest.includes('/');
        if (isFolder || readableFile(name)) entries.set(prefix + name, { id: prefix + name, name, folder: isFolder });
      }
      return sortEntries([...entries.values()]);
    },
    async read(id, signal) {
      signal.throwIfAborted();
      const file = byPath.get(id);
      if (!file) throw new Error('Select the file again on this device.');
      if (file.size > MAX_FILE_BYTES) throw new Error('File is too large.');
      return file;
    },
  };
}

export function connectionKey(owner: string): string {
  if (!owner) throw new Error('Sign in before opening a remote library.');
  return `uchiyomi:remote-libraries:v1:${owner}`;
}
export function parseConnections(raw: string | null): RemoteConnection[] {
  try {
    const data: unknown = JSON.parse(raw || '[]');
    if (!Array.isArray(data)) return [];
    return data.filter((c): c is RemoteConnection => c && typeof c.id === 'string' && typeof c.name === 'string'
      && typeof c.root === 'string' && ['google-drive', 'dropbox', 'device'].includes(c.provider)).slice(0, 30)
      .map(({ id, name, provider, root }) => ({ id, name, provider, root }));
  } catch { return []; }
}
