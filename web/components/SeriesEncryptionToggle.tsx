'use client';

import { useState } from 'react';
import { api, apiResponse, getCurrentUser } from '@/lib/api';
import { bustCover } from '@/lib/coverBust';
import { decryptPage, encryptPage } from '@/lib/encryptedMedia';
import { t as tr } from '@/lib/i18n';
import { refusalBody, requestFailure } from '@/lib/refusals';
import { EncryptedMediaKey, useMediaKey } from './EncryptedMedia';

type Manifest = { encrypted: boolean; revision: string; books: { id: string; pages: number; version: string }[] };
const MAX_BYTES = 64 * 1024 * 1024;

export function SeriesEncryptionToggle({ id, encrypted, onSaved }: { id: string; encrypted: boolean; onSaved: () => void }) {
  const key = useMediaKey();
  const [target, setTarget] = useState<boolean | null>(null);
  const [progress, setProgress] = useState<number | null>(null);
  const [error, setError] = useState('');

  async function convert() {
    const owner = getCurrentUser();
    if (!owner || !key || target === null || progress !== null) return;
    const path = `/api/series/${encodeURIComponent(id)}/encryption`;
    const options = { expectedOwnerId: owner };
    setError('');
    setProgress(0);
    try {
      const current = await api<Manifest>(path, options);
      if (current.encrypted !== target) {
        const body = new FormData();
        const total = current.books.reduce((sum, book) => sum + book.pages, 0);
        let bytes = 0, done = 0;
        for (const book of current.books) {
          for (let page = 1; page <= book.pages; page++) {
            const response = await apiResponse(`${path}/${encodeURIComponent(book.id)}/${page}?version=${book.version}`, options);
            const original = await response.blob();
            bytes += original.size + (target ? 37 : 0);
            if (bytes > MAX_BYTES) throw new Error('conversion_too_large');
            const converted = target ? await encryptPage(original, original.type, key) : await decryptPage(await original.arrayBuffer(), key);
            body.append('pages', converted, 'page');
            setProgress(Math.floor(++done * 100 / (total + 1)));
          }
        }
        await api(`${path}?revision=${current.revision}&encrypted=${target ? '1' : '0'}`, { ...options, method: 'PUT', ...(total ? { body } : {}) });
      }
      bustCover(id);
      onSaved();
      setTarget(null);
    } catch (err) {
      const code = refusalBody(err)?.error ?? (err instanceof Error ? err.message : '');
      setError(code === 'conversion_too_large' ? tr('Conversion supports up to 64 MB and 2,000 pages per series.')
        : code === 'unsupported_archive' || code === 'unsafe_archive' ? tr('Conversion requires all chapters to be available as CBZ or ZIP archives in the series folder.')
        : code === 'series_changed' || code === 'busy' ? tr('This series is changing. Try again when it is ready.')
        : !target && err instanceof DOMException ? tr('These pages could not be decrypted with this recovery key.')
        : requestFailure(err) ?? tr('Could not change series encryption.'));
    } finally { setProgress(null); }
  }

  const busy = progress !== null;
  return <div className="space-y-2 text-sm">
    <label className="flex items-center gap-2">
      <input type="checkbox" checked={target ?? encrypted} disabled={busy || !globalThis.crypto?.subtle}
        onChange={e => { setTarget(e.target.checked === encrypted ? null : e.target.checked); setError(''); }} />
      {tr('Encrypted')}
    </label>
    {target !== null && <>
      <p>{target ? tr('Encrypt the chapter pages using your recovery key.') : tr('Decrypt the chapter pages and store them unencrypted in your Private library.')}</p>
      {target && <p className="text-xs text-fog-400">{tr('Existing backups, downloads and cached images can still contain unencrypted copies.')}</p>}
      <EncryptedMediaKey allowGenerate={target} disabled={busy} />
      <button type="button" className="btn-accent" disabled={!key || busy} onClick={() => void convert()}>
        {busy ? tr('Working…') + ` ${progress}%` : target ? tr('Encrypt chapters') : tr('Decrypt chapters')}
      </button>
    </>}
    {error && <p role="alert" className="text-red-400">{error}</p>}
  </div>;
}
