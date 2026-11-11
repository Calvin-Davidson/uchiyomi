'use client';

import { useEffect, useId, useState, useSyncExternalStore } from 'react';
import { getCurrentUser } from '@/lib/api';
import { encryptedImagePath, fetchEncryptedImage, generateMediaRecoveryKey, getMediaKey, importMediaKey, setMediaKey, subscribeMediaKey } from '@/lib/encryptedMedia';
import { t as tr } from '@/lib/i18n';

export const useMediaKey = () => useSyncExternalStore(subscribeMediaKey, getMediaKey, () => null);

export function useEncryptedImage(src: string) {
  const encrypted = encryptedImagePath(src);
  const key = useMediaKey();
  const [image, setImage] = useState<{ src: string; key: CryptoKey; url: string | null }>();
  useEffect(() => {
    if (!encrypted || !key) return;
    const controller = new AbortController();
    let url: string | undefined;
    const owner = getCurrentUser();
    void fetchEncryptedImage(src, key, controller.signal).then(blob => {
      if (controller.signal.aborted || !owner || getCurrentUser() !== owner) return;
      url = URL.createObjectURL(blob);
      setImage({ src, key, url });
    }).catch(() => {
      if (!controller.signal.aborted) setImage({ src, key, url: null });
    });
    return () => {
      controller.abort();
      if (url) URL.revokeObjectURL(url);
    };
  }, [src, encrypted, key]);
  const match = image?.src === src && image?.key === key ? image : undefined;
  return { src: encrypted ? match?.url ?? '' : src, locked: encrypted && !key, failed: encrypted && match?.url === null };
}

export function EncryptedMediaKey({ allowGenerate = false, disabled = false }: { allowGenerate?: boolean; disabled?: boolean }) {
  const key = useMediaKey();
  const id = useId();
  const [value, setValue] = useState('');
  const [generated, setGenerated] = useState(false);
  const [error, setError] = useState(false);
  const unlock = async () => {
    const owner = getCurrentUser();
    try {
      const imported = await importMediaKey(value);
      if (!owner || owner !== getCurrentUser()) return;
      setMediaKey(imported);
      setValue('');
      setGenerated(false);
      setError(false);
    } catch { setError(true); }
  };
  if (key) return <button type="button" className="chip text-xs" disabled={disabled}
    onClick={() => setMediaKey(null)}>{tr('Lock encrypted media')}</button>;
  return <div className="space-y-2 text-sm">
    <label htmlFor={id} className="block">{tr('Encrypted media recovery key')}</label>
    <input id={id} className="field w-full max-w-xl" type={generated ? 'text' : 'password'} value={value}
      onChange={e => { setValue(e.target.value); setError(false); }} autoComplete="off" spellCheck={false} disabled={disabled} />
    {generated && <p>{tr('Save this recovery key somewhere safe before unlocking. You will need it again after closing or reloading the app.')}</p>}
    {error && <p role="alert">{tr('Enter a 64-character recovery key on a secure connection.')}</p>}
    <div className="flex flex-wrap gap-2">
      <button type="button" className="chip text-xs" disabled={disabled || !value.trim()} onClick={() => void unlock()}>{tr('Unlock encrypted media')}</button>
      {allowGenerate && <button type="button" className="chip text-xs" disabled={disabled} onClick={() => {
        setValue(generateMediaRecoveryKey()); setGenerated(true); setError(false);
      }}>{tr('Generate recovery key')}</button>}
    </div>
  </div>;
}
