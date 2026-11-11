const magic = new TextEncoder().encode('YOMIE2E1');
const mediaType = 'application/vnd.yomi.encrypted-page';
const rasterTypes = ['image/jpeg', 'image/png', 'image/webp', 'image/gif', 'image/avif'];

export const encryptedSeriesId = (id: string) => id.startsWith('s_e2ee_');
export const encryptedBookId = (id: string) => id.startsWith('b_e2ee_');
export const encryptedImagePath = (path: string) => /^\/img\/(?:series\/s_e2ee_|books\/b_e2ee_)/.test(path);

let key: CryptoKey | null = null;
const listeners = new Set<() => void>();
export const getMediaKey = () => key;
export function subscribeMediaKey(listener: () => void) {
  listeners.add(listener);
  return () => { listeners.delete(listener); };
}
export function setMediaKey(next: CryptoKey | null) {
  key = next;
  for (const listener of listeners) listener();
}

export function generateMediaRecoveryKey() {
  return Array.from(crypto.getRandomValues(new Uint8Array(32)), b => b.toString(16).padStart(2, '0')).join('');
}

export async function importMediaKey(recoveryKey: string) {
  const hex = recoveryKey.trim();
  if (!/^[\da-f]{64}$/i.test(hex)) throw new Error('Invalid recovery key');
  const bytes = Uint8Array.from(hex.match(/../g)!, byte => parseInt(byte, 16));
  return crypto.subtle.importKey('raw', bytes, 'AES-GCM', false, ['encrypt', 'decrypt']);
}

export async function encryptPage(file: File, type: string, key: CryptoKey) {
  const kind = rasterTypes.indexOf(type);
  if (kind < 0 || file.size + 37 > 64 * 1024 * 1024) throw new Error('Unsupported page type or size');
  const payload = new Uint8Array(file.size + 1);
  payload[0] = kind;
  payload.set(new Uint8Array(await file.arrayBuffer()), 1);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: magic }, key, payload);
  return new Blob([magic, iv, ciphertext], { type: mediaType });
}

export async function decryptPage(page: ArrayBuffer, key: CryptoKey) {
  const bytes = new Uint8Array(page);
  if (bytes.length <= 37 || !magic.every((byte, i) => bytes[i] === byte)) throw new Error('Invalid encrypted page');
  const payload = new Uint8Array(await crypto.subtle.decrypt({
    name: 'AES-GCM', iv: bytes.subarray(8, 20), additionalData: magic,
  }, key, bytes.subarray(20)));
  const type = rasterTypes[payload[0]];
  if (!type || payload.length < 2) throw new Error('Unsupported page type');
  return new Blob([payload.subarray(1)], { type });
}

export async function fetchEncryptedImage(path: string, key: CryptoKey, signal?: AbortSignal) {
  const response = await fetch(path, { credentials: 'same-origin', cache: 'no-store', signal });
  if (!response.ok || response.headers.get('content-type') !== mediaType) throw new Error('Encrypted page unavailable');
  return decryptPage(await response.arrayBuffer(), key);
}
