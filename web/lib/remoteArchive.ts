import { boundedBlob, MAX_FILE_BYTES } from './remoteLibrary';

export type DevicePage = { name: string; blob: Blob };
const IMAGE = /\.(png|jpe?g|webp|gif|avif)$/i;
const mime = (name: string) => ({ jpg: 'image/jpeg', jpeg: 'image/jpeg', png: 'image/png', webp: 'image/webp', gif: 'image/gif', avif: 'image/avif' }[name.split('.').pop()!.toLowerCase()] || 'application/octet-stream');
const invalid = () => new Error('Unsupported or damaged CBZ. Use a standard ZIP with stored or deflated image pages.');
const crc32 = (bytes: Uint8Array) => {
  let crc = 0xffffffff;
  for (const byte of bytes) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit++) crc = (crc >>> 1) ^ (crc & 1 ? 0xedb88320 : 0);
  }
  return (crc ^ 0xffffffff) >>> 0;
};

/** No HTML, SVG, archive paths, server thumbnails, or persistent decrypted-page cache. */
export async function devicePages(file: Blob, name: string, signal: AbortSignal): Promise<DevicePage[]> {
  signal.throwIfAborted();
  if (file.size > MAX_FILE_BYTES) throw new Error('File exceeds the 128 MiB device reader limit.');
  if (IMAGE.test(name)) return [{ name, blob: file.slice(0, file.size, mime(name)) }];
  if (!/\.(cbz|zip)$/i.test(name)) throw invalid();
  const bytes = new Uint8Array(await file.arrayBuffer()), view = new DataView(bytes.buffer);
  signal.throwIfAborted();
  const u16 = (at: number) => view.getUint16(at, true), u32 = (at: number) => view.getUint32(at, true);
  let end = bytes.length - 22;
  for (; end >= Math.max(0, bytes.length - 65557); end--) {
    if (u32(end) === 0x06054b50 && end + 22 + u16(end + 20) === bytes.length) break;
  }
  if (end < 0 || end < bytes.length - 65557 || u16(end + 4) || u16(end + 6) || u16(end + 8) !== u16(end + 10)) throw invalid();
  const count = u16(end + 10), directorySize = u32(end + 12), directory = u32(end + 16);
  if (count > 5000 || count === 65535 || directory + directorySize !== end) throw invalid();
  let pos = directory, total = 0;
  const pages: DevicePage[] = [];
  for (let i = 0; i < count; i++) {
    signal.throwIfAborted();
    if (pos + 46 > end || u32(pos) !== 0x02014b50) throw invalid();
    const flags = u16(pos + 8), method = u16(pos + 10), crc = u32(pos + 16);
    const compressed = u32(pos + 20), size = u32(pos + 24), nameSize = u16(pos + 28);
    const next = pos + 46 + nameSize + u16(pos + 30) + u16(pos + 32), offset = u32(pos + 42);
    if (next > end) throw invalid();
    const pageName = new TextDecoder().decode(bytes.subarray(pos + 46, pos + 46 + nameSize));
    pos = next;
    if (!IMAGE.test(pageName) || pageName.startsWith('__MACOSX/')) continue;
    total += size;
    if (flags & 1 || ![0, 8].includes(method) || size > 24 * 1024 * 1024 || total > 256 * 1024 * 1024 || pages.length >= 1000) throw invalid();
    if (offset + 30 > directory || u32(offset) !== 0x04034b50 || u16(offset + 8) !== method || u16(offset + 6) !== flags) throw invalid();
    const start = offset + 30 + u16(offset + 26) + u16(offset + 28);
    if (start + compressed > directory) throw invalid();
    const payload = new Blob([bytes.slice(start, start + compressed)]);
    let blob: Blob;
    if (method === 0) blob = payload;
    else {
      const stream = payload.stream().pipeThrough(new DecompressionStream('deflate-raw'));
      // boundedBlob checks actual inflated size, even when the ZIP directory lies.
      blob = await boundedBlob(new Response(stream), size, signal);
    }
    signal.throwIfAborted();
    if (blob.size !== size || crc32(new Uint8Array(await blob.arrayBuffer())) !== crc) throw invalid();
    pages.push({ name: pageName, blob: blob.slice(0, blob.size, mime(pageName)) });
  }
  if (pos !== end || !pages.length) throw invalid();
  return pages.sort((a, b) => a.name.localeCompare(b.name, undefined, { numeric: true }));
}
