// Fork-only: just enough ZIP to read a decrypted CBZ in the browser, without a dependency.
//
// Reads the central directory (stored and deflated entries; no ZIP64, no encryption -- a CBZ is neither), and inflates
// with the browser's own DecompressionStream('deflate-raw'). The server never sees these pages: the archive was
// decrypted on this device, and only object URLs to its images ever reach the DOM.

export interface ZipEntry { name: string; method: number; compressedSize: number; size: number; offset: number }

const IMAGE = /\.(jpe?g|png|webp|gif|avif|bmp|jxl)$/i;

/** Every file entry in the archive, from its central directory. Throws on something that is not a ZIP. */
export function zipEntries(buf: Uint8Array): ZipEntry[] {
  const v = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  // End of central directory: 22 bytes plus a comment of up to 64 KiB, at the very end.
  let eocd = -1;
  for (let i = buf.length - 22; i >= Math.max(0, buf.length - 22 - 0xffff); i--) {
    if (v.getUint32(i, true) === 0x06054b50) { eocd = i; break; }
  }
  if (eocd < 0) throw new Error('Not a ZIP archive');
  const count = v.getUint16(eocd + 10, true);
  let p = v.getUint32(eocd + 16, true);
  const out: ZipEntry[] = [];
  const dec = new TextDecoder();
  for (let i = 0; i < count; i++) {
    if (v.getUint32(p, true) !== 0x02014b50) throw new Error('Damaged ZIP directory');
    const method = v.getUint16(p + 10, true);
    const compressedSize = v.getUint32(p + 20, true);
    const size = v.getUint32(p + 24, true);
    const nameLen = v.getUint16(p + 28, true);
    const extraLen = v.getUint16(p + 30, true);
    const commentLen = v.getUint16(p + 32, true);
    const offset = v.getUint32(p + 42, true);
    const name = dec.decode(buf.subarray(p + 46, p + 46 + nameLen));
    if (!name.endsWith('/')) out.push({ name, method, compressedSize, size, offset });
    p += 46 + nameLen + extraLen + commentLen;
  }
  return out;
}

/** One entry's bytes. */
export async function zipRead(buf: Uint8Array, e: ZipEntry): Promise<Uint8Array<ArrayBuffer>> {
  const v = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  if (v.getUint32(e.offset, true) !== 0x04034b50) throw new Error('Damaged ZIP entry');
  const start = e.offset + 30 + v.getUint16(e.offset + 26, true) + v.getUint16(e.offset + 28, true);
  const data = buf.slice(start, start + e.compressedSize);
  if (e.method === 0) return data;
  if (e.method !== 8) throw new Error(`Unsupported ZIP compression (${e.method})`);
  const stream = new Blob([data]).stream().pipeThrough(new DecompressionStream('deflate-raw'));
  return new Uint8Array(await new Response(stream).arrayBuffer());
}

const natural = new Intl.Collator(undefined, { numeric: true, sensitivity: 'base' });

/** The archive's images in reading order (natural sort, so `page 2` comes before `page 10`), skipping macOS litter. */
export function imageEntries(entries: ZipEntry[]): ZipEntry[] {
  return entries
    .filter((e) => IMAGE.test(e.name) && !e.name.startsWith('__MACOSX/') && !/(^|\/)\._/.test(e.name))
    .sort((a, b) => natural.compare(a.name, b.name));
}

const MIME: Record<string, string> = { jpg: 'image/jpeg', jpeg: 'image/jpeg', png: 'image/png', webp: 'image/webp', gif: 'image/gif', avif: 'image/avif', bmp: 'image/bmp', jxl: 'image/jxl' };
export const imageType = (name: string): string => MIME[name.toLowerCase().split('.').pop() || ''] || 'application/octet-stream';
