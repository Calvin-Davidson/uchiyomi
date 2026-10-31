// Fork-only: where the encrypted chunks of e2e items live on disk.
//
// Every byte here was encrypted in the browser; the server only ever moves ciphertext. Layout:
//   <E2E_DIR>/<libraryId>/<itemId>/<n>.bin
// E2E_DIR defaults to <CONFIG_DIR>/e2e, so the nightly config backup carries it (ciphertext is safe to copy).
// Point E2E_DIR at a bigger disk when the vault grows.
//
// Ids are validated UUIDs and `n` an integer before they reach a path, so nothing a client sends can climb
// out of the directory.
import { createReadStream, promises as fs } from 'fs';
import { randomBytes } from 'crypto';
import path from 'path';
import { env } from '../../env';

export const e2eDir = (): string => process.env.E2E_DIR || path.join(env.CONFIG_DIR, 'e2e');

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function safeId(id: string): string {
  if (!UUID.test(id)) throw new Error('e2e store: bad id');
  return id.toLowerCase();
}

const libDir = (lib: string) => path.join(e2eDir(), safeId(lib));
const itemDir = (lib: string, item: string) => path.join(libDir(lib), safeId(item));
function chunkPath(lib: string, item: string, n: number): string {
  if (!Number.isInteger(n) || n < 0) throw new Error('e2e store: bad chunk');
  return path.join(itemDir(lib, item), `${n}.bin`);
}

/** Write one chunk, atomically: a reader never sees half of it, and a retry of the same chunk replaces it. */
export async function writeChunk(lib: string, item: string, n: number, bytes: Buffer): Promise<void> {
  const dir = itemDir(lib, item);
  await fs.mkdir(dir, { recursive: true });
  const final = chunkPath(lib, item, n);
  const tmp = `${final}.${randomBytes(6).toString('hex')}.tmp`;
  await fs.writeFile(tmp, bytes);
  await fs.rename(tmp, final);
}

/** Bytes of each chunk 0..count-1, or null when one is missing. */
export async function chunkSizes(lib: string, item: string, count: number): Promise<number[] | null> {
  const out: number[] = [];
  for (let n = 0; n < count; n++) {
    const st = await fs.stat(chunkPath(lib, item, n)).catch(() => null);
    if (!st?.isFile()) return null;
    out.push(st.size);
  }
  return out;
}

/** A chunk to stream back, or null when it is not there. */
export async function openChunk(lib: string, item: string, n: number) {
  const p = chunkPath(lib, item, n);
  const st = await fs.stat(p).catch(() => null);
  if (!st?.isFile()) return null;
  return { size: st.size, stream: createReadStream(p) };
}

/** Chunks past `count` (a re-upload that came out shorter) are dropped at commit. */
export async function dropChunksFrom(lib: string, item: string, count: number): Promise<void> {
  const names = await fs.readdir(itemDir(lib, item)).catch(() => [] as string[]);
  for (const name of names) {
    const m = /^(\d+)\.bin$/.exec(name);
    if (m && Number(m[1]) >= count) await fs.rm(path.join(itemDir(lib, item), name), { force: true });
  }
}

export const removeItem = (lib: string, item: string) => fs.rm(itemDir(lib, item), { recursive: true, force: true });
export const removeLibrary = (lib: string) => fs.rm(libDir(lib), { recursive: true, force: true });
