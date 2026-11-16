/** Stable across devices, provider paths, renames, and reconnects. Never uploads file bytes. */
export async function remoteDigest(file: Blob): Promise<string> {
  const bytes = await crypto.subtle.digest('SHA-256', await file.arrayBuffer());
  return Array.from(new Uint8Array(bytes), b => b.toString(16).padStart(2,'0')).join('');
}
export function resumeRemotePage(page: number, pages: number): number {
  return Math.max(0,Math.min(pages-1,Number.isFinite(page) ? Math.floor(page)-1 : 0));
}
