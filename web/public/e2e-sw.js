/* Fork-only: opens end-to-end encrypted vault pages inside the service worker.
 *
 * Loaded by one `importScripts` line at the top of sw.js, so its fetch listener runs first. For a chapter image
 * (/img/books/… and /img/lib/books/…) it lets the request go the way sw.js would send it; if the server answers with a
 * sealed page (content-type application/x-uchiyomi-e2e, bff/src/fork/e2e/serve.ts) it decrypts it here and hands the
 * page an ordinary image. The reader, the thumbnails, the page grid and offline downloads never know.
 *
 * Keys: this device's member private key is in IndexedDB (`uchiyomi-e2e` / `device`, written by web/fork/e2e/device.ts
 * at sign-in) under a non-extractable device key. The server sends, with each sealed page, the vault's private key
 * sealed to the requesting member (x-e2e-lk). Opened keys are cached in memory until the page says they changed.
 *
 * Formats must match web/fork/e2e/crypto.ts and bff/src/fork/e2e/crypto.ts.
 */
(() => {
  const SEALED = 'application/x-uchiyomi-e2e';
  const EC = { name: 'ECDH', namedCurve: 'P-256' };
  const enc = new TextEncoder();
  let userKeys = new Map();   // userId -> CryptoKey (member private)
  let vaultKeys = new Map();  // userId|vault|lk -> CryptoKey (vault private)
  let chapterKeys = new Map(); // sealed chapter key -> CryptoKey

  const unb64u = (s) => {
    const bin = atob(s.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((s.length + 3) % 4));
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  };

  async function openFrom(priv, sealed, aad) {
    const [v, epk, iv, ct] = sealed.split('.');
    if (v !== 'e1' || !epk || !iv || !ct) throw new Error('bad envelope');
    const epkBytes = unb64u(epk);
    const pub = await crypto.subtle.importKey('raw', epkBytes, EC, false, []);
    const bits = await crypto.subtle.deriveBits({ name: 'ECDH', public: pub }, priv, 256);
    const ikm = await crypto.subtle.importKey('raw', bits, 'HKDF', false, ['deriveKey']);
    const key = await crypto.subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt: epkBytes, info: aad }, ikm, { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
    return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64u(iv), additionalData: aad }, key, unb64u(ct)));
  }

  function deviceRecord(userId) {
    return new Promise((resolve) => {
      const r = indexedDB.open('uchiyomi-e2e', 1);
      r.onupgradeneeded = () => { if (!r.result.objectStoreNames.contains('device')) r.result.createObjectStore('device', { keyPath: 'userId' }); };
      r.onerror = () => resolve(null);
      r.onsuccess = () => {
        const db = r.result;
        try {
          const g = db.transaction('device', 'readonly').objectStore('device').get(userId);
          g.onsuccess = () => { db.close(); resolve(g.result || null); };
          g.onerror = () => { db.close(); resolve(null); };
        } catch { db.close(); resolve(null); }
      };
    });
  }

  async function userKey(userId) {
    if (userKeys.has(userId)) return userKeys.get(userId);
    const rec = await deviceRecord(userId);
    if (!rec) return null;
    const pkcs8 = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: rec.iv }, rec.dak, rec.ct));
    const key = await crypto.subtle.importKey('pkcs8', pkcs8, EC, false, ['deriveBits']);
    pkcs8.fill(0);
    userKeys.set(userId, key);
    return key;
  }

  async function vaultKey(userId, vault, lk) {
    const id = `${userId}|${vault}|${lk}`;
    if (vaultKeys.has(id)) return vaultKeys.get(id);
    const mine = await userKey(userId);
    if (!mine) return null;
    const pkcs8 = await openFrom(mine, lk, enc.encode(`uchiyomi-e2e/v2/vault-key/${vault}/${userId}`));
    const key = await crypto.subtle.importKey('pkcs8', pkcs8, EC, false, ['deriveBits']);
    pkcs8.fill(0);
    vaultKeys.set(id, key);
    return key;
  }

  function header(b) {
    if (b.length < 8 || b[0] !== 0x55 || b[1] !== 0x59 || b[2] !== 0x45 || b[3] !== 0x32) return null;
    const n = new DataView(b.buffer, b.byteOffset, b.byteLength).getUint32(4);
    try { return { n, h: JSON.parse(new TextDecoder().decode(b.subarray(8, 8 + n))) }; } catch { return null; }
  }

  async function openPage(b, vaultPriv, vault) {
    const hd = header(b);
    if (!hd) throw new Error('not sealed');
    let ck = chapterKeys.get(hd.h.k);
    if (!ck) {
      const raw = await openFrom(vaultPriv, hd.h.k, enc.encode(`uchiyomi-e2e/v2/chapter-key/${vault}`));
      ck = await crypto.subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, ['decrypt']);
      chapterKeys.set(hd.h.k, ck);
    }
    const aad = b.slice(0, 8 + hd.n);
    const iv = b.slice(8 + hd.n, 20 + hd.n);
    const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv, additionalData: aad }, ck, b.slice(20 + hd.n));
    return { type: hd.h.t || 'image/jpeg', bytes: plain };
  }

  /** What a page shows when this device cannot open it: a placeholder of the page's own shape, saying why. */
  function locked(b, why) {
    const hd = header(b);
    const w = (hd && hd.h.w) || 800, h = (hd && hd.h.h) || 1200;
    const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="${w}" height="${h}" viewBox="0 0 ${w} ${h}">`
      + `<rect width="100%" height="100%" fill="#16161b"/><text x="50%" y="50%" fill="#9292a3" font-family="sans-serif" `
      + `font-size="${Math.max(14, Math.round(w / 28))}" text-anchor="middle">${why}</text></svg>`;
    return new Response(svg, { headers: { 'content-type': 'image/svg+xml', 'cache-control': 'no-store' } });
  }

  async function decrypt(res) {
    const b = new Uint8Array(await res.arrayBuffer());
    const user = res.headers.get('x-e2e-user'), vault = res.headers.get('x-e2e-vault'), lk = res.headers.get('x-e2e-lk');
    if (!user || !vault || !lk) return locked(b, 'Encrypted page');
    let vk;
    try { vk = await vaultKey(user, vault, lk); } catch { vk = null; }
    if (!vk) return locked(b, 'Vault locked: sign in again to read');
    try {
      const page = await openPage(b, vk, vault);
      return new Response(page.bytes, { headers: { 'content-type': page.type, 'cache-control': 'private, no-store' } });
    } catch {
      return locked(b, 'This page could not be decrypted');
    }
  }

  // Chapter pages and thumbnails, and series covers (a vault series with no cover art has its sealed first page).
  const CHAPTER_IMG = /^\/img\/(lib\/)?(books\/[^/]+\/(page\/\d+|thumb)|series\/[^/]+\/thumb)$/;

  self.addEventListener('fetch', (e) => {
    const req = e.request;
    if (req.method !== 'GET') return;
    const url = new URL(req.url);
    if (url.origin !== location.origin || !CHAPTER_IMG.test(url.pathname)) return;
    // Taken over from sw.js for these URLs only: the same caching it would apply (its stale-while-revalidate image
    // cache holds the SEALED bytes, never a decrypted page), then the decryption.
    e.stopImmediatePropagation();
    e.respondWith((async () => {
      /* global staleWhileRevalidate, IMG */
      const res = typeof staleWhileRevalidate === 'function' && typeof IMG === 'string'
        ? await staleWhileRevalidate(req, IMG, true)
        : await fetch(req);
      if (!res || !(res.headers.get('content-type') || '').startsWith(SEALED)) return res;
      return decrypt(res);
    })());
  });

  self.addEventListener('message', (e) => {
    if (e.data && e.data.e2e === 'reset') { userKeys = new Map(); vaultKeys = new Map(); chapterKeys = new Map(); }
  });
})();
