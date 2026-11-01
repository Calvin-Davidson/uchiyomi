/* Shows vault series (docs/VAULTS.md) in the ordinary Library, series page and reader, decrypted inside the service worker.
 *
 * Loaded by one `importScripts` line at the top of sw.js, so its fetch listener runs first. A series in a vault is not in
 * the server's library (bff/src/lib/vaults.ts): the server only holds ciphertext. This worker opens it with the key
 * this device holds, and answers the app's own API calls for it in the shapes the server would use (web/lib/types.ts):
 *
 *   GET  /api/libraries                     the real list, plus "Vault"
 *   POST /api/series/search                 for the Vault library (?lib=<vault>): its series
 *   GET  /api/series/vlt-<item>[/books]     a vault series and its chapters, with this member's progress
 *   GET  /api/books/vlt-<item>~<ch>[/pages] a chapter and its pages
 *   PUT  /api/books/vlt-…/progress          progress, encrypted here and stored with /api/e2e
 *   GET  /img/series|books/vlt-…            covers, chapter thumbnails, pages (decrypted)
 *   anything else about a vault series      an empty answer (GET) or 403 (a write the server can't do on ciphertext)
 *
 * Keys: this device's member private key is in IndexedDB (`uchiyomi-e2e` / `device`, web/lib/vault.ts) under a
 * non-extractable device key. Formats must match web/lib/vaultCrypto.ts and bff/src/lib/vaultCrypto.ts.
 */
(() => {
  const EC = { name: 'ECDH', namedCurve: 'P-256' };
  const enc = new TextEncoder();
  const dec = new TextDecoder();
  const PREFIX = 'vlt-';
  const AD = {
    vaultKey: (v, u) => enc.encode(`uchiyomi-e2e/v2/vault-key/${v}/${u}`),
    itemKey: (v, i) => enc.encode(`uchiyomi-e2e/v3/item-key/${v}/${i}`),
    meta: (i) => enc.encode(`uchiyomi-e2e/v3/meta/${i}`),
    cover: (i) => enc.encode(`uchiyomi-e2e/v3/cover/${i}`),
    page: (i, c, p) => enc.encode(`uchiyomi-e2e/v3/page/${i}/${c}/${p}`),
    state: (i, u) => enc.encode(`uchiyomi-e2e/v3/state/${i}/${u}`),
  };

  const unb64u = (s) => {
    const bin = atob(s.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((s.length + 3) % 4));
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  };
  const b64u = (b) => {
    let s = '';
    for (let i = 0; i < b.length; i += 0x8000) s += String.fromCharCode(...b.subarray(i, i + 0x8000));
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
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
  const openString = async (key, sealed, aad) => {
    const [v, iv, ct] = sealed.split('.');
    if (v !== 'g1') throw new Error('bad ciphertext');
    return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64u(iv), additionalData: aad }, key, unb64u(ct)));
  };
  const sealString = async (key, plain, aad) => {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad }, key, plain));
    return `g1.${b64u(iv)}.${b64u(ct)}`;
  };
  const openRecord = async (key, rec, aad) =>
    new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: rec.slice(0, 12), additionalData: aad }, key, rec.slice(12)));

  // ── Who is signed in, and a token to ask /api/e2e with ───────────────────────────────────────────────────────
  let bearer = null;
  let userId = null;
  const subOf = (token) => { try { return JSON.parse(atob(token.split('.')[1].replace(/-/g, '+').replace(/_/g, '/'))).sub || null; } catch { return null; } };
  function noteAuth(req) {
    const h = req.headers.get('authorization');
    if (h && h.startsWith('Bearer ')) { bearer = h.slice(7); userId = subOf(bearer) || userId; }
  }
  async function e2e(path, init = {}, retry = true) {
    if (!bearer && typeof freshAccessToken === 'function') { bearer = await freshAccessToken(); if (bearer) userId = subOf(bearer) || userId; }
    const res = await fetch(path, { ...init, headers: { ...(init.headers || {}), ...(bearer ? { authorization: `Bearer ${bearer}` } : {}) } });
    if (res.status === 401 && retry && typeof freshAccessToken === 'function') { bearer = await freshAccessToken(); return e2e(path, init, false); }
    if (!res.ok) throw new Error(`e2e ${res.status}`);
    return res;
  }

  function deviceRecord(uid) {
    return new Promise((resolve) => {
      const r = indexedDB.open('uchiyomi-e2e', 1);
      r.onupgradeneeded = () => { if (!r.result.objectStoreNames.contains('device')) r.result.createObjectStore('device', { keyPath: 'userId' }); };
      r.onerror = () => resolve(null);
      r.onsuccess = () => {
        const db = r.result;
        try {
          const g = db.transaction('device', 'readonly').objectStore('device').get(uid);
          g.onsuccess = () => { db.close(); resolve(g.result || null); };
          g.onerror = () => { db.close(); resolve(null); };
        } catch { db.close(); resolve(null); }
      };
    });
  }

  // ── The vault, opened: one per worker, reloaded when the page says it changed or it is a minute old ─────────────
  let vault = null;      // { id, items: Map<itemId, Item>, at }
  let loading = null;
  const ITEM_TTL = 60_000;

  async function load() {
    if (!userId) return null;
    const rec = await deviceRecord(userId);
    if (!rec) return null;
    const pkcs8 = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: rec.iv }, rec.dak, rec.ct));
    const me = await crypto.subtle.importKey('pkcs8', pkcs8, EC, false, ['deriveBits']);
    pkcs8.fill(0);
    const status = await (await e2e('/api/e2e/status')).json();
    const ref = status.vaults && status.vaults[0];
    if (!ref) return null;
    const vpk = await openFrom(me, ref.wrappedKey, AD.vaultKey(ref.id, userId));
    const vpriv = await crypto.subtle.importKey('pkcs8', vpk, EC, false, ['deriveBits']);
    vpk.fill(0);
    const detail = await (await e2e(`/api/e2e/vaults/${encodeURIComponent(ref.id)}`)).json();
    const items = new Map();
    await Promise.all(detail.items.map(async (row) => {
      try {
        const raw = await openFrom(vpriv, row.itemKey, AD.itemKey(ref.id, row.id));
        const key = await crypto.subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
        raw.fill(0);
        const manifest = JSON.parse(dec.decode(await openString(key, row.meta, AD.meta(row.id))));
        let state = { chapters: {} };
        if (row.state) try { state = JSON.parse(dec.decode(await openString(key, row.state, AD.state(row.id, userId)))); } catch { /* unreadable: start over */ }
        items.set(row.id, { row, key, manifest, state });
      } catch { /* an item that does not open is left out */ }
    }));
    return { id: ref.id, items, at: Date.now() };
  }
  let tried = 0;
  function current(fresh = false) {
    if (vault && !fresh && Date.now() - vault.at < ITEM_TTL) return Promise.resolve(vault);
    // No vault (none yet, or locked on this device): ask again at most every 30 s, not on every request.
    if (!vault && !fresh && Date.now() - tried < 30_000) return loading || Promise.resolve(null);
    tried = Date.now();
    return loading ??= load().then((v) => { vault = v; return v; }).catch(() => vault).finally(() => { loading = null; });
  }

  self.addEventListener('message', (e) => {
    if (e.data?.type === 'yomi-user') { if (e.data.userId !== userId) { vault = null; tried = 0; } userId = e.data.userId || null; }
    if (e.data?.type === 'yomi-signout') { vault = null; bearer = null; userId = null; }
    if (e.data?.e2e === 'reset') { vault = null; tried = 0; }
  });

  // ── The app's shapes (web/lib/types.ts) ──────────────────────────────────────────────────────────────────────
  const seriesId = (itemId) => `${PREFIX}${itemId}`;
  const bookId = (itemId, ch) => `${PREFIX}${itemId}~${ch}`;
  /** `vlt-<item>` or `vlt-<item>~<ch>` back to its parts. */
  function parse(id) {
    const m = /^vlt-([0-9a-f-]{36})(?:~(\d+))?$/.exec(decodeURIComponent(id || ''));
    return m ? { item: m[1], ch: m[2] === undefined ? null : Number(m[2]) } : null;
  }

  const progressOf = (it, ch) => {
    const s = it.state.chapters[ch];
    return s ? { page: s.page, completed: s.completed, readDate: s.at, lastModified: s.at } : null;
  };

  function seriesDto(v, it) {
    const m = it.manifest;
    const states = m.chapters.map((_, i) => it.state.chapters[i]);
    const read = states.filter((s) => s && s.completed).length;
    const inProgress = states.filter((s) => s && !s.completed).length;
    return {
      id: seriesId(it.row.id), libraryId: v.id, library: { id: v.id, name: 'Vault' }, libraryPinned: true, libraryReader: null,
      name: m.title, created: m.movedAt,
      booksCount: m.chapters.length, booksReadCount: read, booksUnreadCount: m.chapters.length - read, booksInProgressCount: inProgress,
      metadata: { title: m.title, status: m.status || undefined, summary: m.summary || undefined, author: m.author || undefined, genres: m.genres, tags: [] },
      booksMetadata: { summary: m.summary || undefined, genres: m.genres, tags: [] },
      color: null, source: null, artVersion: 0, autoHero: null, sources: [], seriesType: 'unknown', workId: null, edition: null,
      lastReadAt: Object.values(it.state.chapters).map((s) => s.at).sort().pop() || null,
      latestChapterAt: m.movedAt,
    };
  }

  function bookDto(it, ch) {
    const c = it.manifest.chapters[ch];
    return {
      id: bookId(it.row.id, ch), seriesId: seriesId(it.row.id), seriesTitle: it.manifest.title,
      name: c.title ? `Chapter ${c.number} - ${c.title}` : `Chapter ${c.number}`, number: c.number, numberEnd: null,
      media: { pagesCount: c.pages.length, mediaType: 'application/zip', status: 'READY' },
      metadata: { title: c.title || `Chapter ${c.number}`, number: String(c.number), numberSort: c.number, releaseDate: c.publishedAt || undefined },
      readProgress: progressOf(it, ch), scanlator: null, sourceId: null, chapterName: c.title || null,
      pruned: false, prunedReason: null, owned: false, missingPages: null,
    };
  }

  function pageDto(it, ch) {
    return it.manifest.chapters[ch].pages.map((p, i) => ({
      number: i + 1, fileName: `${String(i + 1).padStart(4, '0')}`, mediaType: p.t, width: p.w ?? undefined, height: p.h ?? undefined, contentVersion: 'v',
    }));
  }

  const page = (all, n, size) => {
    const total = all.length, pages = Math.max(1, Math.ceil(total / size));
    return { content: all.slice(n * size, n * size + size), totalElements: total, totalPages: pages, number: n, size, first: n === 0, last: n >= pages - 1 };
  };
  const json = (body, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json', 'cache-control': 'no-store' } });
  const NOT_FOUND = () => json({ error: 'not_found' }, 404);

  // ── Answering ─────────────────────────────────────────────────────────────────────────────────────────────────
  /** What an /api/series/<vault series>/<sub> GET answers when the vault has nothing to say about it. */
  const EMPTY = {
    listing: { checkedAt: null, content: [] }, versions: { checkedAt: null, content: [] }, similar: { content: [] },
    comments: { on: false, content: [] }, 'reading-pace': { perChapterMs: null, from: null }, gaps: { gaps: [] }, color: { color: null },
  };

  async function seriesApi(req, id, sub, url) {
    const p = parse(id);
    const v = await current();
    const it = p && v && v.items.get(p.item);
    if (!it) return NOT_FOUND();
    if (req.method !== 'GET') return json({ error: 'vault_series' }, 403);
    if (!sub) return json(seriesDto(v, it));
    if (sub === 'books') {
      const all = it.manifest.chapters.map((_, i) => bookDto(it, i));
      if ((url.searchParams.get('sort') || '').includes('desc')) all.reverse();
      return json(page(all, Number(url.searchParams.get('page') || 0), Number(url.searchParams.get('size') || 1000)));
    }
    return json(EMPTY[sub] || { content: [] });
  }

  async function bookApi(req, id, sub) {
    const p = parse(id);
    const v = await current();
    const it = p && p.ch !== null && v && v.items.get(p.item);
    if (!it || !it.manifest.chapters[p.ch]) return NOT_FOUND();
    if (sub === 'progress' && req.method === 'PUT') {
      const body = await req.json().catch(() => ({}));
      const total = it.manifest.chapters[p.ch].pages.length;
      it.state.chapters[p.ch] = { page: Number(body.page) || 0, completed: !!body.completed || (total > 0 && Number(body.page) >= total), at: new Date().toISOString() };
      const sealed = await sealString(it.key, enc.encode(JSON.stringify(it.state)), AD.state(it.row.id, userId));
      await e2e(`/api/e2e/vaults/${encodeURIComponent(v.id)}/items/${encodeURIComponent(it.row.id)}/state`, {
        method: 'PUT', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ sealed }),
      });
      return json({ ok: true });
    }
    if (req.method !== 'GET') return json({ error: 'vault_series' }, 403);
    if (!sub) return json(bookDto(it, p.ch));
    if (sub === 'pages') return json(pageDto(it, p.ch));
    return NOT_FOUND();
  }

  async function image(id, kind, n) {
    const p = parse(id);
    const v = await current();
    const it = p && v && v.items.get(p.item);
    if (!it) return new Response(null, { status: 404 });
    const base = `/api/e2e/vaults/${encodeURIComponent(v.id)}/items/${encodeURIComponent(it.row.id)}`;
    let bytes, type;
    if (kind === 'cover') {
      bytes = await openRecord(it.key, new Uint8Array(await (await e2e(`${base}/cover`)).arrayBuffer()), AD.cover(it.row.id));
      type = 'image/webp';
    } else {
      const ch = p.ch ?? 0;
      const pg = kind === 'thumb' ? 0 : n - 1;
      const meta = it.manifest.chapters[ch]?.pages[pg];
      if (!meta) return new Response(null, { status: 404 });
      bytes = await openRecord(it.key, new Uint8Array(await (await e2e(`${base}/chapters/${ch}/pages/${pg}`)).arrayBuffer()), AD.page(it.row.id, ch, pg));
      type = meta.t;
    }
    // Private and in memory only: the Cache API would keep the plaintext on disk.
    return new Response(bytes, { headers: { 'content-type': type, 'cache-control': 'no-store' } });
  }

  async function libraries(req) {
    const res = await fetch(req);
    const v = await current();
    if (!res.ok || !v) return res;
    const rows = await res.clone().json().catch(() => null);
    if (!Array.isArray(rows)) return res;
    return json([...rows.filter((r) => r.id !== v.id), { id: v.id, name: 'Vault' }]);
  }

  async function search(req) {
    const body = await req.clone().json().catch(() => null);
    const v = await current();
    if (!v || !body || !JSON.stringify(body.condition || {}).includes(`"${v.id}"`)) return fetch(req);
    const q = String(body.query || body.search || '').trim().toLowerCase();
    let all = [...v.items.values()].filter((it) => !q || it.manifest.title.toLowerCase().includes(q)).map((it) => seriesDto(v, it))
      .filter((s) => matches(body.condition, s));
    const sort = String(body.sort || '');
    if (/^unread/i.test(sort)) all.sort((a, b) => b.booksUnreadCount - a.booksUnreadCount);
    else if (/^chapters/i.test(sort)) all.sort((a, b) => b.booksCount - a.booksCount);
    else if (/created|added|new/i.test(sort)) all.sort((a, b) => b.created.localeCompare(a.created));
    else if (/read/i.test(sort)) all.sort((a, b) => (b.lastReadAt || '').localeCompare(a.lastReadAt || ''));
    else all.sort((a, b) => a.name.localeCompare(b.name));
    if (/desc/i.test(sort) && !/created|added|new|read|chapters/i.test(sort)) all.reverse();
    return json(page(all, Number(body.page) || 0, Number(body.size) || 40));
  }

  /** A name compared as the Library's "by this author" compares it: whole, ignoring case and accents. */
  const fold = (s) => String(s).normalize('NFKD').replace(/[̀-ͯ]/g, '').toLowerCase().replace(/[^\p{L}\p{N}]+/gu, ' ').trim();

  /**
   * Whether a vault series (as seriesDto builds it) passes the Library's condition tree, leaf for leaf as the server's
   * condSqlOf (bff/src/lib/ownedCatalog.ts) reads it. Vault series have no sources, so a source filter keeps none of them
   * and "No source" keeps them all. A leaf it does not know keeps everything rather than emptying the shelf.
   */
  function matches(c, s) {
    if (!c || typeof c !== 'object') return true;
    if (Array.isArray(c.allOf)) return c.allOf.every((x) => matches(x, s));
    if (Array.isArray(c.anyOf)) return !c.anyOf.length || c.anyOf.some((x) => matches(x, s));
    const [key] = Object.keys(c);
    const leaf = c[key] || {};
    const val = leaf.value == null ? '' : String(leaf.value);
    const m = s.metadata;
    let hit;
    if (key === 'libraryId') hit = s.libraryId === val;
    else if (key === 'genre') hit = (m.genres || []).some((g) => g.toLowerCase() === val.toLowerCase());
    else if (key === 'status') hit = (m.status || '').toLowerCase() === val.toLowerCase();
    else if (key === 'author') hit = (m.author || '').toLowerCase().includes(val.toLowerCase());
    else if (key === 'authorName') hit = (m.author || '').split(/[,;/&]/).some((n) => fold(n) && fold(n) === fold(val));
    else if (key === 'readStatus') {
      const done = s.booksReadCount, started = s.booksInProgressCount, n = s.booksCount;
      const r = val.toUpperCase();
      hit = r === 'UNREAD' ? done === 0 && started === 0
        : r === 'IN_PROGRESS' ? started > 0 || (done > 0 && done < n)
        : r === 'READ' ? n > 0 && done >= n
        : true;
    } else if (key === 'mainSource' || key === 'anySource') hit = false;
    else if (key === 'hasMainSource') return leaf.operator === 'isFalse';
    else return true;
    return leaf.operator === 'isNot' ? !hit : hit;
  }

  // For web/test/vaultWorker.test.ts: the shapes and the filter, checked against web/lib/types.ts and the server's rules.
  self.__uchiyomiVaultShapes = { seriesDto, bookDto, pageDto, page, parse, matches };

  self.addEventListener('fetch', (e) => {
    const req = e.request;
    const url = new URL(req.url);
    if (url.origin !== location.origin) return;
    const path = url.pathname;
    if (path.startsWith('/api/')) noteAuth(req);
    let m;
    if ((m = /^\/api\/series\/(vlt-[^/]+)(?:\/([^/]+))?\/?$/.exec(path))) return e.respondWith(seriesApi(req, m[1], m[2] || null, url).catch(() => NOT_FOUND()));
    if ((m = /^\/api\/books\/(vlt-[^/]+)(?:\/([^/]+))?\/?$/.exec(path))) return e.respondWith(bookApi(req, m[1], m[2] || null).catch(() => NOT_FOUND()));
    if (/^\/api\/(bookmarks|notes)\/?$/.test(path) && (url.searchParams.get('seriesId') || '').startsWith(PREFIX)) return e.respondWith(json({ content: [] }));
    if ((m = /^\/img\/series\/(vlt-[^/]+)\/thumb\/?$/.exec(path))) return e.respondWith(image(m[1], 'cover').catch(() => new Response(null, { status: 404 })));
    if ((m = /^\/img\/books\/(vlt-[^/]+)\/thumb\/?$/.exec(path))) return e.respondWith(image(m[1], 'thumb').catch(() => new Response(null, { status: 404 })));
    if ((m = /^\/img\/books\/(vlt-[^/]+)\/page\/(\d+)\/?$/.exec(path))) return e.respondWith(image(m[1], 'page', Number(m[2])).catch(() => new Response(null, { status: 404 })));
    // Any other write naming a vault series: the server has no such series, and must not be told about one.
    if (req.method !== 'GET' && /\/vlt-/.test(path)) return e.respondWith(json({ error: 'vault_series' }, 403));
    // The two upstream answers the vault joins, only once this worker has the vault open (offline, sw.js answers).
    if (vault && path === '/api/libraries' && req.method === 'GET') return e.respondWith(libraries(req).catch(() => fetch(req)));
    // sw.js never handles a POST, so taking every search costs nothing; the vault is opened here if it is not yet.
    if (path === '/api/series/search' && req.method === 'POST') return e.respondWith(search(req).catch(() => fetch(req)));
    // Open the vault in the background on the first API call, so the next list includes it.
    if (!vault && !loading && path.startsWith('/api/') && userId) void current();
  });
})();
