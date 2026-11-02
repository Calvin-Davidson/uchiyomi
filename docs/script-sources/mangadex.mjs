// @id        mangadex-js
// @name      MangaDex (JavaScript script)
// @lang      en
// @base      https://mangadex.org
// @supports  latest popular
//
// An example script source: copy it to SOURCES_DIR/scripts/ and reload sources. No packages, Node 18+.
// Usage: node mangadex.mjs search "one piece" 1 | series <id> | chapters <id> | pages <id> | latest 1 | popular 1
const API = 'https://api.mangadex.org';
const LANG = 'en';
const PER_PAGE = 20;

async function get(path, params = {}) {
  const q = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) for (const x of [].concat(v)) q.append(k, String(x));
  const r = await fetch(`${API}${path}?${q}`, { headers: { 'User-Agent': 'uchiyomi-script-source' } });
  if (!r.ok) throw new Error(`MangaDex answered ${r.status} for ${path}`);
  return r.json();
}

/** The English text of a localised map, else any. */
const pick = (d) => d?.[LANG] ?? Object.values(d ?? {})[0];

function series(m) {
  const a = m.attributes;
  const rel = Object.fromEntries((m.relationships ?? []).map((r) => [r.type, r]));
  const cover = rel.cover_art?.attributes?.fileName;
  return {
    id: m.id,
    title: pick(a.title),
    summary: pick(a.description),
    status: a.status,
    genres: (a.tags ?? []).map((t) => pick(t.attributes.name)),
    author: rel.author?.attributes?.name,
    cover: cover ? `https://uploads.mangadex.org/covers/${m.id}/${cover}.256.jpg` : undefined,
    url: `https://mangadex.org/title/${m.id}`,
    updatedAt: a.updatedAt,
  };
}

const listing = async (page, params) => (await get('/manga', {
  limit: PER_PAGE, offset: (Number(page) - 1) * PER_PAGE,
  'includes[]': 'cover_art', 'availableTranslatedLanguage[]': LANG, ...params,
})).data.map(series);

const commands = {
  search: (query, page = 1) => listing(page, { title: query }),
  latest: (page = 1) => listing(page, { 'order[latestUploadedChapter]': 'desc' }),
  popular: (page = 1) => listing(page, { 'order[followedCount]': 'desc' }),
  series: async (id) => series((await get(`/manga/${id}`, { 'includes[]': ['cover_art', 'author'] })).data),
  async chapters(id) {
    const out = [];
    for (let offset = 0; ;) {
      const r = await get(`/manga/${id}/feed`, {
        limit: 500, offset, 'translatedLanguage[]': LANG, 'order[chapter]': 'asc', 'includes[]': 'scanlation_group',
      });
      for (const c of r.data) {
        const a = c.attributes;
        if (a.externalUrl) continue; // hosted elsewhere: no pages here
        const groups = c.relationships.filter((g) => g.type === 'scanlation_group' && g.attributes).map((g) => g.attributes.name);
        out.push({
          id: c.id, number: a.chapter, title: a.title, lang: a.translatedLanguage,
          publishedAt: a.publishAt, scanlator: groups.join(' & ') || undefined,
        });
      }
      offset += r.data.length;
      if (!r.data.length || offset >= r.total) return out;
    }
  },
  async pages(id) {
    const { baseUrl, chapter } = await get(`/at-home/server/${id}`);
    return chapter.data.map((f) => `${baseUrl}/data/${chapter.hash}/${f}`);
  },
};

const [cmd, ...args] = process.argv.slice(2);
if (!commands[cmd]) {
  console.error(`unknown command ${JSON.stringify(cmd)}`);
  process.exit(2);
}
try {
  console.log(JSON.stringify(await commands[cmd](...args)));
} catch (e) {
  console.error(e?.message ?? String(e)); // the last stderr line is the error Uchiyomi shows
  process.exit(1);
}
