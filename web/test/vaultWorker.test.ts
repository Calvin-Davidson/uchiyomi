// The service worker that answers for vault series (public/vault-sw.js) must hand the Library, series page and
// reader the same shapes the server does (lib/types.ts). Its builders run here on a made-up item; the type
// annotations below fail to compile if a required field goes missing, and the asserts check what TypeScript can't.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import vm from 'node:vm';
import type { Book, Page, PageInfo, Series } from '../lib/types';
import { conditionFrom } from '../lib/libraryQuery';
import { NO_SOURCE } from '../components/LibraryFilters';

const ITEM = '33333333-3333-4333-8333-333333333333';

function shapes() {
  const self: Record<string, unknown> & { addEventListener: () => void } = { addEventListener: () => {} };
  vm.runInNewContext(readFileSync(join(__dirname, '../public/vault-sw.js'), 'utf8'), { self, location: { origin: 'http://x' }, TextEncoder, TextDecoder, crypto, atob, btoa, URL, Response });
  // Plain copies: objects made in the vm's realm are not deepEqual to this one's.
  const raw = self.__uchiyomiVaultShapes as Record<string, (...a: unknown[]) => unknown>;
  const own = Object.fromEntries(Object.entries(raw).map(([k, f]) => [k, (...a: unknown[]) => JSON.parse(JSON.stringify(f(...a)) ?? 'null')]));
  return own as unknown as {
    seriesDto: (v: unknown, it: unknown) => Series; bookDto: (it: unknown, ch: number) => Book;
    pageDto: (it: unknown, ch: number) => PageInfo[]; page: <T>(all: T[], n: number, size: number) => Page<T>;
    parse: (id: string) => { item: string; ch: number | null } | null;
    matches: (condition: unknown, s: Series) => boolean;
    applyMeta: (manifest: unknown, body: unknown) => typeof item.manifest;
  };
}

const item = {
  row: { id: ITEM },
  manifest: {
    v: 3, title: 'Secret', folder: 'x', source: 'x', summary: 'S', author: 'A', status: 'ONGOING', genres: ['Drama'], web: null,
    movedAt: '2026-10-01T00:00:00.000Z',
    chapters: [
      { number: 1, title: null, publishedAt: null, pages: [{ t: 'image/png', w: 10, h: 20 }, { t: 'image/png', w: 10, h: 20 }] },
      { number: 2, title: 'Two', publishedAt: null, pages: [{ t: 'image/jpeg', w: null, h: null }] },
    ],
  },
  state: { chapters: { 0: { page: 2, completed: true, at: '2026-10-02T00:00:00.000Z' }, 1: { page: 0, completed: false, at: '2026-10-03T00:00:00.000Z' } } },
};

test('a vault series looks like a library series, in the vault library', () => {
  const S = shapes();
  const s: Series = S.seriesDto({ id: 'vault_0123456789abcdef' }, item);
  assert.equal(s.id, `vlt-${ITEM}`);
  assert.equal(s.libraryId, 'vault_0123456789abcdef');
  assert.equal(s.name, 'Secret');
  assert.deepEqual([s.booksCount, s.booksReadCount, s.booksUnreadCount, s.booksInProgressCount], [2, 1, 1, 1]);
  assert.equal(s.metadata.title, 'Secret');
});

test('its chapters and pages carry ids the worker can read back, with progress and sizes', () => {
  const S = shapes();
  const b: Book = S.bookDto(item, 1);
  assert.deepEqual(S.parse(b.id), { item: ITEM, ch: 1 });
  assert.deepEqual(S.parse(b.seriesId), { item: ITEM, ch: null });
  assert.equal(b.media.pagesCount, 1);
  assert.deepEqual(b.readProgress && { page: b.readProgress.page, completed: b.readProgress.completed }, { page: 0, completed: false });
  const pages: PageInfo[] = S.pageDto(item, 0);
  assert.deepEqual(pages.map((p) => [p.number, p.width, p.height]), [[1, 10, 20], [2, 10, 20]]);
  const pg: Page<number> = S.page([1, 2, 3], 1, 2);
  assert.deepEqual(pg, { content: [3], totalElements: 3, totalPages: 2, number: 1, size: 2, first: false, last: true });
  assert.equal(S.parse('s_real_series'), null);
});

test("the Library's filters narrow the Vault as the server narrows the Library", () => {
  const S = shapes();
  const VAULT = 'vault_0123456789abcdef';
  const at = (chapters: Record<number, { completed: boolean }>) => S.seriesDto({ id: VAULT }, {
    ...item, manifest: { ...item.manifest, author: 'Kim Jung-gi, Léa Roux' },
    state: { chapters: Object.fromEntries(Object.entries(chapters).map(([k, c]) => [k, { page: 1, at: '2026-10-02T00:00:00.000Z', ...c }])) },
  });
  const fresh = at({});
  const reading = at({ 0: { completed: true } });
  const finished = at({ 0: { completed: true }, 1: { completed: true } });
  // What the aside sends: conditionFrom(read, status, genres, lib, src, anysrc, author).
  const keeps = (s: Series, read = '', status = '', genres: string[] = [], src = '', anysrc = '', author = '') =>
    S.matches(conditionFrom(read, status, genres, VAULT, src, anysrc, author), s);
  assert.deepEqual([fresh, reading, finished].map((s) => keeps(s, 'UNREAD')), [true, false, false]);
  assert.deepEqual([fresh, reading, finished].map((s) => keeps(s, 'IN_PROGRESS')), [false, true, false]);
  assert.deepEqual([fresh, reading, finished].map((s) => keeps(s, 'READ')), [false, false, true]);
  assert.ok(keeps(fresh, '', 'ongoing') && !keeps(fresh, '', 'ENDED'));
  assert.ok(keeps(fresh, '', '', ['drama']) && !keeps(fresh, '', '', ['Drama', 'Comedy']));
  assert.ok(keeps(fresh, '', '', [], '', '', 'lea roux') && !keeps(fresh, '', '', [], '', '', 'Roux'));
  // No sources: a source filter keeps none of them, "No source" all of them.
  assert.ok(!keeps(fresh, '', '', [], 'mangadex') && !keeps(fresh, '', '', [], '', 'mangadex') && keeps(fresh, '', '', [], NO_SOURCE));
  assert.ok(keeps(fresh) && !S.matches(conditionFrom('', '', [], 'vault_ffffffffffffffff'), fresh));
});

test('Edit details changes what the manifest holds, and the stars come back on the series', () => {
  const S = shapes();
  const m = S.applyMeta({ ...item.manifest }, { title: '  New name ', summary: '', author: 'B', status: 'ENDED', genres: [' Horror ', ''], ageRating: 18 });
  assert.deepEqual([m.title, m.summary, m.author, m.status, m.genres], ['New name', null, 'B', 'ENDED', ['Horror']]);
  // A series always has a title: an emptied field keeps the one it had.
  assert.equal(S.applyMeta({ ...item.manifest }, { title: '' }).title, 'Secret');
  assert.equal(S.seriesDto({ id: 'v' }, { ...item, state: { ...item.state, rating: 4 } }).yomi?.rating, 4);
  assert.equal(S.seriesDto({ id: 'v' }, item).yomi?.rating, null);
});
