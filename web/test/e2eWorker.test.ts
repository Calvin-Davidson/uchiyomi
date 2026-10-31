// Fork-only: the service worker that answers for vault series (public/e2e-sw.js) must hand the Library, series page and
// reader the same shapes the server does (lib/types.ts). Its builders run here on a made-up item; the type
// annotations below fail to compile if a required field goes missing, and the asserts check what TypeScript can't.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import vm from 'node:vm';
import type { Book, Page, PageInfo, Series } from '../lib/types';

const ITEM = '33333333-3333-4333-8333-333333333333';

function shapes() {
  const self: Record<string, unknown> & { addEventListener: () => void } = { addEventListener: () => {} };
  vm.runInNewContext(readFileSync(join(__dirname, '../public/e2e-sw.js'), 'utf8'), { self, location: { origin: 'http://x' }, TextEncoder, TextDecoder, crypto, atob, btoa, URL, Response });
  // Plain copies: objects made in the vm's realm are not deepEqual to this one's.
  const raw = self.__uchiyomiVaultShapes as Record<string, (...a: unknown[]) => unknown>;
  const own = Object.fromEntries(Object.entries(raw).map(([k, f]) => [k, (...a: unknown[]) => JSON.parse(JSON.stringify(f(...a)) ?? 'null')]));
  return own as unknown as {
    seriesDto: (v: unknown, it: unknown) => Series; bookDto: (it: unknown, ch: number) => Book;
    pageDto: (it: unknown, ch: number) => PageInfo[]; page: <T>(all: T[], n: number, size: number) => Page<T>;
    parse: (id: string) => { item: string; ch: number | null } | null;
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
