// sources/titleNumbers.ts: a positional listing (Tapas) renumbered from its titles, specials between chapters.
import test from 'node:test';
import assert from 'node:assert/strict';
import { titleNumbers, leadingNumber } from '../src/lib/sources/titleNumbers';
import type { SourceChapter } from '../src/lib/sources/types';

const listing = (titles: string[]): SourceChapter[] =>
  titles.map((title, i) => ({ sourceId: String(i + 1), number: i + 1, order: i + 1, title }));

test('leading numbers', () => {
  assert.equal(leadingNumber("25. What's To Come"), 25);
  assert.equal(leadingNumber('Chapter 12: The Return'), 12);
  assert.equal(leadingNumber('Ep. 7 - Home'), 7);
  assert.equal(leadingNumber('Q&A Announcement!'), null);
  assert.equal(leadingNumber('2nd Q&A'), null);
  assert.equal(leadingNumber('25th Anniversary'), null);
});

test('a Tapas listing takes its titles numbers, specials a hundredth step after the chapter before', () => {
  const titles = Array.from({ length: 24 }, (_, i) => `${i + 1}. Part ${i + 1}`);
  titles.splice(10, 0, 'Caption Contest!', 'Q&A Announcement!');
  titles.push('2023 Holiday Special', '25. What\'s To Come');
  const out = titleNumbers(listing(titles));
  const by = new Map(out.map((c) => [c.title, c.number]));
  assert.equal(by.get('10. Part 10'), 10);
  assert.equal(by.get('Caption Contest!'), 10.01);
  assert.equal(by.get('Q&A Announcement!'), 10.02);
  assert.equal(by.get('11. Part 11'), 11);
  assert.equal(by.get('2023 Holiday Special'), 24.01);
  assert.equal(by.get("25. What's To Come"), 25);
  assert.equal(out.find((c) => c.title === "25. What's To Come")!.sourceNumber, 28);
});

test('a listing numbered by the source, or with few titled posts, is left alone', () => {
  const real = listing(Array.from({ length: 20 }, (_, i) => `${i + 1}. Part`)).map((c) => ({ ...c, number: c.number + 100 }));
  assert.equal(titleNumbers(real), real);
  const untitled = listing(Array.from({ length: 20 }, (_, i) => (i % 2 ? `${i}. Part` : 'News')));
  assert.equal(titleNumbers(untitled), untitled);
  const short = listing(['1. a', 'Q&A', '2. b']);
  assert.equal(titleNumbers(short), short);
});

test('forced (a series an admin put on title numbers) skips the detector, short listings included', () => {
  const short = listing(['1. a', 'Q&A', '2. b']);
  assert.deepEqual(titleNumbers(short, { force: true }).map((c) => c.number), [1, 1.01, 2]);
});

test('the listing layer: auto applies title numbers where the detector fires, `title` forces them', async () => {
  process.env.JWT_SECRET ||= 'test-secret-at-least-16-chars';
  process.env.DATABASE_URL ||= 'postgres://unused/unused';
  const { numberingFor } = await import('../src/lib/numbering');
  const tapas = listing([...Array.from({ length: 14 }, (_, i) => `${i + 1}. Part`), 'Q&A', '15. Part']);
  const auto = numberingFor(tapas, 'auto');
  assert.equal(auto.applied, 'title');
  assert.deepEqual(auto.chapters.slice(-2).map((c) => c.number), [14.01, 15]);
  assert.equal(numberingFor(tapas, 'source').applied, 'source');
  const short = listing(['1. a', 'Q&A', '2. b']);
  assert.equal(numberingFor(short, 'auto').applied, 'source');
  assert.equal(numberingFor(short, 'title').applied, 'title');
});
