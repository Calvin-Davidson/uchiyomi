// Chapter numbers read from titles, for an extension that numbers by position (Tapas).
//
// The Tapas extension gives every post its place in the list: Q&As, caption contests, season teasers and hiatus
// notes each take a number, so The Beginning After the End's "259. ..." lists as chapter 301 and the series reads
// "298 chapters · Ch. 1–301". Its titles carry the real number ("25. What's To Come"), and another source of the
// same series numbers by it, so the two disagreed on every chapter after the first special.
//
// Per series (lib/numbering.ts, mode `title`): an admin may choose it for any series, and `force` then skips the
// proof below. Left to the detector, a listing must prove both halves: the extension's numbers ARE positions (1..K
// in posting order), and most titles lead with a number that climbs steadily. Then a titled post takes its title's number,
// and a post without one (a special) takes the number before it + 0.01, + 0.02, ... -- in order, between the
// chapters it was posted between, and in the band lib/specials (web) leaves out of the chapter count. A listing
// that does not pass both is returned as it came.
import type { SourceChapter } from './types';

/** "25. What's To Come", "Chapter 25", "Ep. 25 - ...", "Episode 25: ...". Not "2nd Q&A", not "25th Anniversary". */
const LEADING = /^\s*(?:(?:chapter|chap|ch|episode|ep)\.?\s*)?(\d{1,4}(?:\.\d{1,2})?)(?=$|[\s.:\-–—)|])/iu;

export const TITLE_NUMBERS = Object.freeze({
  /** Below this many posts nothing is judged. */
  MIN_POSTS: 12,
  /** At least this share of the extension's numbers equal the post's position... */
  POSITIONAL: 0.9,
  /** ...and at least this share of the posts take a title number... */
  TITLED: 0.6,
  /** ...that never jumps further than this past the one before (a "2023 Holiday Special" is a special). */
  MAX_JUMP: 5,
  /** The step a special takes after the chapter before it. */
  SPECIAL_STEP: 0.01,
});

export function leadingNumber(title: string | undefined | null): number | null {
  const m = LEADING.exec(title ?? '');
  if (!m) return null;
  const n = Number(m[1]);
  return Number.isFinite(n) ? n : null;
}

const round = (n: number): number => Math.round(n * 1000) / 1000;

/** The listing renumbered from its titles, or `list` itself when it does not qualify. Keeps the input's order. */
export function titleNumbers<T extends SourceChapter>(list: readonly T[], opts: { force?: boolean } = {}): readonly T[] {
  const T_ = TITLE_NUMBERS;
  if (!list.length || (!opts.force && list.length < T_.MIN_POSTS)) return list;
  const seq = list.map((c, i) => ({ c, i })).sort((a, b) => (a.c.order ?? a.i + 1) - (b.c.order ?? b.i + 1) || a.i - b.i);
  const positional = seq.filter((r, k) => r.c.number === k + 1).length;
  if (!opts.force && positional < T_.POSITIONAL * seq.length) return list;

  const next: number[] = new Array(list.length);
  let last = 0, specials = 0, titled = 0, changed = false;
  for (const r of seq) {
    const n = leadingNumber(r.c.title);
    let num: number;
    if (n != null && n > last && n <= last + T_.MAX_JUMP) {
      num = n; last = n; specials = 0; titled++;
    } else {
      specials++;
      num = round(last + specials * T_.SPECIAL_STEP);
    }
    next[r.i] = num;
    if (num !== r.c.number) changed = true;
  }
  if (!changed || (!opts.force && titled < T_.TITLED * seq.length)) return list;
  return list.map((c, i) => (next[i] === c.number ? c : { ...c, number: next[i], sourceNumber: c.number }));
}

/** The detector: would this listing be renumbered from its titles, left to itself? */
export const titleNumbering = (list: readonly SourceChapter[]): boolean => titleNumbers(list) !== list;
