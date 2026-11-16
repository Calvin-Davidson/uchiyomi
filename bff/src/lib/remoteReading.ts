import { createHash } from 'node:crypto';
import { one, q, tx } from './db';
import { incognitoOn } from './incognito';
import { eventTime, reachedEnd } from './progressRules';

export const REMOTE_READING_DDL = `
CREATE TABLE IF NOT EXISTS remote_books (
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  digest text NOT NULL,
  book_id text NOT NULL,
  series_id text NOT NULL,
  title text NOT NULL,
  series_title text NOT NULL,
  pages integer NOT NULL CHECK (pages BETWEEN 1 AND 1000),
  PRIMARY KEY(user_id,digest), UNIQUE(user_id,book_id)
);
CREATE TABLE IF NOT EXISTS remote_read_progress (
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  book_id text NOT NULL,
  series_id text NOT NULL,
  page integer NOT NULL CHECK(page BETWEEN 1 AND 1000),
  completed boolean NOT NULL DEFAULT false,
  updated_at timestamptz NOT NULL DEFAULT now(),
  is_private boolean NOT NULL DEFAULT true CHECK(is_private),
  incognito boolean NOT NULL DEFAULT false,
  PRIMARY KEY(user_id,book_id),
  FOREIGN KEY(user_id,book_id) REFERENCES remote_books(user_id,book_id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS remote_read_receipts (
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  event_id uuid NOT NULL,
  PRIMARY KEY(user_id,event_id)
);`;

export const remoteBookId = (uid: string, digest: string) => `remote:${uid}:${digest}`;
export interface RemoteReadingWrite {
  title: string; seriesTitle: string; page: number; pages: number;
  eventId: string; at: number; deviceId?: string; incognito?: boolean;
}

export async function remotePosition(uid: string, digest: string) {
  return await one<{page:number;completed:boolean}>(
    'SELECT page,completed FROM remote_read_progress WHERE user_id=$1 AND book_id=$2', [uid, remoteBookId(uid, digest)])
    ?? { page: 1, completed: false };
}

/** Files stay on the device. Only owner-private metadata and normal reading events are accepted. */
export async function writeRemoteReading(uid: string, digest: string, w: RemoteReadingWrite) {
  const incognito = w.incognito === true || await incognitoOn(uid);
  const book = remoteBookId(uid, digest);
  const series = `remote:${uid}:${createHash('sha256').update(w.seriesTitle).digest('hex')}`;
  const at = eventTime(w.at) ?? new Date();
  const completed = w.page === w.pages || reachedEnd(w.page, w.pages);
  await tx(async qq => {
    // Retry-safe: a timeout may have happened after the previous transaction committed.
    const receipt = await qq('INSERT INTO remote_read_receipts(user_id,event_id) VALUES($1,$2) ON CONFLICT DO NOTHING RETURNING event_id', [uid,w.eventId]);
    if (!receipt.length) return;
    await qq(`INSERT INTO remote_books(user_id,digest,book_id,series_id,title,series_title,pages)
      VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(user_id,digest) DO UPDATE SET
      title=EXCLUDED.title,series_title=EXCLUDED.series_title,pages=EXCLUDED.pages`,
      [uid,digest,book,series,w.title,w.seriesTitle,w.pages]);
    // Keep the original series identity when the same file is opened through another connection.
    const [metadata] = await qq<{series_id:string}>('SELECT series_id FROM remote_books WHERE user_id=$1 AND digest=$2',[uid,digest]);
    await qq(`INSERT INTO remote_read_progress(user_id,book_id,series_id,page,completed,updated_at,is_private,incognito)
      VALUES($1,$2,$3,$4,$5,$6,true,$7) ON CONFLICT(user_id,book_id) DO UPDATE SET
      page=CASE WHEN EXCLUDED.updated_at >= remote_read_progress.updated_at THEN EXCLUDED.page ELSE remote_read_progress.page END,
      completed=remote_read_progress.completed OR EXCLUDED.completed,
      updated_at=GREATEST(remote_read_progress.updated_at,EXCLUDED.updated_at),
      is_private=true,incognito=remote_read_progress.incognito AND EXCLUDED.incognito`,
      [uid,book,metadata.series_id,w.page,completed,at,incognito]);
    if (!incognito) await qq(`INSERT INTO reading_events(user_id,book_id,series_id,page,completed,device_id,created_at,is_private)
      VALUES($1,$2,$3,$4,$5,$6,$7,true)`, [uid,book,metadata.series_id,w.page,completed,w.deviceId??null,at]);
  });
  return { ...await remotePosition(uid,digest), incognito };
}

export async function remoteHistory(uid: string, limit: number) {
  return q(`SELECT e.book_id,e.series_id,e.page,e.completed,e.created_at,
      b.title AS book_title,b.series_title,true AS remote
    FROM (SELECT DISTINCT ON(book_id) book_id,series_id,page,completed,created_at FROM reading_events
      WHERE user_id=$1 AND book_id LIKE 'remote:%' ORDER BY book_id,created_at DESC,id DESC) e
    JOIN remote_books b ON b.user_id=$1 AND b.book_id=e.book_id
    ORDER BY e.created_at DESC LIMIT $2`, [uid,limit]);
}
