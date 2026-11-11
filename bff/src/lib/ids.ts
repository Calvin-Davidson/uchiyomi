// Identity for library rows.
//
// These used to be sha1 of the file path, which made the path the identity: renaming a folder minted a new
// series and stranded the user's reading progress on the old row, and two library roots holding the same
// relative path collided. Ids are minted here instead, so a row can move on disk and stay itself.
//
// The ordinary ID shape is unchanged from the hashed version -- same prefix, length and character
// class -- because existing ids appear in URLs, OPDS entry ids, the offline IndexedDB keys on people's
// phones, and the cover filenames under CONFIG_DIR. Every one of those keeps working, and an install that
// predates the change ends up with a mix of hashed and minted ids that nothing can tell apart.
// Encrypted uploads use distinct IDs so image URLs can opt into local decryption without probing ordinary images.
import { randomBytes } from 'crypto';

/** 20 hex characters, matching the sliced sha1 these replace. */
const rand = () => randomBytes(10).toString('hex');

export const newSeriesId = (encrypted = false): string => (encrypted ? 's_e2ee_' : 's_') + rand();
export const newBookId = (encrypted = false): string => (encrypted ? 'b_e2ee_' : 'b_') + rand();

/** Shape check, used by tests and by anything validating an id from outside. */
export const isSeriesId = (s: string): boolean => /^s_(?:e2ee_)?[0-9a-f]{20}$/.test(s);
export const isBookId = (s: string): boolean => /^b_(?:e2ee_)?[0-9a-f]{20}$/.test(s);
