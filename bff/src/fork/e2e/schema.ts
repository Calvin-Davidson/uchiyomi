// Fork-only: end-to-end encrypted ("private") libraries. Schema.
//
// Kept out of lib/migrate.ts on purpose so merging upstream never touches it: these tables are created by
// migrateE2E(), which registerE2E() runs once at boot, under its own advisory lock. Every statement is
// idempotent (IF NOT EXISTS), so it is safe on every start.
//
// What it stores:
//
//   e2e_user_keys       a member's PUBLIC key (ECDH P-256, SPKI).
//   e2e_key_wraps       the member's PRIVATE key, encrypted by a key-encryption key (KEK). One row per way of unlocking
//                       it: `kind = 'password'` (KEK from PBKDF2 over the account password, in the browser). A device-held
//                       key (DAK) is another row, wrapping the SAME private key.
//   e2e_vaults          a vault: an ordinary `libraries` row whose chapters are sealed to the vault's PUBLIC key. The
//                       server holds the public key only, so it can encrypt new chapters and never read them back.
//   e2e_vault_members   who may open a vault, with the vault's private key sealed (ECIES) to that member's public key.
//   e2e_sealed          which chapter files have been encrypted, as of which mtime/size (so the sweep skips them).
//
// Key hierarchy:  password --KEK--> member private key --ECIES--> vault private key --ECIES--> chapter key --> pages.
import { pool } from '../../lib/db';

const E2E_LOCK = 8_263_901; // arbitrary, stable; distinct from lib/migrate.ts's locks

const DDL = `
CREATE TABLE IF NOT EXISTS e2e_user_keys (
  user_id    uuid PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  alg        text NOT NULL,
  public_key text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS e2e_key_wraps (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id      uuid NOT NULL REFERENCES e2e_user_keys(user_id) ON DELETE CASCADE,
  kind         text NOT NULL,
  label        text NOT NULL DEFAULT '',
  params       jsonb NOT NULL DEFAULT '{}'::jsonb,
  wrapped      text NOT NULL,
  created_at   timestamptz NOT NULL DEFAULT now(),
  updated_at   timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS e2e_key_wraps_user_idx ON e2e_key_wraps (user_id);

-- v1 (a standalone upload store) was never released; its tables are replaced by vaults on real libraries.
DROP TABLE IF EXISTS e2e_items;
DROP TABLE IF EXISTS e2e_library_members;
DROP TABLE IF EXISTS e2e_libraries;

CREATE TABLE IF NOT EXISTS e2e_vaults (
  library_id  text PRIMARY KEY REFERENCES libraries(id) ON DELETE CASCADE,
  owner_id    uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  alg         text NOT NULL,
  public_key  text NOT NULL,
  created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS e2e_vault_members (
  library_id  text NOT NULL REFERENCES e2e_vaults(library_id) ON DELETE CASCADE,
  user_id     uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role        text NOT NULL CHECK (role IN ('owner', 'editor', 'reader')),
  wrap_alg    text NOT NULL,
  wrapped_key text NOT NULL,
  added_by    uuid REFERENCES users(id) ON DELETE SET NULL,
  created_at  timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (library_id, user_id)
);
CREATE INDEX IF NOT EXISTS e2e_vault_members_user_idx ON e2e_vault_members (user_id);

CREATE TABLE IF NOT EXISTS e2e_sealed (
  book_id    text PRIMARY KEY REFERENCES lib_books(id) ON DELETE CASCADE,
  mtime_ms   bigint,
  size       bigint,
  pages      int,
  error      text,
  sealed_at  timestamptz NOT NULL DEFAULT now()
);
`;

export async function migrateE2E(): Promise<void> {
  const client = await pool.connect();
  try {
    await client.query('SELECT pg_advisory_lock($1)', [E2E_LOCK]);
    try {
      await client.query('BEGIN');
      await client.query(DDL);
      await client.query('COMMIT');
    } catch (e) {
      await client.query('ROLLBACK').catch(() => {});
      throw e;
    }
  } finally {
    await client.query('SELECT pg_advisory_unlock($1)', [E2E_LOCK]).catch(() => {});
    client.release();
  }
}
