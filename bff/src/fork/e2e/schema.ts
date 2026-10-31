// Fork-only: end-to-end encrypted ("private") libraries. Schema.
//
// Kept out of lib/migrate.ts on purpose so merging upstream never touches it: these tables are created by
// migrateE2E(), which registerE2E() runs once at boot, under its own advisory lock. Every statement is
// idempotent (IF NOT EXISTS), so it is safe on every start.
//
// The server never sees a key or a plaintext byte. What it stores:
//
//   e2e_user_keys       a member's PUBLIC key (ECDH P-256, SPKI) -- what others wrap library keys to.
//   e2e_key_wraps       the member's PRIVATE key, encrypted ("wrapped") by a key-encryption key (KEK). One row
//                       per way of unlocking it: `kind = 'passphrase'` today (KEK from PBKDF2 over a vault
//                       passphrase). A device-held key (DAK) later is just another row with its own `kind`, wrapping
//                       the SAME private key, so moving to it needs no re-encryption of any library.
//   e2e_libraries       a library: its encrypted metadata (name, ...), and the current library-key version.
//   e2e_library_members who may open it, and the library key (LK) wrapped to that member's public key.
//   e2e_items           a file in it: its own content key wrapped by the LK, encrypted metadata, and how many
//                       encrypted chunks it was uploaded as (the chunks themselves are files on disk, store.ts).
//
// Key hierarchy:  passphrase --KEK--> private key --ECIES--> library key --AES-GCM--> item key --> chunks/meta.
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

CREATE TABLE IF NOT EXISTS e2e_libraries (
  id          uuid PRIMARY KEY,
  owner_id    uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  key_version int  NOT NULL DEFAULT 1,
  meta        text NOT NULL,
  created_at  timestamptz NOT NULL DEFAULT now(),
  updated_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS e2e_library_members (
  library_id  uuid NOT NULL REFERENCES e2e_libraries(id) ON DELETE CASCADE,
  user_id     uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role        text NOT NULL CHECK (role IN ('owner', 'editor', 'reader')),
  key_version int  NOT NULL,
  wrap_alg    text NOT NULL,
  wrapped_key text NOT NULL,
  added_by    uuid REFERENCES users(id) ON DELETE SET NULL,
  created_at  timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (library_id, user_id)
);
CREATE INDEX IF NOT EXISTS e2e_library_members_user_idx ON e2e_library_members (user_id);

CREATE TABLE IF NOT EXISTS e2e_items (
  id          uuid PRIMARY KEY,
  library_id  uuid NOT NULL REFERENCES e2e_libraries(id) ON DELETE CASCADE,
  key_version int  NOT NULL,
  wrapped_key text NOT NULL,
  meta        text NOT NULL,
  chunks      int  NOT NULL DEFAULT 0,
  size        bigint NOT NULL DEFAULT 0,
  state       text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'ready')),
  created_by  uuid REFERENCES users(id) ON DELETE SET NULL,
  created_at  timestamptz NOT NULL DEFAULT now(),
  updated_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS e2e_items_library_idx ON e2e_items (library_id, created_at);
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
