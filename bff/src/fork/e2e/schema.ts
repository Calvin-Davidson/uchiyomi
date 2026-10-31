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
//                       it: `kind = 'password'` (KEK from PBKDF2 over the account password, in the browser).
//   e2e_vaults          a vault: its PUBLIC key. Not a library: nothing in it is visible to the rest of the app.
//   e2e_vault_members   who may open a vault, with the vault's private key sealed (ECIES) to that member's public key.
//   e2e_vault_items     one series moved in: its item key sealed to the vault, and its manifest (title, metadata,
//                       chapter list, page sizes) encrypted under that key. Chapter files and the cover are on disk
//                       under CONFIG_DIR/e2e-vault/<vault>/<item>/, encrypted under the same key.
//   e2e_vault_state     each member's reading progress in an item, encrypted under the item key in their browser.
//
// Key hierarchy:  password --KEK--> member private key --ECIES--> vault private key --ECIES--> item key --> everything.
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

-- v2 (vaults as real libraries, sealed in place) was never released: its vault libraries go, their series go back to the
-- main library, and its tables are replaced.
DO $$ BEGIN
  IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'e2e_vaults' AND column_name = 'library_id') THEN
    UPDATE lib_series SET library_id = 'lib', library_pinned = false WHERE library_id IN (SELECT library_id FROM e2e_vaults);
    DELETE FROM user_libraries WHERE library_id IN (SELECT library_id FROM e2e_vaults);
    DELETE FROM libraries WHERE id IN (SELECT library_id FROM e2e_vaults);
    DROP TABLE e2e_vault_members;
    DROP TABLE e2e_vaults;
  END IF;
END $$;
DROP TABLE IF EXISTS e2e_sealed;
DROP TABLE IF EXISTS e2e_items;
DROP TABLE IF EXISTS e2e_library_members;
DROP TABLE IF EXISTS e2e_libraries;

CREATE TABLE IF NOT EXISTS e2e_vaults (
  id          text PRIMARY KEY,
  owner_id    uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  alg         text NOT NULL,
  public_key  text NOT NULL,
  created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS e2e_vault_members (
  vault_id    text NOT NULL REFERENCES e2e_vaults(id) ON DELETE CASCADE,
  user_id     uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role        text NOT NULL CHECK (role IN ('owner', 'editor', 'reader')),
  wrap_alg    text NOT NULL,
  wrapped_key text NOT NULL,
  added_by    uuid REFERENCES users(id) ON DELETE SET NULL,
  created_at  timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (vault_id, user_id)
);
CREATE INDEX IF NOT EXISTS e2e_vault_members_user_idx ON e2e_vault_members (user_id);

CREATE TABLE IF NOT EXISTS e2e_vault_items (
  id          uuid PRIMARY KEY,
  vault_id    text NOT NULL REFERENCES e2e_vaults(id) ON DELETE CASCADE,
  item_key    text NOT NULL,
  meta        text NOT NULL,
  chapters    int NOT NULL,
  bytes       bigint NOT NULL,
  created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS e2e_vault_items_vault_idx ON e2e_vault_items (vault_id);

CREATE TABLE IF NOT EXISTS e2e_vault_state (
  item_id     uuid NOT NULL REFERENCES e2e_vault_items(id) ON DELETE CASCADE,
  user_id     uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  sealed      text NOT NULL,
  updated_at  timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (item_id, user_id)
);

-- v1 cleanup. Its key pairs were wrapped under a separate vault passphrase, which nothing asks for any more: a key with no
-- password wrap and in no vault is dropped, so the next sign-in makes a fresh one under the account password.
DELETE FROM e2e_user_keys k
 WHERE NOT EXISTS (SELECT 1 FROM e2e_key_wraps w WHERE w.user_id = k.user_id AND w.kind = 'password')
   AND NOT EXISTS (SELECT 1 FROM e2e_vault_members m WHERE m.user_id = k.user_id);
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
