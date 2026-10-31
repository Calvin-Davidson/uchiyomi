# Private libraries (end-to-end encrypted) — fork only

Private libraries are encrypted on the reader's device before anything is uploaded. The server stores ciphertext and
access rules, and holds no key that can read any of it. Server admins can't read them either. Open them at **`/vault`**.

## Layout: kept apart from upstream

| Where | What |
| --- | --- |
| `bff/src/fork/e2e/` | Schema (`schema.ts`), routes (`routes.ts`), chunk storage (`store.ts`), entry point (`index.ts`) |
| `web/fork/e2e/` | WebCrypto (`crypto.ts`), API and session (`vault.ts`), CBZ reader (`zip.ts`), the page (`VaultPage.tsx`) |
| `bff/test/e2eLibraries.int.test.ts`, `web/test/e2eVault.test.ts` | Tests |

Only three upstream files change, by one or two lines each, all marked `fork-only`:

- `bff/src/server.ts`: imports `registerE2E` and calls it after the other route plugins.
- `web/app/vault/page.tsx` (new): re-exports `web/fork/e2e/VaultPage`.
- `web/app/globals.css`: `@source "../fork/";`, so Tailwind generates the classes the fork's UI uses.

The tables live outside `lib/migrate.ts` (`e2e_*`, created idempotently at every boot under their own advisory lock).
The routes aren't in `bff/openapi.yaml` or `docs/api.md`, and the upstream route-table tests don't register them. The
UI strings are plain English, outside the upstream i18n catalogue. No nav link is added; link to `/vault` from wherever
suits the fork.

## Configuration

- `E2E_LIBRARIES=0` turns the feature off: no tables are created and no routes are registered.
- `E2E_DIR` is where encrypted chunks are stored. The default is `<CONFIG_DIR>/e2e`, which the nightly config backup
  includes; the data is ciphertext, so it's safe to back up. Point it at a bigger disk for large vaults.

## Key hierarchy

```
vault passphrase ──PBKDF2-SHA256 (600k)──▶ KEK
KEK ──AES-256-GCM──▶ private key (ECDH P-256)                         e2e_key_wraps   (one row per unlock method)
member's public key ◀──ECIES (ECDH + HKDF-SHA256 + AES-GCM)── library key   e2e_library_members (one wrap per member)
library key (AES-256, versioned) ──AES-GCM──▶ item key                e2e_items.wrapped_key
item key ──AES-GCM──▶ metadata (name, type, size) and 960 KiB chunks  e2e_items.meta + files under E2E_DIR
```

- Every ciphertext carries AES-GCM associated data that binds it to its place: account, library, key version, item,
  chunk index and whether it's the last chunk. The server can't swap keys or chunks between libraries or items,
  reorder chunks, or truncate a file without decryption failing.
- After unlock, the private key is imported as **non-extractable** and kept only in memory. A reload or **Lock**
  forgets it.
- Library and item ids are generated in the browser, so they can be bound into the associated data before the
  server ever sees them.
- Chunks are about 960 KiB of plaintext, so each upload stays under nginx's default 1 MiB request limit (the split
  layout). Uploads are resumable chunk by chunk and committed at the end. Uploads that are never committed are
  swept after 24 hours.

## Sharing, roles and rotation

- Roles: `owner` (members, rotation, deletion), `editor` (add, rename and remove files), `reader`.
- To share, the owner looks up the member's public key by username. The UI shows its **fingerprint** so both people
  can compare it out of band; the server is the key directory, so this check is what stops a substituted key.
  The owner's browser then wraps the library key to that public key.
- Removing a member stops the server serving them immediately. The owner's browser then **rotates** the library key:
  a new version, wrapped to every remaining member, with every item key re-wrapped under it, all in one transaction.
  Chunks are never re-encrypted.
- A member can leave. The owner can't; they delete the library instead.

## Lost passphrase

Nothing can recover it. **Reset vault** (on the unlock screen or in Vault settings) deletes the key pair and every
library the account owns, along with their files, and leaves the libraries others shared with it. The owners can then
share those again.

## Moving to device keys (DAK) later

The private key is unwrapped through an `Unlocker` (`web/fork/e2e/crypto.ts`). Today's is `passphraseUnlocker`. A
device-held key is another `Unlocker` with its own `kind`, for example a non-extractable AES key in IndexedDB or a
passkey's WebAuthn PRF output. It wraps the **same** private key and is stored as one more `e2e_key_wraps` row
(`POST /api/e2e/keys/wraps`). Nothing below the private key changes, so adopting it re-encrypts no library. The
passphrase wrap can stay as a recovery path or be removed (the server never deletes the last wrap).

If "DAK" means per-item data keys instead: items already have their own content key under the library key.

## Known limits (v1)

- The whole file is decrypted in memory before display; there's no streaming reader. Large PDFs and EPUBs are
  saved decrypted rather than shown.
- No thumbnails, reading progress or search inside private libraries: the server can't see the content.
- The vault page isn't translated.
- PBKDF2 is used because WebCrypto has it natively. A memory-hard KDF (Argon2id via WASM) can be added as another
  `kdf` value in a wrap's `params` without touching existing wraps.

## API (all signed in, under `/api/e2e`)

```
GET    /api/e2e/keys                          PUT    /api/e2e/keys
DELETE /api/e2e/keys                          POST   /api/e2e/keys/wraps
PUT    /api/e2e/keys/wraps/:id                DELETE /api/e2e/keys/wraps/:id
GET    /api/e2e/users/:username/key
GET    /api/e2e/libraries                     POST   /api/e2e/libraries
GET    /api/e2e/libraries/:id                 PATCH  /api/e2e/libraries/:id
DELETE /api/e2e/libraries/:id                 POST   /api/e2e/libraries/:id/rotate
GET    /api/e2e/libraries/:id/members         PUT    /api/e2e/libraries/:id/members/:userId
DELETE /api/e2e/libraries/:id/members/:userId
GET    /api/e2e/libraries/:id/items           POST   /api/e2e/libraries/:id/items
PUT    /api/e2e/items/:id/chunks/:n           GET    /api/e2e/items/:id/chunks/:n
POST   /api/e2e/items/:id/commit              PATCH  /api/e2e/items/:id
DELETE /api/e2e/items/:id
```
