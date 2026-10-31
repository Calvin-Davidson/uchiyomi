# Vault: end-to-end encrypted series (fork only)

The vault is a private shelf you move finished downloads into. Once a series is in it, everything about it is
encrypted: title, details, chapter list, cover, pages, and each member's reading progress. The server stores it but
can't read it. Your browser opens it.

## Using it

1. Sign in with your password. The first time, that creates your key pair and your vault, and unlocks them on that device.
2. Download a series the usual way.
3. On its card choose **Move to vault**. The server encrypts it and then removes it from the library, the same way an admin
   would with Remove, Delete files and Forget. That clears its rows, progress, bookmarks and cached images.
4. **Vault** in the menu has its own library, series page and long-strip reader. Progress is saved encrypted.
5. **Move out of vault** on a series page decrypts it back into the downloads folder as CBZ files with `ComicInfo.xml`,
   and a scan picks it up as a new series.

## How it works

```
account password ──PBKDF2-SHA256 (600k)──▶ KEK                       (in the browser, at sign-in)
KEK ──AES-GCM──▶ member private key (ECDH P-256)                      e2e_key_wraps
member public key ◀──ECIES── vault private key (ECDH P-256)           e2e_vault_members
vault PUBLIC key ◀──ECIES── item key (random, one per series)         e2e_vault_items.item_key (sealed by the server)
item key ──AES-256-GCM──▶ manifest, cover, pages, progress            e2e_vault_items.meta, CONFIG_DIR/e2e-vault/, e2e_vault_state
```

- **Chapter files.** `CONFIG_DIR/e2e-vault/<vault>/<item>/<n>.bin` is `UYV3 | count | offset table | records`. Each
  record is `iv | AES-GCM(page)`, bound to its item, chapter and page. The server serves a page by its offsets and
  never needs the key.
- **Moving in** happens on the server, because the server already has the plaintext from the download. It seals the
  new item key to the vault's public key and then forgets it.
- **Moving out** needs the plaintext again: the browser opens the item key and sends it to the server for that one
  request.

## What the server can still see

- How many series a vault holds, each one's chapter count, total size and page count per chapter, and when it was moved in.
- The plaintext while it moves a series in or out, and the series as it was before the move (downloads, logs, backups).
- The account password at sign-in, as it always has. A server modified to log passwords could derive the KEK.

## Limits

- A vault series isn't followed: no new chapters, trackers, OPDS or Komga API. Move it out, update it, move it back in.
- Moving out brings back the files and `ComicInfo.xml` details, not the source link, overrides or vault progress.
- Removing a member doesn't rotate the vault key.
- Needs HTTPS (or localhost) for WebCrypto. Accounts without a password (SSO, passwordless profiles) can't unlock a vault.
- If the password is lost and no signed-in device is left, the vault can't be read again.
- The vault UI is English only.

## Code layout

| Where | What |
| --- | --- |
| `bff/src/fork/e2e/` | `schema.ts` (own tables and migration), `crypto.ts`, `move.ts` (move in and out), `routes.ts` (`/api/e2e/*`), `index.ts` |
| `web/fork/e2e/` | `crypto.ts`, `device.ts` (IndexedDB device key), `session.ts` (keys, sign-in hooks), `items.ts` (opening items), `hooks.tsx`, `VaultPage.tsx` |
| `bff/test/e2eCrypto.test.ts`, `web/test/e2eVault.test.ts` | tests |

Upstream files change by one to three lines each, all marked `fork-only`:

| File | Hook |
| --- | --- |
| `bff/src/server.ts` | `registerE2E(app)` |
| `web/components/Sidebar.tsx`, `SeriesMenu.tsx` | Vault menu item, Move to vault |
| `web/lib/auth.tsx`, `web/components/ProfileAccount.tsx` | unlock at sign-in, forget at sign-out, re-wrap on password change |
| `web/app/vault/page.tsx` (new), `web/app/globals.css` | the page; Tailwind scans `web/fork/` |

`E2E_LIBRARIES=0` turns it off: no tables, no routes. Nothing runs in the background.
