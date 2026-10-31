# Vault: an end-to-end encrypted library (fork only)

A vault is an ordinary library. You follow series in it, check them for new chapters, fetch chapters from your sources
and read them in the normal reader. Two things are different:

- **Only its members see it.** Other accounts aren't told it exists, and that includes admins.
- **Its chapter files are encrypted with the vault's public key.** The server can write new chapters into it, but it
  can't read them back. Members' browsers decrypt the pages.

## Using it

1. Sign in with your password. That creates your key pair the first time and unlocks it on that device.
2. Your vault is created automatically the first time your key is unlocked: **Vault** sits under Library in the menu.
3. Add series the usual way, then choose **Move to vault** on the series card's menu. Its existing chapters are
   encrypted in the background, and every chapter fetched for it after that is encrypted before it's written to disk.
4. **Vault** in the menu now opens the Library filtered to the vault. **Manage vault** (under it, or `/vault`) shows
   members, how many chapter files are encrypted, and any that couldn't be.

If you share a vault, the other person must have signed in once with their password since vaults were turned on. Compare
the key fingerprint the share dialog shows with the one on their Vault page.

## How it works

```
account password ──PBKDF2-SHA256 (600k)──▶ KEK                       (in the browser, at sign-in)
KEK ──AES-GCM──▶ member private key (ECDH P-256)                      e2e_key_wraps, kind 'password'
member public key ◀──ECIES── vault private key (ECDH P-256)           e2e_vault_members
vault PUBLIC key ◀──ECIES── chapter key (random, per chapter file)    in each sealed page's header (the SERVER seals it)
chapter key ──AES-256-GCM──▶ page                                     the CBZ, entry by entry
```

- **Sealing (server).** A sealed page is still a ZIP entry with the same name: `UYE2 | header | iv | ciphertext`. The
  header holds the sealed chapter key, the image type and its width and height. So the scanner, page counts, ordering,
  `ComicInfo.xml` (left in plaintext) and the reader's page layout all keep working. Only CBZ files can be sealed;
  anything else in a vault is listed on the Vault page.
- **Reading (browser).** The page route sends a sealed page as it's stored, along with the vault's private key sealed to
  the requesting member. The service worker (`web/public/e2e-sw.js`) opens it with the key this device holds and hands
  the page an ordinary image. The reader, thumbnails, page grid and offline downloads don't change. Resized page copies
  aren't made for sealed pages, because resizing needs the plaintext image.
- **Device key (the DAK).** After the password unlocks it, the member private key is kept in IndexedDB under a
  non-extractable AES key that never leaves the device. Signing out removes it. A device that still holds it can re-wrap
  the key when the password changes, including a password reset done elsewhere. Passkeys or other device keys would be
  more `e2e_key_wraps` rows for the same private key (`Unlocker` in `web/fork/e2e/crypto.ts`), with no re-encryption.

## What the server can and can't see

- It **can't** read a sealed page, and it never has a private key.
- It **does** see the series metadata (title, source, chapter list, covers from the source), because it needs them to
  find and download new chapters. It also sees plaintext pages in memory while downloading them, and it sees plaintext
  files that were on disk before a series was moved into the vault. Those files are rewritten sealed. The image cache's
  copies of them (thumbnails, pages, 200/400/1200-wide copies) are deleted; *Fit pages to my screen* copies are left
  for the cache to evict.
- The password is sent to the server at sign-in, as it always has been, so a server modified to log passwords could
  derive the KEK. A separate vault passphrase or a passkey would close that gap, and either fits as another `Unlocker`.

## Limits

- **There's no way back out.** The server can't decrypt, so a series can't be moved out of a vault. Remove it and add
  it again instead. An admin's *Move library*, or deleting the vault's library in Admin → Libraries, leaves its files
  encrypted in a normal library.
- **Removing a member doesn't rotate the key.** Re-encrypting every chapter would have to happen in a browser. The
  server stops serving the removed member immediately.
- **No server-side image work on sealed pages:** automatic banners, page hashing and junk-page detection, translation,
  spread joining and title extraction. OPDS and the Komga API hand external readers sealed bytes they can't open.
- **Needs HTTPS (or localhost) and a service worker.** A private window without service workers shows "Vault locked"
  placeholders.
- **Accounts without a password** (SSO, passwordless profiles) can't unlock a vault.
- **A lost password with no signed-in device left** makes the vault unreadable. Remove its series, delete the vault,
  then reset your keys.
- The vault UI is in English only.

## Code layout (kept apart from upstream)

| Where | What |
| --- | --- |
| `bff/src/fork/e2e/` | `schema.ts` (own tables, own migration), `vaults.ts` (members in memory), `crypto.ts` (seal), `seal.ts` (CBZ sealing, sweep, cache purge), `serve.ts` (sealed pages), `routes.ts` (`/api/e2e/*`), `index.ts` |
| `web/fork/e2e/` | `crypto.ts`, `device.ts` (IndexedDB device key), `session.ts` (login and password hooks, vault calls), `hooks.tsx` (sidebar item, menu item, lock banner), `VaultPage.tsx` |
| `web/public/e2e-sw.js` | decrypts sealed pages in the service worker |
| `bff/test/e2eCrypto.test.ts`, `bff/test/e2eLibraries.int.test.ts`, `web/test/e2eVault.test.ts` | tests |

Upstream files change by one or two lines each, all marked `fork-only`:

| File | Hook |
| --- | --- |
| `bff/src/server.ts` | `registerE2E(app)` |
| `bff/src/lib/visibility.ts` | members-only vaults; a restricted member keeps their vaults |
| `bff/src/lib/ownedCatalog.ts` | the same rule for the libraries list |
| `bff/src/lib/downloader.ts` | seal before write (both writes) |
| `bff/src/lib/library.ts` | sealed pages report their own size |
| `bff/src/routes/images.ts` | serve sealed pages and covers untouched |
| `web/public/sw.js` | `importScripts('/e2e-sw.js')` |
| `web/components/Sidebar.tsx`, `SeriesMenu.tsx`, `AppShell.tsx` | Vault item, Move to vault, lock banner |
| `web/lib/auth.tsx`, `web/components/ProfileAccount.tsx` | unlock at sign-in, forget at sign-out, re-wrap on password change |
| `web/app/vault/page.tsx` (new), `web/app/globals.css` | the manage page; Tailwind scans `web/fork/` |

`E2E_LIBRARIES=0` turns it off: no tables, no routes, and every hook does nothing.
