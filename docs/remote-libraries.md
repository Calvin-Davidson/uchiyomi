# Remote libraries on the reader's device

Open **Library → Remote libraries**. These libraries are separate from the server's
scanned library. The browser lists and reads files; the BFF never receives file
contents, covers, encryption keys, or provider credentials. It does receive book
and containing-folder titles, a content fingerprint, page counts, reading position,
completion, and activity so Uchiyomi can track your reading across devices.

## Reading progress, history, and statistics

Opening a book restores your saved page. Successfully displaying a page saves
your position to your account; a failed image does not advance the bookmark.
The content fingerprint identifies the same file across renames, reconnects,
devices, and providers. A modified archive is a different book. Reconnect the
provider or select the file on each device; Uchiyomi never stores a server copy.

Remote reads appear in **Reading history**, with a link to reconnect the remote
library. They count toward the existing chapter totals, daily activity, streaks,
weekly goals, and reading-time statistics. Remote activity is owner-private and
does not publish titles to household discovery. Incognito saves your position
without creating history or statistical activity. Existing completion rules are
used; reopening a completed chapter does not mark it unread.

Progress saves run in order. Failed saves show a retry control; retry before
leaving the page. Retries cannot double-count activity, and older events cannot
rewind a newer bookmark. There is no persistent offline progress outbox yet.
Remote series are not automatically mapped to external trackers, recommendations,
or server-library series artwork.

## Generic setup, including Proton Drive

1. Install/sign in to the storage provider's app on the device used for reading.
2. Make the desired comics available locally through that app.
3. Choose **Device file provider / synced folder** in Uchiyomi, give the library a
   name, and choose its folder. On devices without folder selection, choose files
   from the OS picker instead. A mobile provider must expose files to that picker.
4. Browse folders and open CBZ/ZIP archives or individual images.

This works with locally available files from Proton Drive, Google Drive, Dropbox,
and other sync/file providers. For Proton, its own client performs decryption on
the reader's device. Uchiyomi does not request Proton keys, bypass its encryption,
or mount the decrypted library on the server. This is **not a direct Proton SDK
integration** and does not download cloud-only placeholders itself. Proton's
[SDK documentation](https://github.com/ProtonDriveApps/sdk) describes the separate
encryption-aware integration required for a future direct connector.

## Direct Google Drive and Dropbox access (advanced)

Both adapters use the same browser-side `RemoteProvider` interface (`list` and
`read`). Requests go directly to fixed provider API origins with no Uchiyomi
cookies, redirects, or persistent HTTP caching. The server is never a proxy.

Supply a short-lived OAuth access token obtained using your own provider
application. Never enter a password, client secret, or refresh token.

- **Google Drive:** enable the Drive API and authorize read access
  (`https://www.googleapis.com/auth/drive.readonly`). Enter the folder ID from its
  Drive URL, or leave it blank for the root. The connector uses
  [files.list](https://developers.google.com/workspace/drive/api/reference/rest/v3/files/list)
  and file downloads with `alt=media`.
- **Dropbox:** authorize `files.metadata.read` and `files.content.read` in your
  application. Enter a folder path such as `/Manga`, or leave it blank for the
  application's accessible root. App-folder access stays restricted to that app
  folder. The connector uses
  [list_folder and download](https://www.dropbox.com/developers/documentation/http/documentation).

There is no built-in OAuth login/refresh flow yet. Reconnect with a fresh token
when it expires. The generic file-provider route avoids manual tokens entirely.
Ordinary Google Drive/Dropbox files do not become end-to-end encrypted by using
this reader. Encrypted container formats require their own device-side client;
they are not decrypted by the plain cloud adapters.

## Privacy and lifecycle

- Connection names, provider types, and root IDs/paths are saved in
  browser localStorage under the signed-in account ID. No connection information
  is synchronized to the BFF or another device. Reading metadata and progress are
  stored separately on the server, scoped to the signed-in account.
- Tokens, file selections, directory listings, and decrypted pages are memory-only. Lock,
  navigation away, or account changes cancel work and release reader references
  and image object URLs. Reconnecting requires a token or a new file selection.
- Forget removes the device's connection record; it preserves your reading
  history and bookmark. All adapters are read-only and never modify cloud files.
- Account namespacing prevents accidental display under another account. It is
  **not encryption against someone who controls the browser profile**. The OS
  provider may also retain its own local decrypted copies. Use OS account and
  device protections for shared machines.
- As with any web client, the served application code must be trusted. A malicious
  server administrator able to replace JavaScript could read data granted to that
  JavaScript; this design removes server-side data processing, not that web trust
  limitation. It makes no secure-memory-erasure guarantee in JavaScript.

## Current limits

CBZ/ZIP (stored or deflated entries) and PNG/JPEG/WebP/GIF/AVIF are supported.
Files are limited to 128 MiB, individual inflated images to 24 MiB, and each
archive to 1,000 image pages / 256 MiB inflated image bytes. ZIP64, encrypted ZIP,
CBR, PDF, EPUB, and server scanning are not supported. CRC checks reject damaged
image payloads. SVG and HTML are never rendered from archives.

This reader requires a signed-in, online Uchiyomi session to enter. It has no
background file synchronization, uploads, external tracker mapping, or offline
launch support. Device selections are snapshots: select the folder again
to see newly synced files. Direct connectors can refresh a folder by selecting
its breadcrumb. Provider credentials and real account access must be tested in
the deployment's browser; automated tests use mocked provider responses.

To add another provider, implement `RemoteProvider` in `web/lib/remoteLibrary.ts`
with browser-only listing and reading, explicit encryption semantics, bounded
reads, and abort support. Never substitute a server proxy for a provider that
cannot be accessed safely from a device.
