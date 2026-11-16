import test from 'node:test';
import assert from 'node:assert/strict';
import { deflateRawSync } from 'node:zlib';
import { boundedBlob, cloudProvider, connectionKey, deviceProvider, parseConnections } from '../lib/remoteLibrary';
import { devicePages } from '../lib/remoteArchive';
import { remoteDigest, resumeRemotePage } from '../lib/remoteReading';

const signal = () => new AbortController().signal;
const json = (value: unknown) => new Response(JSON.stringify(value));

test('remote reading identity survives renames and reconnects; resume clamps changed page counts', async () => {
  assert.equal(await remoteDigest(new File(['same bytes'],'old.cbz')),await remoteDigest(new File(['same bytes'],'new.cbz')));
  assert.notEqual(await remoteDigest(new Blob(['a'])),await remoteDigest(new Blob(['b'])));
  assert.equal(resumeRemotePage(4,10),3); assert.equal(resumeRemotePage(99,10),9);
  assert.equal(resumeRemotePage(NaN,10),0);
});

test('saved connections are account-scoped and parsing strips credentials', () => {
  assert.notEqual(connectionKey('alice'), connectionKey('bob'));
  assert.throws(() => connectionKey(''));
  assert.deepEqual(parseConnections('{broken'), []);
  assert.deepEqual(parseConnections(JSON.stringify([{ id: '1', name: 'Books', provider: 'dropbox', root: '', token: 'secret' }, { provider: 'unknown' }])),
    [{ id: '1', name: 'Books', provider: 'dropbox', root: '' }]);
});

test('Drive paginates and sends credentials only to its fixed origin without cookies or cache', async () => {
  const requests: { url: string; init: RequestInit }[] = [];
  const provider = cloudProvider('google-drive', 'secret', (async (url, init) => {
    requests.push({ url: String(url), init: init! });
    return requests.length === 1 ? json({ nextPageToken: 'two', files: [{ id: 'folder', name: 'Series', mimeType: 'application/vnd.google-apps.folder' }] })
      : json({ files: [{ id: '10', name: '10.cbz' }, { id: '2', name: '2.cbz' }, { id: 'html', name: 'unsafe.html' }] });
  }) as typeof fetch);
  assert.deepEqual((await provider.list('root', signal())).map(f => f.id), ['folder', '2', '10']);
  assert.match(requests[1].url, /pageToken=two/);
  for (const request of requests) {
    assert.equal(new URL(request.url).origin, 'https://www.googleapis.com');
    assert.equal(request.init.credentials, 'omit'); assert.equal(request.init.cache, 'no-store');
    assert.equal(request.init.redirect, 'error'); assert.equal(request.init.referrerPolicy, 'no-referrer');
    assert.equal((request.init.headers as Record<string, string>).Authorization, 'Bearer secret');
  }
  await assert.rejects(provider.list("bad' folder", signal()));
});

test('Dropbox follows cursor pagination and uses file IDs for direct downloads', async () => {
  const calls: { url: string; init: RequestInit }[] = [];
  const provider = cloudProvider('dropbox', 'secret', (async (url, init) => {
    calls.push({ url: String(url), init: init! });
    if (String(url).includes('content.dropboxapi')) return new Response('book');
    return calls.length === 1 ? json({ entries: [{ '.tag': 'folder', id: 'id:folder', name: 'Series' }], has_more: true, cursor: 'next' })
      : json({ entries: [{ '.tag': 'file', id: 'id:book', name: '1.cbz' }], has_more: false });
  }) as typeof fetch);
  assert.equal((await provider.list('', signal())).length, 2);
  assert.equal(calls[1].url, 'https://api.dropboxapi.com/2/files/list_folder/continue');
  assert.deepEqual(JSON.parse(calls[1].init.body as string), { cursor: 'next' });
  assert.equal(await (await provider.read('id:book', signal())).text(), 'book');
  assert.equal((calls[2].init.headers as Record<string, string>)['Dropbox-API-Arg'], '{"path":"id:book"}');
});

test('device files stay local, support nested folders and reject missing files', async () => {
  const file = new File(['image'], '1.png');
  Object.defineProperty(file, 'webkitRelativePath', { value: 'Series/1.png' });
  const provider = deviceProvider([file, new File(['not rendered'], 'bad.svg')]);
  assert.deepEqual(await provider.list('', signal()), [{ id: 'Series', name: 'Series', folder: true }]);
  assert.deepEqual(await provider.list('Series', signal()), [{ id: 'Series/1.png', name: '1.png', folder: false }]);
  assert.equal(await provider.read('Series/1.png', signal()), file);
  await assert.rejects(provider.read('missing', signal()));
  const stopped = new AbortController(); stopped.abort();
  await assert.rejects(provider.list('', stopped.signal), { name: 'AbortError' });
});

test('stream caps reject dishonest Content-Length and abort pending reads', async () => {
  await assert.rejects(boundedBlob(new Response('too big', { headers: { 'Content-Length': '1' } }), 2), /too large/);
  const controller = new AbortController();
  const pending = boundedBlob(new Response(new ReadableStream({ start() {} })), 100, controller.signal);
  controller.abort();
  await assert.rejects(pending, { name: 'AbortError' });
  const expired = cloudProvider('google-drive', 'token', (async () => new Response('', { status: 401 })) as typeof fetch);
  await assert.rejects(expired.list('root', signal()), /expired/);
});

// Tiny ZIP fixture builder; no runtime archive dependency is needed in the browser.
function zip(names: string[], method = 8, declaredSize?: number): Blob {
  const locals: Buffer[] = [], directories: Buffer[] = [];
  let offset = 0;
  for (const name of names) {
    const data = Buffer.from('test image'), filename = Buffer.from(name);
    let crc = 0xffffffff;
    for (const byte of data) { crc ^= byte; for (let b = 0; b < 8; b++) crc = (crc >>> 1) ^ (crc & 1 ? 0xedb88320 : 0); }
    const packed = method === 8 ? deflateRawSync(data) : data;
    const local = Buffer.alloc(30); local.writeUInt32LE(0x04034b50); local.writeUInt16LE(method, 8);
    local.writeUInt32LE((crc ^ 0xffffffff) >>> 0, 14); local.writeUInt32LE(packed.length, 18); local.writeUInt32LE(declaredSize ?? data.length, 22); local.writeUInt16LE(filename.length, 26);
    const central = Buffer.alloc(46); central.writeUInt32LE(0x02014b50); central.writeUInt16LE(method, 10);
    central.writeUInt32LE((crc ^ 0xffffffff) >>> 0, 16); central.writeUInt32LE(packed.length, 20); central.writeUInt32LE(declaredSize ?? data.length, 24); central.writeUInt16LE(filename.length, 28); central.writeUInt32LE(offset, 42);
    locals.push(local, filename, packed); directories.push(central, filename); offset += local.length + filename.length + packed.length;
  }
  const directory = Buffer.concat(directories), end = Buffer.alloc(22); end.writeUInt32LE(0x06054b50);
  end.writeUInt16LE(names.length, 8); end.writeUInt16LE(names.length, 10); end.writeUInt32LE(directory.length, 12); end.writeUInt32LE(offset, 16);
  return new Blob([new Uint8Array(Buffer.concat([...locals, directory, end]))]);
}
test('CBZ reads stored and deflated images in natural order without rendering SVG/HTML', async () => {
  for (const method of [0, 8]) {
    const pages = await devicePages(zip(['10.png', '2.jpg', 'evil.svg', 'index.html'], method), 'book.cbz', signal());
    assert.deepEqual(pages.map(p => p.name), ['2.jpg', '10.png']);
    assert.equal(pages[0].blob.type, 'image/jpeg'); assert.equal(await pages[0].blob.text(), 'test image');
  }
});
test('CBZ rejects malformed, truncated, unsupported, and oversized inflated payloads', async () => {
  for (const file of [new Blob(['bad']), zip(['1.png'], 99), zip(['1.png'], 8, 1), zip(['1.png'], 0, 50000000)])
    await assert.rejects(devicePages(file, 'book.cbz', signal()));
  await assert.rejects(devicePages(zip(['1.png']).slice(0, 40), 'book.cbz', signal()));
  const damaged = new Uint8Array(await zip(['1.png'], 0).arrayBuffer()); damaged[35] ^= 1;
  await assert.rejects(devicePages(new Blob([damaged]), 'book.cbz', signal()));
  const stopped = new AbortController(); stopped.abort();
  await assert.rejects(devicePages(zip(['1.png']), 'book.cbz', stopped.signal), { name: 'AbortError' });
});
