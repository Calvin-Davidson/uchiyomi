// Device-only acceptance test: build the static export first. No BFF or cloud account required.
// BROWSER_PATH may point to an installed Chrome/Chromium binary.
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { resolve, extname, sep } from 'node:path';
import puppeteer from 'puppeteer';

const root = resolve('out');
const user = { id: 'remote-owner', username: 'reader', displayName: 'Reader', role: 'user', settings: {}, perms: { canDownload: false } };
const contentTypes = { '.html': 'text/html', '.js': 'application/javascript', '.css': 'text/css', '.json': 'application/json', '.txt': 'text/plain', '.woff2': 'font/woff2' };
const serverRequests = [];
const progress = new Map();
const progressWrites = [];
function comicFixture() {
  const png = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+/l9sAAAAASUVORK5CYII=','base64');
  let crc = 0xffffffff;
  for (const byte of png) { crc ^= byte; for (let i=0;i<8;i++) crc=(crc>>>1)^(crc&1?0xedb88320:0); }
  const locals=[], directories=[]; let offset=0;
  for (let page=1;page<=4;page++) {
    const name=Buffer.from(`${page}.png`),local=Buffer.alloc(30),central=Buffer.alloc(46);
    local.writeUInt32LE(0x04034b50);local.writeUInt32LE((crc^0xffffffff)>>>0,14);local.writeUInt32LE(png.length,18);local.writeUInt32LE(png.length,22);local.writeUInt16LE(name.length,26);
    central.writeUInt32LE(0x02014b50);central.writeUInt32LE((crc^0xffffffff)>>>0,16);central.writeUInt32LE(png.length,20);central.writeUInt32LE(png.length,24);central.writeUInt16LE(name.length,28);central.writeUInt32LE(offset,42);
    locals.push(local,name,png);directories.push(central,name);offset+=local.length+name.length+png.length;
  }
  const directory=Buffer.concat(directories),end=Buffer.alloc(22);end.writeUInt32LE(0x06054b50);end.writeUInt16LE(4,8);end.writeUInt16LE(4,10);end.writeUInt32LE(directory.length,12);end.writeUInt32LE(offset,16);
  return Buffer.concat([...locals,directory,end]).toString('base64');
}
const server = createServer(async (req, res) => {
  serverRequests.push(req.url);
  const path = new URL(req.url, 'http://localhost').pathname;
  if (path.startsWith('/auth/') || path.startsWith('/api/')) {
    res.setHeader('Content-Type', 'application/json');
    if (/^\/api\/personal\/remote-books\/[a-f0-9]{64}\/progress$/.test(path)) {
      const key = user.id + path;
      if (req.method === 'PUT') {
        let body = ''; for await (const part of req) body += part;
        const data = JSON.parse(body); progressWrites.push(data);
        progress.set(key,{page:data.page,completed:data.page >= data.pages-1});
      }
      res.end(JSON.stringify(progress.get(key) || {page:1,completed:false})); return;
    }
    const data = path === '/auth/refresh' ? { user, accessToken: 'test-session' }
      : path === '/auth/me' ? user
      : path.includes('libraries') ? { content: [] }
      : path.includes('jobs') ? { jobs: [], archive: { series: [] }, queue: [] }
      : { content: [], items: [], profiles: [] };
    res.end(JSON.stringify(data)); return;
  }
  const file = resolve(root, '.' + decodeURIComponent(path), path.endsWith('/') ? 'index.html' : '');
  if (!file.startsWith(root + sep)) { res.writeHead(403).end(); return; }
  try { res.setHeader('Content-Type', contentTypes[extname(file)] || 'application/octet-stream'); res.end(await readFile(file)); }
  catch { res.writeHead(404).end(); }
});
await new Promise(done => server.listen(0, '127.0.0.1', done));
let browser;
try {
  browser = await puppeteer.launch({ headless: true, executablePath: process.env.BROWSER_PATH || undefined });
  const page = await browser.newPage();
  const errors = []; page.on('pageerror', error => errors.push(error.message));
  const origin = `http://127.0.0.1:${server.address().port}`;
  await page.setViewport({ width: 390, height: 844 });
  await page.goto(`${origin}/remote-library/`, { waitUntil: 'networkidle0' });
  await page.waitForSelector('input[type=file]');
  await page.evaluate(() => {
    const bytes = Uint8Array.from(atob('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+/l9sAAAAASUVORK5CYII='), c => c.charCodeAt(0));
    const input = document.querySelector('input[type=file]');
    const transfer = new DataTransfer(); transfer.items.add(new File([bytes], 'private-page.png', { type: 'image/png' }));
    input.files = transfer.files; input.dispatchEvent(new Event('change', { bubbles: true }));
  });
  await page.waitForFunction(() => [...document.querySelectorAll('button')].some(b => b.textContent.includes('private-page.png')));
  await page.evaluate(() => [...document.querySelectorAll('button')].find(b => b.textContent.includes('private-page.png')).click());
  await page.waitForSelector('img[src^="blob:"]');
  await page.waitForFunction(() => document.body.textContent.includes('Reading progress saved'));
  assert.equal(progressWrites.length,1);
  assert.equal(progressWrites[0].title,'private-page.png');
  assert.equal(progressWrites[0].page,1);
  assert.ok(!JSON.stringify(progressWrites).includes('iVBOR'), 'image bytes never sent with reading metadata');
  assert.equal(await page.$eval('img[src^="blob:"]', img => img.complete && img.naturalWidth > 0), true);
  const blob = await page.$eval('img[src^="blob:"]', img => img.src);
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true, 'mobile layout fits');
  await page.evaluate(() => [...document.querySelectorAll('button')].find(b => b.textContent === 'Lock library').click());
  assert.equal(await page.$('img[src^="blob:"]'), null);
  assert.equal(await page.evaluate(async url => { try { await fetch(url); return false; } catch { return true; } }, blob), true, 'lock revokes page URLs');
  const saved = await page.evaluate(() => localStorage.getItem('uchiyomi:remote-libraries:v1:remote-owner'));
  assert.ok(saved); assert.ok(!saved.includes('private-page.png'));
  assert.ok(!serverRequests.some(url => url.includes('private-page') || url.includes('remote-owner')), 'titles and account IDs do not appear in request URLs');
  await page.evaluate(encoded => {
    const input=document.querySelector('input[type=file]'),transfer=new DataTransfer();
    transfer.items.add(new File([Uint8Array.from(atob(encoded),c=>c.charCodeAt(0))],'Resume.cbz'));
    input.files=transfer.files;input.dispatchEvent(new Event('change',{bubbles:true}));
  },comicFixture());
  const clickBook = async () => {
    await page.waitForFunction(()=>[...document.querySelectorAll('button')].some(b=>b.textContent.includes('Resume.cbz')));
    await page.evaluate(()=>[...document.querySelectorAll('button')].find(b=>b.textContent.includes('Resume.cbz')).click());
  };
  await clickBook();
  await page.waitForSelector('img[src^="blob:"]');
  await page.waitForFunction(()=>document.body.textContent.includes('Reading progress saved'));
  for(let i=0;i<2;i++) {
    await page.evaluate(()=>[...document.querySelectorAll('button')].find(b=>b.textContent==='Next').click());
    await page.waitForFunction(()=>document.body.textContent.includes('Reading progress saved'));
  }
  assert.equal(progressWrites.at(-1).page,3);
  await page.evaluate(()=>[...document.querySelectorAll('button')].find(b=>b.textContent==='Close book').click());
  await clickBook();
  await page.waitForSelector('img[alt="Page 3"]');
  await page.waitForFunction(()=>document.body.textContent.includes('Reading progress saved'));
  assert.equal(progressWrites.at(-1).page,3,'reopening resumes instead of overwriting progress with page one');
  // A different account on the same browser profile cannot see the remembered connection.
  user.id = 'other-owner';
  await page.evaluate(() => localStorage.clear()); // clear app offline identity before this simulated fresh login
  await page.evaluate(value => localStorage.setItem('uchiyomi:remote-libraries:v1:remote-owner', value), saved);
  await page.reload({ waitUntil: 'networkidle0' });
  await page.waitForSelector('input[type=file]');
  assert.equal(await page.$('section[aria-label="Saved connections"]'), null);
  assert.deepEqual(errors, []);
  console.log('Remote library browser checks passed: local reading, progress sync, mobile layout, URL revocation, account isolation.');
} finally { await browser?.close(); await new Promise(done => server.close(done)); }
