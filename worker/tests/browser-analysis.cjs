'use strict';
// Real Chromium tests; run only in the documented --network none review container.
const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const fs = require('node:fs/promises');
const { spawn } = require('node:child_process');
const { chromium } = require('playwright');
const { getDomain } = require('tldts');
const { createDomAnalyzer } = require('../dom-analyzer.cjs');
const { createNetworkAnalyzer } = require('../network-analyzer.cjs');
const { createRedirectAnalyzer } = require('../redirect-analyzer.cjs');
let server, browser, base;
const receipts = [], verified = [];
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
const output = process.env.ANALYSIS_TEST_OUTPUT;

function html(pathname) {
  // innerHTML below uses only fixed, project-owned fixture strings, not remote/user HTML.
  if (pathname === '/dom/page') return `<!doctype html><title>Loading</title><div id="root"></div>
    <iframe src="/iframe"></iframe><iframe src="${base.replace('127.0.0.1', 'localhost')}/iframe"></iframe>
    <script>window.valueReads=0;setTimeout(()=>{
      document.title='Controlled login';
      document.querySelector('#root').innerHTML='<form method="POST" action="../submit?token=secret-sentinel"><input type="password" value="secret-sentinel"></form><section id="shadow"></section>';
      const shadow=document.querySelector('#shadow').attachShadow({mode:'open'});
      shadow.innerHTML='<form action="https://other.example.test/collect?token=secret-sentinel"><input type="password"><input autocomplete="one-time-code"><input autocomplete="cc-number"></form>';
      for(const input of [...document.querySelectorAll('input'),...shadow.querySelectorAll('input')]) {
        Object.defineProperty(input,'value',{get(){window.valueReads++;throw Error('value must not be read')}});
      }
    },60)</script>`;
  if (pathname === '/iframe') return '<!doctype html><input type="password" value="secret-sentinel">';
  if (pathname === '/base/page') return '<!doctype html><base href="https://base.other.test/path/"><form action="" method="post"><input type="password"></form>';
  if (pathname === '/n1') return '<!doctype html><img src="/pixel.svg"><img src="/dropped"><img src="/forbidden?token=secret-sentinel">';
  if (pathname === '/r1/final') return '<!doctype html><title>Final</title><p>HTTP final</p>';
  if (pathname === '/r2/start') return '<!doctype html><p>start</p><script>setTimeout(()=>location.href="/r2/next",60)</script>';
  if (pathname === '/r2/next') return '<!doctype html><p>next</p><script>setTimeout(()=>location.href="https://blocked.example.test/login?token=secret-sentinel",150)</script>';
  return null;
}
const allowed = new Set(['/dom/page', '/iframe', '/base/page', '/n1', '/pixel.svg', '/dropped', '/r1/start', '/r1/mid', '/r1/final', '/r2/start', '/r2/next']);
before(async () => {
  if (output) await fs.mkdir(output, { recursive: true });
  server = http.createServer((req, res) => {
    const pathname = new URL(req.url, 'http://fixture').pathname;
    receipts.push({ method: req.method, pathname });
    if (pathname === '/dropped') return req.socket.destroy();
    if (pathname === '/r1/start' || pathname === '/r1/mid') {
      res.writeHead(pathname === '/r1/start' ? 302 : 307, { location: pathname === '/r1/start' ? 'mid' : 'final' });
      return res.end();
    }
    if (pathname === '/pixel.svg') {
      res.writeHead(200, { 'content-type': 'image/svg+xml' });
      return res.end('<svg xmlns="http://www.w3.org/2000/svg" width="4" height="4"><rect width="4" height="4"/></svg>');
    }
    const body = html(pathname);
    res.writeHead(body ? 200 : 404, { 'content-type': 'text/html; charset=utf-8' });
    res.end(body || 'Not a fixture');
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  base = `http://127.0.0.1:${server.address().port}`;
  browser = await chromium.launch({ headless: true, chromiumSandbox: true });
});
after(async () => {
  if (browser) await browser.close();
  if (server) await new Promise(resolve => server.close(resolve));
  if (output) {
    const artifacts = { results: { verified, receipts } };
    try { artifacts.pngBase64 = (await fs.readFile(`${output}/normal.png`)).toString('base64'); } catch {}
    try { artifacts.job = JSON.parse(await fs.readFile(`${output}/normal-job.json`, 'utf8')); } catch {}
    // Return generated artifacts over stdout; no writable host mount or permission relaxation.
    console.log('QR_GUARD_ARTIFACTS_JSON ' + JSON.stringify(artifacts));
  }
});
async function context(onBlocked = () => {}) {
  const ctx = await browser.newContext({ serviceWorkers: 'block' });
  await ctx.route('**/*', async route => {
    const u = new URL(route.request().url());
    const sameFixture = (u.origin === base || u.origin === base.replace('127.0.0.1', 'localhost')) && allowed.has(u.pathname);
    if (sameFixture) return route.continue();
    await route.abort();
    onBlocked(route.request());
  });
  return ctx;
}

test('DOM real rendered login, open Shadow DOM, OTP and accessible cross-origin iframe', async () => {
  const ctx = await context();
  try {
    const page = await ctx.newPage();
    await page.goto(`${base}/dom/page`);
    await page.waitForSelector('form');
    for (const frame of page.frames().slice(1)) await frame.waitForSelector('input');
    const a = createDomAnalyzer(page, { officialDomain: 'official.test', resolveRegisteredDomain: host => getDomain(host, { allowPrivateDomains: true }) });
    const result = await a.collect();
    assert.equal(result.pageTitle, 'Controlled login');
    assert.equal(result.passwordFieldCount, 4);
    assert.deepEqual(result.sensitiveFieldTypes, ['password', 'otp', 'payment_card']);
    assert.equal(result.forms.length, 2);
    assert.ok(result.forms.some(f => f.method === 'post' && f.actionHost === '127.0.0.1'));
    assert.ok(result.forms.some(f => f.actionHost === 'other.example.test'));
    assert.ok(a.observations().some(x => x.kind === 'form_action_domain_comparison' && x.mismatch));
    assert.equal(a.observations()[0].inspectedFrames, 3);
    assert.equal(await page.evaluate(() => window.valueReads), 0);
    assert.equal(JSON.stringify([result, a.observations(), a.limitations()]).includes('secret-sentinel'), false);
    verified.push({ case: 'DOM-rendered-shadow-otp-iframe', passwordFieldCount: result.passwordFieldCount, frames: 3 });
    a.stop();
  } finally { await ctx.close(); }
});

test('DOM empty form action uses document URL even with external base URI', async () => {
  const ctx = await context();
  try {
    const page = await ctx.newPage();
    await page.goto(`${base}/base/page`);
    const expected = await page.locator('form').evaluate(form => new URL(form.action).hostname);
    const a = createDomAnalyzer(page);
    assert.equal((await a.collect()).forms[0].actionHost, expected);
    verified.push({ case: 'DOM-empty-action-base', actionHost: expected });
  } finally { await ctx.close(); }
});

test('DOM actual detached frame never establishes an untrusted zero', async () => {
  const ctx = await context();
  try {
    const page = await ctx.newPage();
    await page.setContent('<!doctype html><iframe srcdoc="<p>empty</p>"></iframe>');
    const detached = page.frames().find(frame => frame !== page.mainFrame());
    assert.ok(detached);
    await page.locator('iframe').evaluate(frame => frame.remove());
    const a = createDomAnalyzer({ frames: () => [page.mainFrame(), detached] });
    assert.equal(await a.collect(), null);
    assert.ok(a.limitations().some(reason => reason.includes('inaccessible')));
    verified.push({ case: 'DOM-detached-frame-unknown', result: null });
  } finally { await ctx.close(); }
});

test('N1 real allowed subresources, transport failure and proved policy block stay distinct', async () => {
  let a;
  const ctx = await context(request => a.markPolicyBlocked(request));
  try {
    const page = await ctx.newPage();
    a = createNetworkAnalyzer(page);
    await page.goto(`${base}/n1`);
    await sleep(100);
    const result = a.result();
    assert.deepEqual(result.requestHosts, ['127.0.0.1']);
    assert.ok(result.requestCount >= 4);
    assert.equal(result.blockedRequestCount, 1);
    assert.ok(a.observations().some(x => x.outcome === 'response_received' && x.resourceType === 'image'));
    assert.ok(a.observations().filter(x => x.outcome === 'network_failed').length >= 2);
    assert.equal(a.observations().filter(x => x.outcome === 'policy_blocked').length, 1);
    assert.equal(JSON.stringify(a.observations()).includes('secret-sentinel'), false);
    verified.push({ case: 'N1', ...result });
    a.stop();
  } finally { await ctx.close(); }
});

test('R1 real HTTP 302/307 chain ends only at an observed committed URL', async () => {
  const ctx = await context();
  try {
    const page = await ctx.newPage();
    const a = createRedirectAnalyzer(page, { initialUrl: `${base}/r1/start` });
    await page.goto(`${base}/r1/start`);
    const result = a.result();
    assert.equal(result.redirected, true);
    assert.equal(result.finalUrl, `${base}/r1/final`);
    assert.deepEqual(result.redirectChain.map(edge => edge.statusCode), [302, 307]);
    assert.ok(result.redirectChain.every(edge => edge.type === 'http' && !edge.blocked));
    verified.push({ case: 'R1', ...result });
    a.stop();
  } finally { await ctx.close(); }
});

test('R2 real JavaScript navigation followed by a blocked cross-origin attempt', async () => {
  let a, done;
  const blocked = new Promise(resolve => { done = resolve; });
  const ctx = await context(request => { a.markPolicyBlocked(request); done(); });
  try {
    const page = await ctx.newPage();
    a = createRedirectAnalyzer(page, { initialUrl: `${base}/r2/start` });
    await page.goto(`${base}/r2/start`);
    await page.waitForURL(`${base}/r2/next`);
    let timer;
    try { await Promise.race([blocked, new Promise((_, reject) => { timer = setTimeout(() => reject(Error('No policy callback')), 3000); })]); }
    finally { clearTimeout(timer); }
    const result = a.result();
    assert.equal(result.finalUrl, `${base}/r2/next`);
    assert.equal(result.redirected, true);
    assert.ok(result.redirectChain.some(edge => edge.type === 'client_navigation' && !edge.blocked));
    assert.ok(result.redirectChain.some(edge => edge.blocked && edge.to === 'https://blocked.example.test/login'));
    assert.equal(JSON.stringify([result, a.observations()]).includes('secret-sentinel'), false);
    verified.push({ case: 'R2', ...result });
    a.stop();
  } finally { await ctx.close(); }
});

test('Worker real jobs 202, running PNG 200, completed result and unchanged URL restriction', async () => {
  await browser.close(); browser = null;
  const child = spawn(process.execPath, ['/app/worker.cjs'], { stdio: ['ignore', 'pipe', 'pipe'] });
  let logs = '';
  for (const stream of [child.stdout, child.stderr]) stream.on('data', chunk => { logs = (logs + chunk.toString()).slice(-8000); });
  async function call(path, options = {}) { return fetch(`http://127.0.0.1:4000${path}`, { ...options, signal: AbortSignal.timeout(1000) }); }
  try {
    let healthy = false;
    for (let i = 0; i < 100; i++) {
      try { if ((await call('/internal/health')).ok) { healthy = true; break; } } catch {}
      await sleep(50);
    }
    assert.ok(healthy, 'owned Worker child became healthy');

    const body = { scanId: 'browser-normal', url: 'http://127.0.0.1:4000/demo/normal', timeoutMs: 20000 };
    const post = value => call('/internal/jobs', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(value) });
    assert.equal((await post(body)).status, 202);

    assert.equal((await post(body)).status, 200);
    assert.equal((await post({ ...body, scanId: 'busy' })).status, 429);
    assert.equal((await post({ ...body, scanId: 'blocked', url: `${base}/n1` })).status, 422);
    assert.equal((await call('/internal/analyze', { method: 'POST' })).status, 404);
    let readyWhileRunning = false, final;
    for (let i = 0; i < 400; i++) {
      const job = await (await call('/internal/jobs/browser-normal')).json();
      if (job.status === 'running' && job.screenshotStatus === 'ready') {
        const image = await call('/internal/jobs/browser-normal/screenshot');
        assert.equal(image.status, 200);
        const png = Buffer.from(await image.arrayBuffer());
        assert.equal(png.subarray(0, 8).toString('hex'), '89504e470d0a1a0a');
        if (output && !readyWhileRunning) await fs.writeFile(`${output}/normal.png`, png);
        readyWhileRunning = true;
      }
      if (['completed', 'failed'].includes(job.status)) { final = job; break; }
      await sleep(25);
    }
    assert.ok(readyWhileRunning);

    assert.equal(final?.status, 'completed');
    assert.equal(final.screenshotStatus, 'ready');
    assert.equal(final.domAnalysis.pageTitle, '선발대 테스트');
    assert.equal(final.domAnalysis.passwordFieldCount, 0);
    assert.equal(final.redirectAnalysis.finalUrl, body.url);
    assert.equal(final.redirectAnalysis.redirected, false);
    assert.equal(final.networkAnalysis.blockedRequestCount, 0);
    assert.equal(final.networkAnalysis.requestCount, 1);
    const ids = new Set(final.evidence.map(x => x.id));
    assert.equal(ids.size, final.evidence.length);
    assert.ok(final.signals.every(signal => signal.evidenceIds.every(id => ids.has(id))));
    assert.equal(final.evidence.some(x => ['network_request', 'navigation_response'].includes(x.kind)), false);
    assert.equal((await call('/internal/jobs/browser-normal/screenshot')).status, 200);
    assert.ok(receipts.every(receipt => receipt.method === 'GET'), 'fixture forms were never submitted');
    assert.equal(logs.includes('secret-sentinel'), false);
    if (output) await fs.writeFile(`${output}/normal-job.json`, JSON.stringify(final, null, 2));
    verified.push({ case: 'Worker-API-F4', created: 202, pngWhileRunning: 200, status: final.status, restrictedUrl: 422 });
  } finally {

    const exited = new Promise(resolve => { if (child.exitCode !== null || child.signalCode !== null) resolve(); else child.once('exit', resolve); });
    child.kill('SIGTERM');
    const killTimer = setTimeout(() => child.kill('SIGKILL'), 1000);
    try { await exited; } finally { clearTimeout(killTimer); }

  }
});
