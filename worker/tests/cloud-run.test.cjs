'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const { validateInput, parseCandidate, publicUrl, allowedRequest, runScan } = require('../cloud/run.cjs');

const target = 'https://page.example/path?token=observation-sentinel';
const input = { scanId: 'cloud-unit', url: target, timeoutMs: 20000 };

test('input and URL validation reject ambiguity, credentials and disallowed ports', () => {
  assert.deepEqual(validateInput(input), input);
  assert.throws(() => validateInput({ ...input, timeoutMs: 30000 }));
  assert.throws(() => validateInput({ ...input, scanId: '../invalid' }));
  assert.throws(() => validateInput({ ...input, command: 'anything' }));
  for (const value of ['javascript:alert(1)', 'https:example.com', '//example.com/', 'http://@example.com/',
    'http://user:pass@example.com/', 'http://example.com:443/', 'https://example.com:80/',
    'https://example.com:8080/', 'https://example.com/ bad', 'https://example.com\\@localhost/', 'http://168.63.129.16/']) {
    assert.throws(() => parseCandidate(value), value);
  }
  assert.equal(parseCandidate('https://example.com:443/').href, 'https://example.com/');
});

test('all DNS addresses are checked, including metadata and mixed public/private answers', async () => {
  const publicResolver = async () => [{ address: '93.184.215.14', family: 4 }];
  assert.equal(await publicUrl(target, publicResolver), target);
  for (const rows of [
    [{ address: '93.184.215.14', family: 4 }, { address: '127.0.0.1', family: 4 }],
    [{ address: '168.63.129.16', family: 4 }],
    [{ address: '169.254.169.254', family: 4 }],
    [{ address: '::ffff:127.0.0.1', family: 6 }],
  ]) await assert.rejects(publicUrl(target, async () => rows));
  await assert.rejects(publicUrl('http://127.0.0.1/', publicResolver));
});

test('routing allows only bodyless GET/HEAD from the observed page', async () => {
  const page = {};
  const request = (method = 'GET', body = null, owner = page) => ({ method: () => method,
    postDataBuffer: () => body, frame: () => ({ page: () => owner }), url: () => target });
  const allow = async () => target;
  assert.equal(await allowedRequest(request(), page, allow), true);
  assert.equal(await allowedRequest(request('HEAD'), page, allow), true);
  assert.equal(await allowedRequest(request('POST'), page, allow), false);
  assert.equal(await allowedRequest(request('GET', Buffer.from('data')), page, allow), false);
  assert.equal(await allowedRequest(request('GET', null, {}), page, allow), false);
  assert.equal(await allowedRequest(request(), page, async () => { throw Error(); }), false);
});

function doubles({ domFailure = false, screenshotFailure = false, blockedRequest = false, launchFailure = false } = {}) {
  const page = new EventEmitter(), context = new EventEmitter(), files = new Map();
  let route, launchOptions, contextOptions, screenshotOptions, closed = false, blockedCount = 0;
  const domResult = { pageTitle: 'Controlled observation', passwordFieldCount: 1, sensitiveFieldTypes: ['password'], forms: [{ method: 'post', actionHost: 'receiver.example' }] };
  const png = Buffer.alloc(32); Buffer.from('89504e470d0a1a0a', 'hex').copy(png); png.writeUInt32BE(390, 16); png.writeUInt32BE(844, 20);
  page.url = () => target;
  page.goto = async () => {
    if (blockedRequest) await route({ request: () => ({ method: () => 'POST', postDataBuffer: () => Buffer.from('synthetic'),
      frame: () => ({ page: () => page }), url: () => 'https://receiver.example/' }),
    continue: async () => assert.fail('POST must not continue'), abort: async () => {} });
    return { status: () => 200 };
  };
  page.screenshot = async options => { screenshotOptions = options; if (screenshotFailure) throw Error('untrusted URL must not leak'); return png; };
  context.route = async (_pattern, callback) => { route = callback; };
  context.routeWebSocket = async () => {};
  context.newPage = async () => page;
  const evidence = [], signals = [];
  const dependencies = {
    fs: { writeFile: async (path, data) => { files.set(path, data); } }, sleep: async () => {}, checkUrl: async value => value,
    chromium: { launch: async options => { launchOptions = options; if (launchFailure) throw Error('launch internals'); return {
      newContext: async options => { contextOptions = options; return context; }, close: async () => { closed = true; },
    }; } },
    createObserver: () => ({ stop() {}, record(kind, summary, data) {
      const id = 'ev-' + evidence.length; evidence.push({ id, kind, summary, data }); signals.push({ kind, evidenceIds: [id] });
    }, result: () => ({ evidence, signals }) }),
    createNetworkAnalyzer: () => ({ stop() {}, markPolicyBlocked() { blockedCount++; },
      result: () => ({ requestHosts: ['page.example'], requestCount: 1, blockedRequestCount: blockedCount }),
      limitations: () => [], observations: () => [] }),
    createRedirectAnalyzer: () => ({ stop() {}, markPolicyBlocked() {}, limitations: () => [],
      result: () => ({ redirected: false, finalUrl: 'https://page.example/path', redirectChain: [] }) }),
    createDomAnalyzer: () => ({ stop() {}, collect: async () => { if (domFailure) throw Error('DOM internals'); },
      result: () => domFailure ? null : domResult, limitations: () => [], observations: () => [{ kind: 'dom_inspection', incomplete: domFailure }] }),
  };
  return { dependencies, files, get closed() { return closed; }, get launchOptions() { return launchOptions; },
    get contextOptions() { return contextOptions; }, get screenshotOptions() { return screenshotOptions; } };
}

test('successful observation retains exact final URL and metadata without submitting forms', async () => {
  const fake = doubles(); const result = await runScan(input, fake.dependencies);
  assert.equal(result.status, 'completed'); assert.equal(result.inspectionComplete, true);
  assert.equal(result.finalUrl, target); assert.equal(result.domAnalysis.passwordFieldCount, 1);
  assert.equal(result.screenshotStatus, 'ready'); assert.ok(fake.files.has('/tmp/qr-shot.png'));
  assert.equal(fake.launchOptions.chromiumSandbox, true); assert.equal('proxy' in fake.contextOptions, false);
  assert.deepEqual(fake.contextOptions.viewport, { width: 390, height: 844 });
  assert.equal(fake.contextOptions.serviceWorkers, 'block'); assert.equal(fake.contextOptions.acceptDownloads, false);
  assert.equal(fake.screenshotOptions.fullPage, false); assert.equal(fake.closed, true);
  assert.doesNotMatch(JSON.stringify(result.evidence), /observation-sentinel/);
  assert.equal('verdict' in result, false);
});

test('DOM failure preserves PNG and never turns missing observations into zero', async () => {
  const fake = doubles({ domFailure: true }); const result = await runScan(input, fake.dependencies);
  assert.equal(result.screenshotStatus, 'ready'); assert.equal(result.domAnalysis, null);
  assert.equal(result.inspectionComplete, false); assert.equal(result.errorCode, 'dom_incomplete');
  assert.equal(result.evidence.some(item => item.kind === 'dom_observation'), false);
});

test('policy blocks and capture failures cannot report a complete observation', async () => {
  const blocked = await runScan(input, doubles({ blockedRequest: true }).dependencies);
  assert.equal(blocked.networkAnalysis.blockedRequestCount, 1); assert.equal(blocked.inspectionComplete, false);
  const failed = await runScan(input, doubles({ screenshotFailure: true }).dependencies);
  assert.equal(failed.status, 'failed'); assert.equal(failed.screenshotStatus, 'failed'); assert.equal(failed.inspectionComplete, false);
  assert.equal(failed.capturedAt, null); assert.doesNotMatch(JSON.stringify(failed), /untrusted URL/);
});

test('unsafe targets never launch Chromium and sandbox launch failures are distinct', async () => {
  const fake = doubles(); fake.dependencies.checkUrl = async () => { throw Error('private target detail'); };
  const blocked = await runScan(input, fake.dependencies);
  assert.equal(fake.launchOptions, undefined); assert.equal(blocked.errorCode, 'unsafe_target');
  assert.equal(blocked.finalUrl, null); assert.equal(blocked.domAnalysis, null);
  const launch = await runScan(input, doubles({ launchFailure: true }).dependencies);
  assert.equal(launch.errorCode, 'browser_launch_failed'); assert.equal(launch.inspectionComplete, false);
});
