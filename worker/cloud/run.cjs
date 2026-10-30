'use strict';

// One read-only observation in a disposable VM. The caller must enforce and
// verify its network firewall; URL checks here are additional protection.
const fs = require('node:fs/promises');
const { Resolver } = require('node:dns/promises');
const { assertPublicHttpUrl } = require('../destination-policy.cjs');

const INPUT = '/tmp/qr-input.json';
const OUTPUT = '/tmp/qr-result.json';
const SHOT = '/tmp/qr-shot.png';
const MAX_PNG_BYTES = 1536 * 1024;
const LIMITS = [
  '초기 로딩과 짧은 관찰 구간만 검사했으며 사용자 상호작용은 수행하지 않았습니다.',
  '로그인·입력·폼 제출과 브랜드 모델 분석은 수행하지 않았습니다.',
];

function validateInput(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input) ||
      Object.keys(input).some(key => !['scanId', 'url', 'timeoutMs'].includes(key)) ||
      typeof input.scanId !== 'string' || !/^[A-Za-z0-9_-]{1,64}$/.test(input.scanId)) throw new Error('invalid_request');
  const timeoutMs = input.timeoutMs ?? 20000;
  if (!Number.isInteger(timeoutMs) || timeoutMs < 1000 || timeoutMs > 20000) throw new Error('invalid_request');
  return { scanId: input.scanId, url: input.url, timeoutMs };
}

function parseCandidate(value) {
  if (typeof value !== 'string' || value.length > 2048 ||
      !/^https?:\/\//i.test(value) || /[\s\\\x00-\x1f\x7f]/.test(value)) throw new Error('unsafe_target');
  const authority = value.slice(value.indexOf('://') + 3).split(/[/?#]/, 1)[0];
  if (!authority || authority.includes('@')) throw new Error('unsafe_target');
  let parsed;
  try { parsed = new URL(value); } catch { throw new Error('unsafe_target'); }
  if (!['http:', 'https:'].includes(parsed.protocol) || parsed.username || parsed.password ||
      (parsed.port && parsed.port !== (parsed.protocol === 'http:' ? '80' : '443'))) throw new Error('unsafe_target');
  if (parsed.hostname.replace(/^\[|\]$/g, '') === '168.63.129.16') throw new Error('unsafe_target');
  return parsed;
}

async function resolveHost(host) {
  const resolver = new Resolver();
  let timer;
  try {
    const results = await Promise.race([
      Promise.allSettled([resolver.resolve4(host), resolver.resolve6(host)]),
      new Promise((_, reject) => { timer = setTimeout(() => { resolver.cancel(); reject(new Error('dns_timeout')); }, 4000); }),
    ]);
    const rows = [];
    for (const [index, item] of results.entries()) {
      if (item.status === 'fulfilled') rows.push(...item.value.map(address => ({ address, family: index === 0 ? 4 : 6 })));
      else if (!['ENODATA', 'ENOTFOUND'].includes(item.reason?.code)) throw new Error('dns_unavailable');
    }
    if (!rows.length) throw new Error('dns_unavailable');
    return rows;
  } finally { clearTimeout(timer); }
}

async function publicUrl(value, resolver = resolveHost) {
  const parsed = parseCandidate(value);
  const checkedResolver = async host => {
    const rows = await resolver(host);
    if (rows.some(row => (typeof row === 'string' ? row : row.address) === '168.63.129.16')) throw new Error('unsafe_target');
    return rows;
  };
  await assertPublicHttpUrl(parsed.href, checkedResolver);
  return parsed.href;
}

async function allowedRequest(request, page, checkUrl = publicUrl) {
  try {
    if (!['GET', 'HEAD'].includes(request.method()) || request.postDataBuffer() !== null || request.frame().page() !== page) return false;
    await checkUrl(request.url());
    return true;
  } catch { return false; }
}

async function runScan(raw, dependencies = {}) {
  const io = dependencies.fs || fs;
  let input;
  try { input = validateInput(raw); }
  catch { return { scanId: typeof raw?.scanId === 'string' ? raw.scanId.slice(0, 64) : null, status: 'failed', finalUrl: null,
    httpStatus: null, pageTitle: null, domAnalysis: null, networkAnalysis: null, redirectAnalysis: null,
    signals: [], evidence: [], limitations: [...LIMITS], inspectionComplete: false,
    screenshotStatus: 'failed', errorCode: 'invalid_request', capturedAt: null }; }
  const result = { scanId: input.scanId, status: 'failed', finalUrl: null, httpStatus: null, pageTitle: null,
    domAnalysis: null, networkAnalysis: null, redirectAnalysis: null, signals: [], evidence: [],
    limitations: [...LIMITS], inspectionComplete: false, screenshotStatus: 'pending', errorCode: null, capturedAt: null };
  let browser, page, context, observer, network, redirect, dom;
  let expired = false, policyBlocked = 0, domFailed = false, screenshotComplete = false, captureChanged = false, targetValidated = false;
  const checkUrl = dependencies.checkUrl || publicUrl;
  const sleep = dependencies.sleep || (delay => new Promise(resolve => setTimeout(resolve, delay)));
  const timer = setTimeout(() => { expired = true; if (browser) void browser.close().catch(() => {}); }, input.timeoutMs);
  const assertTime = () => { if (expired) throw new Error('worker_timeout'); };
  const remaining = maximum => Math.max(1, Math.min(maximum, input.timeoutMs));
  try {
    await checkUrl(input.url); assertTime(); targetValidated = true;
    const chromium = dependencies.chromium || require('playwright').chromium;
    browser = await chromium.launch({ headless: true, chromiumSandbox: true, timeout: remaining(10000),
      args: ['--disable-quic', '--force-webrtc-ip-handling-policy=disable_non_proxied_udp'] });
    assertTime();
    context = await browser.newContext({ viewport: { width: 390, height: 844 }, serviceWorkers: 'block', acceptDownloads: false });
    await context.route('**/*', async route => {
      if (await allowedRequest(route.request(), page, checkUrl)) return route.continue();
      await route.abort(); policyBlocked++;
      network?.markPolicyBlocked(route.request()); redirect?.markPolicyBlocked(route.request());
    });
    await context.routeWebSocket('**/*', socket => { policyBlocked++; socket.close(); });
    page = await context.newPage();
    const createObserver = dependencies.createObserver || require('../observer.cjs').createObserver;
    const createNetworkAnalyzer = dependencies.createNetworkAnalyzer || require('../network-analyzer.cjs').createNetworkAnalyzer;
    const createRedirectAnalyzer = dependencies.createRedirectAnalyzer || require('../redirect-analyzer.cjs').createRedirectAnalyzer;
    const createDomAnalyzer = dependencies.createDomAnalyzer || require('../dom-analyzer.cjs').createDomAnalyzer;
    observer = createObserver(page, context, input.scanId, { observeNetwork: false, observeNavigation: false });
    network = createNetworkAnalyzer(page); redirect = createRedirectAnalyzer(page, { initialUrl: input.url }); dom = createDomAnalyzer(page);
    page.on('download', () => { policyBlocked++; });
    context.on('page', popup => { if (popup !== page) { policyBlocked++; void popup.close().catch(() => {}); } });
    const response = await page.goto(input.url, { waitUntil: 'domcontentloaded', timeout: remaining(10000) });
    result.httpStatus = response ? response.status() : null;
    assertTime(); await sleep(750); assertTime();
    try { await dom.collect(); } catch { domFailed = true; result.errorCode = 'dom_incomplete'; }
    assertTime();
    const capturedUrl = await checkUrl(page.url()); assertTime();
    const png = await page.screenshot({ fullPage: false, type: 'png', timeout: remaining(5000) });
    assertTime();
    if (!Buffer.isBuffer(png) || png.length < 24 || png.length > MAX_PNG_BYTES ||
        png.subarray(0, 8).toString('hex') !== '89504e470d0a1a0a') throw new Error('invalid_screenshot');
    const width = png.readUInt32BE(16), height = png.readUInt32BE(20);
    if (width !== 390 || height !== 844) throw new Error('invalid_screenshot');
    await io.writeFile(SHOT, png, { mode: 0o600 }); screenshotComplete = true;
    result.screenshotStatus = 'ready'; result.capturedAt = new Date().toISOString();
    result.finalUrl = await checkUrl(page.url()); assertTime();
    if (result.finalUrl !== capturedUrl) { captureChanged = true; result.limitations.push('촬영 중 페이지가 이동해 화면과 도착 주소의 대응을 확인하지 못했습니다.'); }
    if (result.httpStatus === null || result.httpStatus >= 400) result.limitations.push('페이지의 정상 HTTP 응답을 확인하지 못했습니다.');
    result.status = 'completed';
  } catch (error) {
    result.errorCode = expired ? 'worker_timeout' : ['invalid_screenshot', 'worker_timeout'].includes(error?.message)
      ? error.message : !targetValidated ? 'unsafe_target' : !browser ? 'browser_launch_failed' : 'browser_error';
    result.limitations.push('격리 브라우저 관찰을 완료하지 못했습니다.');
  } finally {
    clearTimeout(timer);
    network?.stop(); redirect?.stop(); dom?.stop(); observer?.stop();
    result.networkAnalysis = network?.result() ?? null;
    result.redirectAnalysis = redirect?.result() ?? null;
    result.domAnalysis = domFailed ? null : dom?.result() ?? null;
    result.pageTitle = result.domAnalysis?.pageTitle ?? null;
    const networkLimits = network?.limitations() ?? [], redirectLimits = redirect?.limitations() ?? [], domLimits = dom?.limitations() ?? [];
    const domObservation = dom?.observations().find(item => item.kind === 'dom_inspection');
    const networkFailed = (network?.observations() ?? []).some(item => item.outcome === 'network_failed' || item.statusCode >= 400);
    if (policyBlocked) result.limitations.push('접근 정책으로 차단된 요청이 있어 관찰 범위가 불완전합니다.');
    if (networkFailed) result.limitations.push('일부 리소스 요청 실패로 페이지 관찰 범위가 불완전합니다.');
    if (domFailed || !result.domAnalysis) result.limitations.push('DOM 관찰이 불완전합니다.');
    result.limitations = [...new Set([...result.limitations, ...networkLimits, ...redirectLimits, ...domLimits])];
    result.inspectionComplete = result.status === 'completed' && screenshotComplete && !!result.finalUrl &&
      result.httpStatus !== null && result.httpStatus < 400 && !!result.domAnalysis && domObservation?.incomplete === false &&
      !!result.networkAnalysis && !!result.redirectAnalysis && !networkLimits.length && !redirectLimits.length &&
      !policyBlocked && !networkFailed && !captureChanged && domLimits.every(item => [
        'Only accessible rendered DOM and open shadow roots are inspected; closed shadow roots are not observable.',
        'Official-domain comparison unavailable without a verified domain and resolver.',
      ].includes(item));
    if (observer) {
      if (result.httpStatus !== null) observer.record('navigation', '격리 브라우저의 페이지 응답을 관찰했습니다.', { httpStatus: result.httpStatus });
      if (result.domAnalysis) observer.record('dom_observation', '입력값을 읽거나 제출하지 않고 폼과 필드를 관찰했습니다.',
        { passwordFieldCount: result.domAnalysis.passwordFieldCount, formCount: result.domAnalysis.forms.length });
      if (result.networkAnalysis) observer.record('network_observation', '네트워크 요청과 정책 차단 수를 관찰했습니다.',
        { requestCount: result.networkAnalysis.requestCount, blockedRequestCount: result.networkAnalysis.blockedRequestCount, policyBlockedCount: policyBlocked });
      if (result.redirectAnalysis) observer.record('redirect_observation', '실제로 관찰한 페이지 이동을 기록했습니다.',
        { redirected: result.redirectAnalysis.redirected, redirectCount: result.redirectAnalysis.redirectChain.length });
      const observed = observer.result(); result.signals = observed.signals; result.evidence = observed.evidence;
    }
    if (!screenshotComplete) result.screenshotStatus = 'failed';
    if (browser) {
      let closeTimer;
      await Promise.race([browser.close().catch(() => {}), new Promise(resolve => { closeTimer = setTimeout(resolve, 2000); })]);
      clearTimeout(closeTimer);
    }
  }
  return result;
}

async function main() {
  try {
    await fs.rm(SHOT, { force: true });
    const stat = await fs.lstat(INPUT);
    if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 8192) throw new Error('invalid_request');
    const input = JSON.parse(await fs.readFile(INPUT, 'utf8'));
    const result = await runScan(input);
    await fs.writeFile(OUTPUT, JSON.stringify(result), { mode: 0o600 });
    process.stdout.write(JSON.stringify({ status: result.status }) + '\n');
    process.exitCode = result.status === 'completed' ? 0 : 1;
  } catch {
    process.stdout.write('{"status":"failed","errorCode":"runner_error"}\n');
    process.exitCode = 1;
  }
}

module.exports = { validateInput, parseCandidate, publicUrl, allowedRequest, runScan, MAX_PNG_BYTES };
if (require.main === module) main().then(() => process.exit(process.exitCode || 0));
