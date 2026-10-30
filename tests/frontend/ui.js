import '../../src/main.js';
import { urlVerdictDemoResponse } from '../../src/data/url-verdict-demo.js';

const fixture = document.getElementById('fixture');
const results = document.getElementById('results');
const summary = document.getElementById('summary');
const originalFetch = window.fetch;
const originalOpen = window.open;
const originalHistoryState = history.state;
const originalUrl = location.href;
const tests = [];
const INLINE_PNG = 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAIAAACQd1PeAAAADElEQVR4nGMwbPoGAAKRAapHxV+yAAAAAElFTkSuQmCC';

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function allDeep(root, selector) {
  const found = [...root.querySelectorAll(selector)];
  for (const element of root.querySelectorAll('*')) {
    if (element.shadowRoot) found.push(...allDeep(element.shadowRoot, selector));
  }
  return found;
}

function find(root, selector) {
  return allDeep(root, selector)[0] || null;
}

async function waitUntil(predicate, message = '예상한 화면이 표시되지 않았습니다.', timeout = 2200) {
  const deadline = performance.now() + timeout;
  while (!predicate()) {
    if (performance.now() > deadline) throw new Error(message);
    await new Promise((resolve) => setTimeout(resolve, 15));
  }
}

function scanResponse(url, overrides = {}) {
  return {
    scanId: 'ui-scan', requestedUrl: url, finalUrl: 'https://destination.example.test/checked',
    status: 'completed', verdict: 'clear', screenshotUrl: null,
    reportCount: 0, isReported: false, reportedByUser: false,
    checkedAt: '2026-10-31T01:00:00Z',
    signals: [{ summary: '화면 통합 검증용 관찰 근거', source: 'ui-fixture', evidenceIds: [] }],
    limitations: ['모의 API 응답이며 실제 검사가 아닙니다.'], ...overrides,
  };
}

function jsonResponse(payload) {
  return new Response(JSON.stringify(payload), { status: 200, headers: { 'Content-Type': 'application/json' } });
}

function installFetch(handler, requests) {
  window.fetch = (input, options = {}) => {
    const url = new URL(typeof input === 'string' ? input : input.url, location.href);
    const method = options.method || 'GET';
    assert(url.origin === location.origin, '외부 서버로 요청했습니다.');
    const creation = method === 'POST' && ['/api/analyze', '/api/scans'].includes(url.pathname);
    const report = method === 'POST' && /^\/api\/scans\/[\w-]+\/reports$/.test(url.pathname);
    const polling = method === 'GET' && /^\/api\/scans\/[\w-]+$/.test(url.pathname);
    assert(creation || report || polling, '허용되지 않은 API 경로·메서드로 요청했습니다.');
    assert(options.redirect === 'error', 'API 리다이렉트 차단 설정이 없습니다.');
    const request = { path: url.pathname, method, body: options.body === undefined ? null : JSON.parse(options.body), signal: options.signal };
    requests.push(request);
    return new Promise((resolve, reject) => {
      const abort = () => reject(new DOMException('모의 요청 취소', 'AbortError'));
      if (options.signal?.aborted) return abort();
      options.signal?.addEventListener('abort', abort, { once: true });
      Promise.resolve().then(() => handler(request)).then(resolve, reject).finally(() => {
        options.signal?.removeEventListener('abort', abort);
      });
    });
  };
}

function mount() {
  const app = document.createElement('qr-app');
  fixture.append(app);
  return app;
}

function enterUrl(app, url = 'https://input.example.test/start?token=private#secret') {
  const scan = find(app.shadowRoot, 'qr-scan-page');
  assert(scan?.shadowRoot, '스캔 화면의 open Shadow DOM이 없습니다.');
  scan.shadowRoot.querySelector('input').value = url;
  const event = new Event('submit', { bubbles: true, cancelable: true });
  scan.shadowRoot.querySelector('form').dispatchEvent(event);
  assert(event.defaultPrevented, '폼 제출의 기본 동작을 차단하지 않았습니다.');
  return url;
}

function cameraQr(app, value) {
  const scan = find(app.shadowRoot, 'qr-scan-page');
  const scanner = scan.shadowRoot.querySelector('qr-camera-scanner');
  scanner.dispatchEvent(new CustomEvent('qr-detected', {
    detail: { value, source: 'camera' }, bubbles: true, composed: true,
  }));
  return scan;
}

function deepActiveElement() {
  let active = document.activeElement;
  while (active?.shadowRoot?.activeElement) active = active.shadowRoot.activeElement;
  return active;
}

async function resultPage(app) {
  await waitUntil(() => find(app.shadowRoot, 'qr-result-page'));
  return find(app.shadowRoot, 'qr-result-page');
}

function noDestinationLinks(app) {
  assert(allDeep(app.shadowRoot, 'a[href]').every((anchor) => new URL(anchor.href, location.href).origin === location.origin), '피싱 결과에 목적지 링크가 있습니다.');
  assert(!allDeep(app.shadowRoot, 'button').some((button) => button.textContent.includes('사이트 들어가기')), '접속 불가 판정에 접속 버튼이 있습니다.');
}

test('격리 PNG를 정적 Blob 이미지로 표시하고 재스캔 시 해제하며 목적지를 요청하지 않는다', async ({ app, requests, opened, mock }) => {
  mock((request) => jsonResponse({
    scanId: 'ui-scan', requestedUrl: request.body.url, status: 'completed', mode: 'sandbox', analysisScope: 'sandbox',
    staticAnalysis: { status: 'completed', signals: [], providers: [], limitations: [] },
    sandboxAnalysis: { status: 'completed', finalUrl: 'https://destination.example.test/checked', httpStatus: 200,
      screenshot: { status: 'ready', available: true }, signals: [], limitations: [] },
    previewImage: { scanId: 'ui-scan', mimeType: 'image/png', base64: INLINE_PNG },
    verdict: { level: 'unknown', reasons: ['화면을 관찰했으며 브랜드 판단은 보류했습니다.'], evidenceIds: [], limitations: [] },
    evidence: [], reportAvailable: false, reportCount: null,
  }));
  enterUrl(app);
  const page = await resultPage(app);
  const preview = page.shadowRoot.querySelector('qr-site-preview');
  const image = preview.shadowRoot.querySelector('img');
  await waitUntil(() => !image.hidden && image.complete && image.naturalWidth === 1, '격리 PNG를 실제 이미지로 디코딩하지 못했습니다.');
  const objectUrl = image.src;
  assert(objectUrl.startsWith('blob:') && !preview.shadowRoot.querySelector('.caption').hidden, '정적 Blob 이미지가 아닙니다.');
  assert(requests.length === 1 && opened.length === 0, '이미지 표시 중 추가 요청이나 목적지 접속이 발생했습니다.');
  noDestinationLinks(app);
  const revoked = [];
  const originalRevoke = URL.revokeObjectURL;
  URL.revokeObjectURL = (value) => { revoked.push(value); originalRevoke.call(URL, value); };
  try {
    page.shadowRoot.querySelector('.rescan').click();
    assert(revoked.includes(objectUrl) && find(app.shadowRoot, 'qr-scan-page'), '이전 미리보기 자원을 해제하지 않았습니다.');
  } finally { URL.revokeObjectURL = originalRevoke; }
});

function test(name, run) { tests.push({ name, run }); }

test('수동 입력 → 로딩 → 정상 결과 → 명시적 클릭으로만 사이트 열기', async ({ app, requests, opened, mock }) => {
  let release;
  mock((request) => new Promise((resolve) => { release = () => resolve(jsonResponse(scanResponse(request.body.url))); }));
  const url = enterUrl(app);
  assert(find(app.shadowRoot, 'qr-loading-page'), '2뎁스 로딩 화면이 없습니다.');
  await waitUntil(() => release);
  assert(opened.length === 0, '검사 중 목적지를 열었습니다.');
  release();
  const page = await resultPage(app);
  const button = page.shadowRoot.querySelector('.main-action');
  assert(!button.disabled && button.textContent.includes('사이트 들어가기'), '정상 결과 접속 버튼이 없습니다.');
  assert(opened.length === 0, '결과 진입만으로 목적지를 열었습니다.');
  assert(requests.length === 1 && requests[0].body.url === url, '입력 URL이 검사 요청 본문과 다릅니다.');
  assert(requests[0].body.source === 'manual', '수동 입력 출처를 서버에 전달하지 않았습니다.');
  assert(!page.shadowRoot.getElementById('requested').textContent.includes('private'), '결과에 URL 토큰을 노출했습니다.');
  button.click();
  assert(opened.length === 1, '사용자 클릭당 사이트 열기가 한 번이어야 합니다.');
  assert(opened[0][0] === 'https://destination.example.test/checked', '검사된 최종 주소와 열린 주소가 다릅니다.');
  assert(opened[0][2] === 'noopener,noreferrer', '새 창 격리 옵션이 없습니다.');
});

test('프로토콜 없는 카메라 QR은 HTTPS로 검사하며 수동 입력창을 열거나 포커스를 빼앗지 않음', async ({ app, requests, opened, mock }) => {
  let requestedUrl;
  mock((request) => {
    if (request.method === 'POST') {
      requestedUrl = request.body.url;
      return jsonResponse({ scanId: 'ui-scan', status: 'queued', mode: 'sandbox' });
    }
    return jsonResponse(scanResponse(requestedUrl));
  });
  const scan = find(app.shadowRoot, 'qr-scan-page');
  const input = scan.shadowRoot.querySelector('input');
  const manual = scan.shadowRoot.querySelector('.manual-entry');
  const cameraButton = scan.shadowRoot.querySelector('qr-camera-scanner').shadowRoot.querySelector('button');
  let inputFocuses = 0;
  input.addEventListener('focus', () => { inputFocuses += 1; });
  cameraButton.focus();
  cameraQr(app, 'www.input.example.test/start');
  assert(find(app.shadowRoot, 'qr-loading-page'), 'QR 인식 후 로딩으로 진행하지 않았습니다.');
  assert(!manual.open && inputFocuses === 0, 'QR을 읽은 뒤 수동 입력창으로 포커스를 옮겼습니다.');
  await resultPage(app);
  assert(requestedUrl === 'https://www.input.example.test/start', 'QR 주소에 HTTPS를 정확히 보완하지 않았습니다.');
  assert(requests[0].method === 'POST' && requests[0].body.mode === 'sandbox' && requests[0].body.source === 'qr', '정규화 후 올바른 검사 요청을 보내지 않았습니다.');
  assert(requests.some((request) => request.method === 'GET'), '생성된 검사 상태를 조회하지 않았습니다.');
  assert(inputFocuses === 0 && opened.length === 0, '결과 전환 중 수동 입력 포커스 또는 목적지 열기가 발생했습니다.');
});

test('URL이 아닌 카메라 QR은 촬영 화면에서 오류를 알리고 수동 입력·포커스를 보존', async ({ app, requests, opened }) => {
  const scan = find(app.shadowRoot, 'qr-scan-page');
  const scanner = scan.shadowRoot.querySelector('qr-camera-scanner');
  const input = scan.shadowRoot.querySelector('input');
  const manual = scan.shadowRoot.querySelector('.manual-entry');
  input.value = 'previous.example.test/path';
  const cameraButton = scanner.shadowRoot.querySelector('button');
  cameraButton.focus();
  cameraQr(app, 'WIFI:T:WPA;S:demo;P:demo;;');
  assert(find(app.shadowRoot, 'qr-scan-page') === scan, '잘못된 QR이 검사 화면으로 전환됐습니다.');
  assert(!manual.open && input.value === 'previous.example.test/path', '카메라 오류가 수동 입력 상태를 변경했습니다.');
  assert(deepActiveElement() === cameraButton, '카메라 QR 오류로 포커스를 빼앗았습니다.');
  assert(scanner.shadowRoot.querySelector('.state.error')?.textContent.trim(), '촬영 화면에 QR 오류가 표시되지 않았습니다.');
  assert(requests.length === 0 && opened.length === 0, '잘못된 QR로 네트워크 요청 또는 목적지 열기가 발생했습니다.');
});

test('직접 입력한 프로토콜 없는 주소도 HTTPS로 검사하고 잘못된 수동 입력은 해당 입력에 안내', async ({ app, requests, mock }) => {
  const scan = find(app.shadowRoot, 'qr-scan-page');
  const input = scan.shadowRoot.querySelector('input');
  enterUrl(app, 'not a website');
  assert(scan.shadowRoot.querySelector('.manual-entry').open, '잘못된 수동 입력창이 펼쳐지지 않았습니다.');
  assert(deepActiveElement() === input && input.getAttribute('aria-invalid') === 'true', '수동 입력 오류의 포커스·필드 표시가 없습니다.');
  assert(requests.length === 0, '잘못된 수동 입력을 API로 전송했습니다.');
  mock((request) => jsonResponse(scanResponse(request.body.url)));
  enterUrl(app, 'input.example.test:8443/path?step=1#done');
  await resultPage(app);
  assert(requests.length === 1 && requests[0].body.url === 'https://input.example.test:8443/path?step=1#done', '수동 입력의 HTTPS 보완 또는 경로 보존에 실패했습니다.');
});

test('피싱 결과는 목적지 진입 없이 신고 건수·이력과 신고 버튼 제공', async ({ app, requests, opened, mock }) => {
  mock((request) => jsonResponse(request.path.endsWith('/reports')
    ? { reportCount: 129, reportedByUser: true }
    : scanResponse(request.body.url, { verdict: 'phishing', reportCount: 128, isReported: true })));
  enterUrl(app);
  const page = await resultPage(app);
  noDestinationLinks(app);
  assert(page.shadowRoot.getElementById('report-count').textContent === '128', '서버 신고 건수가 표시되지 않았습니다.');
  assert(page.shadowRoot.querySelector('.report-scope').textContent.includes('현재 서버'), '신고 집계 범위가 표시되지 않았습니다.');
  assert(page.shadowRoot.querySelector('.report-history').textContent.includes('이전에 신고'), '신고 이력 안내가 없습니다.');
  const button = page.shadowRoot.querySelector('.main-action');
  assert(!button.disabled, '다른 사람의 신고 이력으로 현재 사용자 신고를 막았습니다.');
  button.click(); button.click();
  await waitUntil(() => button.textContent.includes('신고 완료'));
  assert(button.disabled, '신고 완료 후 중복 신고를 막지 않았습니다.');
  assert(requests.filter((request) => request.path.endsWith('/reports')).length === 1, '신고 요청이 중복 발생했습니다.');
  assert(page.shadowRoot.getElementById('report-count').textContent === '129', '신고 성공 후 서버 집계값을 반영하지 않았습니다.');
  assert(opened.length === 0, '피싱 결과에서 사이트를 열었습니다.');
});

test('신고 실패는 기존 결과·건수를 보존하고 재시도 제공', async ({ app, mock }) => {
  mock((request) => request.path.endsWith('/reports')
    ? Promise.reject(new TypeError('모의 네트워크 오류'))
    : jsonResponse(scanResponse(request.body.url, { verdict: 'phishing', reportCount: 128 })));
  enterUrl(app);
  const page = await resultPage(app);
  const button = page.shadowRoot.querySelector('.main-action');
  button.click();
  await waitUntil(() => page.shadowRoot.querySelector('.report-status').classList.contains('error'));
  assert(!button.disabled && button.textContent.includes('다시 시도'), '신고 실패 재시도 동작이 없습니다.');
  assert(page.shadowRoot.getElementById('report-count').textContent === '128', '실패한 신고를 건수에 반영했습니다.');
  noDestinationLinks(app);
});

test('실제 백엔드 형식의 판정 이유·미방문 사유·신고 집계를 표시', async ({ app, requests, mock }) => {
  let requestedUrl;
  mock((request) => {
    if (request.path.endsWith('/reports')) return jsonResponse({ scanId: 'ui-scan', reportCount: 3, isReported: true, reportedByUser: true });
    if (request.method === 'POST') {
      requestedUrl = request.body.url;
      return jsonResponse({ scanId: 'ui-scan', status: 'queued', mode: 'sandbox' });
    }
    return jsonResponse({
      scanId: 'ui-scan', requestedUrl, status: 'completed', mode: 'sandbox',
      staticAnalysis: { status: 'completed', signals: [], providers: [], limitations: [] },
      sandboxAnalysis: { status: 'skipped', skipReason: 'known_malicious', screenshot: { status: 'skipped', available: false }, signals: [], limitations: [] },
      verdict: { level: 'malicious', reasons: ['위협 목록에서 발견된 주소예요.'], evidenceIds: ['ev-google'], limitations: [] },
      evidence: [{ id: 'ev-google', kind: 'known_threat_match', source: 'google_safe_browsing', summary: '위협 목록 일치', observedAt: '2026-10-31T01:00:00Z' }],
      reportCount: 2, isReported: true, reportedByUser: false,
    });
  });
  enterUrl(app);
  const page = await resultPage(app);
  assert(page.shadowRoot.querySelector('.decision-reasons').textContent.includes('위협 목록에서 발견된 주소'), '서버 판정 이유가 표시되지 않았습니다.');
  const reference = page.shadowRoot.querySelector('.references').textContent;
  assert(reference.includes('위협 목록 일치') && !reference.includes('ev-google'), '판정 근거의 설명 대신 내부 식별자가 노출되었습니다.');
  assert(page.shadowRoot.querySelector('qr-site-preview').shadowRoot.querySelector('.empty p').textContent.includes('방문하지 않았어요'), '이미지가 없는 이유를 구별하지 않았습니다.');
  assert(page.shadowRoot.getElementById('report-count').textContent === '2', '서버 신고 집계가 누락되었습니다.');
  page.shadowRoot.querySelector('.main-action').click();
  await waitUntil(() => page.shadowRoot.getElementById('report-count').textContent === '3');
  assert(requests.filter((request) => request.path.endsWith('/reports')).length === 1, '신고 접수 요청이 다릅니다.');
  noDestinationLinks(app);
});

test('카메라·수동 입력을 시작하기 전 Google URL 전송을 안내', async ({ app, requests }) => {
  const scan = find(app.shadowRoot, 'qr-scan-page');
  const notice = scan.shadowRoot.querySelector('.privacy');
  assert(notice && notice.textContent.includes('주소가 Google에 전송'), '검사 전 URL 전송 안내가 없습니다.');
  assert(notice.compareDocumentPosition(scan.shadowRoot.querySelector('qr-camera-scanner')) & Node.DOCUMENT_POSITION_FOLLOWING, '카메라 시작 전 안내를 확인할 수 없습니다.');
  assert(requests.length === 0, '안내를 표시하는 것만으로 검사 요청이 발생했습니다.');
});

test('공개 주소 검사 결과는 화면 미확인을 안내하고 원본 주소만 명시적 클릭으로 연다', async ({ app, opened, mock }) => {
  mock((request) => jsonResponse(scanResponse(request.body.url, {
    analysisScope: 'static', reportAvailable: false, finalUrl: null, reportCount: null, isReported: null,
    previewMessage: '사이트 화면 미리보기는 점검 중이에요',
  })));
  const url = enterUrl(app, 'https://input.example.test/');
  const page = await resultPage(app);
  const verdict = page.shadowRoot.querySelector('qr-verdict-summary');
  assert(verdict.shadowRoot.querySelector('h2').textContent.includes('주소 검사'), '주소 검사와 화면 검사를 구분하지 않았습니다.');
  assert(verdict.shadowRoot.querySelector('.copy').textContent.includes('사이트 화면과 최종 목적지는 확인하지 않았어요'), '검사 한계가 결과 앞부분에 없습니다.');
  assert(page.shadowRoot.getElementById('final').textContent.includes('미확인'), '확인하지 않은 도착 주소를 표시했습니다.');
  assert(page.shadowRoot.querySelector('qr-site-preview').shadowRoot.querySelector('.empty p').textContent.includes('점검 중'), '미리보기 점검 안내가 없습니다.');
  assert(opened.length === 0, '결과만으로 원본 사이트를 열었습니다.');
  page.shadowRoot.querySelector('.main-action').click();
  assert(opened.length === 1 && opened[0][0] === url, '정적 완료 결과에서 명시한 원본 주소를 열지 않았습니다.');
});

test('공개 피싱 판정은 신고 준비 중과 미확인 건수를 표시하고 접수·접속하지 않는다', async ({ app, opened, requests, mock }) => {
  mock((request) => jsonResponse(scanResponse(request.body.url, { verdict: 'phishing', analysisScope: 'static',
    reportAvailable: false, reportCount: null, isReported: null, finalUrl: null })));
  enterUrl(app);
  const page = await resultPage(app);
  const button = page.shadowRoot.querySelector('.main-action');
  assert(button.disabled && button.textContent.includes('신고 기능 준비 중'), '신고 미제공 상태에서 접수 버튼을 활성화했습니다.');
  assert(page.shadowRoot.getElementById('report-count').textContent === '확인 불가', '신고 미제공 건수를 0건으로 표시했습니다.');
  const before = requests.length;
  button.click();
  page.dispatchEvent(new CustomEvent('report-request', { bubbles: true, composed: true }));
  await new Promise(resolve => setTimeout(resolve, 20));
  assert(requests.length === before, '신고 미제공 상태에서 요청을 보냈습니다.');
  noDestinationLinks(app);
  assert(opened.length === 0, '피싱 결과에서 목적지를 열었습니다.');
});

test('공개 목록 미일치는 판단 보류로 접속을 막고 조회 실패를 미탐지라고 설명하지 않는다', async ({ app, opened, mock }) => {
  let lookupFailed = false;
  mock((request) => jsonResponse(scanResponse(request.body.url, {
    verdict: 'inconclusive', analysisScope: 'static', reportAvailable: false, finalUrl: null,
    providers: [{ name: 'google_safe_browsing', status: lookupFailed ? 'failed' : 'checked', matched: lookupFailed ? null : false }],
  })));
  enterUrl(app);
  let page = await resultPage(app);
  let verdict = page.shadowRoot.querySelector('qr-verdict-summary');
  assert(verdict.shadowRoot.querySelector('h2').textContent.includes('판단을 보류'), '목록 미일치를 정상 결과로 안내했습니다.');
  assert(verdict.shadowRoot.querySelector('.copy').textContent.includes('사이트 화면과 동작은 확인하지 못했어요'), '미관찰 범위 안내가 없습니다.');
  noDestinationLinks(app);
  assert(opened.length === 0, '판단 보류에서 목적지를 열었습니다.');
  page.shadowRoot.querySelector('.rescan').click();
  await waitUntil(() => find(app.shadowRoot, 'qr-scan-page'));
  lookupFailed = true;
  enterUrl(app);
  page = await resultPage(app);
  verdict = page.shadowRoot.querySelector('qr-verdict-summary');
  assert(!verdict.shadowRoot.querySelector('.copy').textContent.includes('발견되지 않았지만'), '조회 실패를 목록 미일치로 설명했습니다.');
  noDestinationLinks(app);
});

test('주소 검사 로딩은 화면 미확인 범위를 안내한다', async ({ app, mock }) => {
  mock(() => new Promise(() => {}));
  enterUrl(app);
  const loading = find(app.shadowRoot, 'qr-loading-page');
  loading.analysisScope = 'static';
  assert(!loading.shadowRoot.querySelector('.scope').hidden, '주소 검사 범위가 숨겨져 있습니다.');
  assert(loading.shadowRoot.querySelector('h1').textContent.includes('주소를 검사'), '주소 검사 제목이 구분되지 않았습니다.');
  loading.shadowRoot.querySelector('.cancel').click();
});

test('알 수 없는 판정은 확인 불가로 처리하고 사이트 접속 제공 안 함', async ({ app, opened, mock }) => {
  mock((request) => jsonResponse(scanResponse(request.body.url, { verdict: 'unexpected-value', reportCount: null })));
  enterUrl(app);
  await resultPage(app);
  noDestinationLinks(app);
  assert(opened.length === 0, '알 수 없는 판정에서 사이트를 열었습니다.');
});

test('진행 중인 검사 응답은 로딩에서 계속 조회하며 접속을 제공하지 않고 취소 가능', async ({ app, requests, opened, mock }) => {
  let requestedUrl;
  mock((request) => {
    if (request.method === 'POST') {
      requestedUrl = request.body.url;
      return jsonResponse({ scanId: 'ui-scan', status: 'queued', mode: 'sandbox' });
    }
    return jsonResponse(scanResponse(requestedUrl, { status: 'running', verdict: null }));
  });
  enterUrl(app);
  await waitUntil(() => requests.some((request) => request.method === 'GET'));
  const loading = find(app.shadowRoot, 'qr-loading-page');
  assert(loading && !loading.shadowRoot.querySelector('section.error'), '진행 중인 작업을 오류로 처리했습니다.');
  noDestinationLinks(app);
  assert(!find(app.shadowRoot, 'qr-result-page'), '미완료 결과를 정상 완료로 표시했습니다.');
  assert(opened.length === 0, '미완료 상태에서 목적지를 열었습니다.');
  loading.shadowRoot.querySelector('.cancel').click();
  assert(find(app.shadowRoot, 'qr-scan-page') && requests.every((request) => request.signal.aborted), '진행 중 작업의 클라이언트 조회를 취소하지 못했습니다.');
});

test('취소 후 늦은 이전 응답은 새 검사의 결과를 덮어쓰지 않음', async ({ app, requests, mock }) => {
  let releaseBody;
  let first = true;
  mock((request) => {
    if (!first) return jsonResponse(scanResponse(request.body.url, { verdict: 'phishing', scanId: 'new-scan', reportCount: 64 }));
    first = false;
    return { ok: true, json: () => new Promise((resolve) => { releaseBody = () => resolve(scanResponse(request.body.url)); }) };
  });
  enterUrl(app, 'https://old.example.test/');
  await waitUntil(() => releaseBody);
  find(app.shadowRoot, 'qr-loading-page').shadowRoot.querySelector('.cancel').click();
  assert(requests[0].signal.aborted, '취소 시 검사 요청을 중단하지 않았습니다.');
  enterUrl(app, 'https://new.example.test/');
  const page = await resultPage(app);
  releaseBody();
  await new Promise((resolve) => setTimeout(resolve, 40));
  assert(find(app.shadowRoot, 'qr-result-page') === page, '과거 응답이 현재 화면을 교체했습니다.');
  assert(page.shadowRoot.getElementById('report-count').textContent === '64', '새 검사 결과가 과거 응답으로 바뀌었습니다.');
  noDestinationLinks(app);
});

test('실제 API 네트워크 실패가 데모 성공으로 대체되지 않음', async ({ app, requests, mock }) => {
  mock(() => Promise.reject(new TypeError('모의 연결 실패')));
  enterUrl(app);
  await waitUntil(() => find(app.shadowRoot, 'qr-loading-page')?.shadowRoot.querySelector('section.error'));
  assert(requests.length === 1, 'API 실패 후 불필요한 추가 요청이 발생했습니다.');
  assert(!find(app.shadowRoot, 'qr-result-page'), '연결 실패를 데모 결과로 바꿨습니다.');
  assert(app.shadowRoot.querySelector('.demo-banner').hidden, '실제 검사 요청이 데모 모드로 전환됐습니다.');
});

test('지정 URL 데모의 로딩·결과 표시는 활성 상태를 따르고 재스캔하면 초기화된다', async ({ app, requests, opened, mock }) => {
  mock((request) => jsonResponse(scanResponse(request.body.url, { verdict: 'inconclusive', finalUrl: null })));
  for (const [url, reason] of [
    ['https://realistic-phishing-website.vercel.app/', '로고와 주소 불일치'],
    ['https://fake-phishing-website.vercel.app/', '동적 판단에서 감지'],
  ]) {
    const enabled = urlVerdictDemoResponse(url) !== null;
    const before = requests.length;
    enterUrl(app, url);
    const banner = app.shadowRoot.querySelector('.demo-banner');
    assert(find(app.shadowRoot, 'qr-loading-page') && banner.hidden === !enabled, '로딩 화면에서 URL 데모 여부를 표시하지 않았습니다.');
    const page = await resultPage(app);
    assert(banner.hidden === !enabled, '결과 화면에서 URL 데모 여부를 표시하지 않았습니다.');
    assert(requests.length - before === (enabled ? 0 : 1), 'URL 데모 활성 상태와 검사 요청이 다릅니다.');
    if (enabled) {
      assert(banner.textContent.includes('데모 응답 · 실제 검사 아님'), '실제 검사와 구별하는 안내가 없습니다.');
      assert(page.shadowRoot.querySelector('.decision-reasons').textContent.includes(reason), 'URL별 탐지 사유가 표시되지 않았습니다.');
      const button = page.shadowRoot.querySelector('.main-action');
      assert(button.disabled && button.textContent.includes('신고 기능 준비 중'), '모의 결과에서 실제 신고를 허용했습니다.');
      assert(page.shadowRoot.getElementById('report-count').textContent === '확인 불가', '모의 신고 건수를 만들었습니다.');
      assert(page.shadowRoot.getElementById('final').textContent.includes('미확인'), '방문하지 않은 도착 주소를 만들었습니다.');
      button.click();
      page.dispatchEvent(new CustomEvent('report-request', { bubbles: true, composed: true }));
      page.dispatchEvent(new CustomEvent('open-site-request', { bubbles: true, composed: true }));
    }
    noDestinationLinks(app);
    assert(opened.length === 0 && requests.length - before === (enabled ? 0 : 1), '모의 결과에서 목적지 접속·신고 요청이 발생했습니다.');
    page.shadowRoot.querySelector('.rescan').click();
    assert(find(app.shadowRoot, 'qr-scan-page') && banner.hidden, '재스캔 후 URL 데모 표시가 남았습니다.');
  }
});

test('지정 URL 검사 취소는 데모 표시를 지우고 늦은 결과를 표시하지 않는다', async ({ app, requests, mock }) => {
  const url = 'https://fake-phishing-website.vercel.app/';
  const enabled = urlVerdictDemoResponse(url) !== null;
  mock(() => new Promise(() => {}));
  enterUrl(app, url);
  find(app.shadowRoot, 'qr-loading-page').shadowRoot.querySelector('.cancel').click();
  assert(find(app.shadowRoot, 'qr-scan-page') && app.shadowRoot.querySelector('.demo-banner').hidden, '취소 후 촬영 화면과 데모 표시가 초기화되지 않았습니다.');
  await new Promise((resolve) => setTimeout(resolve, 1500));
  assert(!find(app.shadowRoot, 'qr-result-page'), '취소한 URL 검사의 늦은 결과를 표시했습니다.');
  assert(enabled ? requests.length === 0 : requests.every((request) => request.signal.aborted), '취소한 검사 요청을 정리하지 않았습니다.');
});

test('다시 스캔과 앱 재마운트는 검사·입력 상태를 초기화', async ({ app, mock }) => {
  mock((request) => jsonResponse(scanResponse(request.body.url, { verdict: 'phishing' })));
  enterUrl(app);
  const page = await resultPage(app);
  page.shadowRoot.querySelector('.rescan').click();
  const scan = find(app.shadowRoot, 'qr-scan-page');
  assert(scan && scan.shadowRoot.querySelector('input').value === '', '다시 스캔 후 이전 URL이 남았습니다.');
  assert(!find(app.shadowRoot, 'qr-result-page'), '다시 스캔 후 결과가 남았습니다.');
  app.remove();
  const fresh = mount();
  try {
    assert(find(fresh.shadowRoot, 'qr-scan-page'), '초기 화면이 1뎁스가 아닙니다.');
    assert(!find(fresh.shadowRoot, 'qr-result-page'), '재마운트 후 결과가 복원됐습니다.');
    assert(!location.href.includes('token='), '앱 주소에 검사 URL을 저장했습니다.');
  } finally { fresh.remove(); }
});

test('모든 UI Custom Element가 open Shadow DOM을 제공', async ({ app }) => {
  const elements = [app, ...allDeep(app.shadowRoot, '*').filter((element) => element.localName.startsWith('qr-'))];
  assert(elements.length >= 3, '컴포넌트 구성이 확인되지 않습니다.');
  assert(elements.every((element) => element.shadowRoot?.mode === 'open'), 'open Shadow DOM이 없는 UI 컴포넌트가 있습니다.');
});

let passed = 0;
const uncaught = [];
const captureError = (event) => uncaught.push(event.type);
window.addEventListener('error', captureError);
window.addEventListener('unhandledrejection', captureError);

try {
  for (const entry of tests) {
    const requests = [];
    const opened = [];
    window.open = (...args) => { opened.push(args); return null; };
    installFetch(() => { throw new Error('설정되지 않은 API 요청입니다.'); }, requests);
    const app = mount();
    const item = document.createElement('li');
    try {
      await entry.run({ app, requests, opened, mock: (handler) => installFetch(handler, requests) });
      assert(uncaught.length === 0, '처리되지 않은 브라우저 오류가 발생했습니다.');
      item.dataset.pass = 'true'; item.textContent = `통과 · ${entry.name}`; passed += 1;
    } catch (error) {
      item.dataset.pass = 'false'; item.textContent = `실패 · ${entry.name}: ${error.message}`;
    } finally {
      fixture.replaceChildren();
      window.fetch = originalFetch;
      window.open = originalOpen;
      history.replaceState(originalHistoryState, '', originalUrl);
      uncaught.length = 0;
    }
    results.append(item);
  }
} finally {
  window.removeEventListener('error', captureError);
  window.removeEventListener('unhandledrejection', captureError);
  window.fetch = originalFetch;
  window.open = originalOpen;
  fixture.replaceChildren();
  history.replaceState(originalHistoryState, '', originalUrl);
}

summary.textContent = `${tests.length}개 중 ${passed}개 통과`;
summary.dataset.pass = String(passed === tests.length);
document.documentElement.dataset.testsComplete = 'true';
