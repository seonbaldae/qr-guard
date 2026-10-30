import { validateUrl, displayUrl } from '../../src/utils/url.js';
import { normalizeScanResponse, previewUrl } from '../../src/services/response-adapter.js';
import { analyzeUrl } from '../../src/services/scan-api.js';
import { reportSite } from '../../src/services/report-api.js';
import { loadPreviewImage } from '../../src/services/preview-api.js';
import { createRequestScope, waitFor } from '../../src/services/http.js';

const TEST_URL = 'https://example.test/survey';
const response = (overrides = {}) => ({
  scanId: 'test-123', requestedUrl: TEST_URL, status: 'completed', verdict: 'clear',
  finalUrl: null, reportCount: 0, isReported: false, reportedByUser: false,
  limitations: ['모의 응답입니다.'], ...overrides,
});

// Shape returned by the Python backend (API contract v0.2).
const backendReport = (overrides = {}) => ({
  scanId: 'test-123', status: 'completed', mode: 'sandbox', requestedUrl: TEST_URL,
  staticAnalysis: {
    status: 'completed', registeredDomain: 'example.test', signals: [],
    providers: [{ name: 'google-safebrowsing', status: 'checked', matched: false, checkedAt: '2026-10-31T00:00:00Z' }],
    limitations: ['정적 한계'],
  },
  sandboxAnalysis: {
    status: 'completed', skipReason: null, finalUrl: TEST_URL, httpStatus: 200,
    screenshot: { status: 'ready', available: true, capturedAt: '2026-10-31T00:00:02Z', expiresAt: null },
    signals: [], limitations: [],
  },
  evidence: [],
  verdict: { level: 'no_known_threat', reasons: [], evidenceIds: [], limitations: ['판정 한계'] },
  updatedAt: '2026-10-31T00:00:02Z',
  ...overrides,
});

function assert(value, message = '기대 동작과 다릅니다.') {
  if (!value) throw new Error(message);
}

async function rejects(task, predicate = () => true) {
  try { await task(); } catch (error) { assert(predicate(error), '오류 처리 상태가 다릅니다.'); return; }
  throw new Error('거부해야 하는 작업이 허용되었습니다.');
}

async function withFetch(fakeFetch, task) {
  const original = globalThis.fetch;
  globalThis.fetch = fakeFetch;
  try { await task(); } finally { globalThis.fetch = original; }
}

export async function runServiceTests() {
  const results = [];
  async function test(name, task) {
    try { await task(); results.push({ name, passed: true }); }
    catch (error) { results.push({ name, passed: false, message: error.message }); }
  }

  await test('허용된 절대 HTTP(S) 주소를 정규화한다', () => {
    assert(validateUrl('  HTTPS://EXAMPLE.TEST:443  ') === 'https://example.test/');
    assert(validateUrl('http://example.test/path') === 'http://example.test/path');
  });
  await test('실행 가능한 프로토콜·상대 주소·계정 포함 주소를 거부한다', async () => {
    for (const invalid of ['javascript:alert(1)', 'data:text/html,test', '//example.test', 'example.test', 'https://name:secret@example.test', 'https://@example.test', 'https://example.test/\npath', 'https://example.test\\@other.test']) {
      await rejects(() => validateUrl(invalid));
    }
  });
  await test('브라우저가 보정할 수 있는 빈 호스트·추가 슬래시 주소도 거부한다', async () => {
    for (const invalid of ['https:///example.test', 'https:////example.test/path', 'https://?', 'https://#fragment', 'https://']) {
      await rejects(() => validateUrl(invalid));
    }
  });
  await test('표시 주소에는 쿼리·해시의 개인정보를 남기지 않는다', () => {
    const text = displayUrl('https://example.test/path?token=private-token#private-fragment');
    assert(!text.includes('private') && !text.includes('token='));
  });
  await test('정적 단계의 완료·빈 신호만으로 정상 판정을 만들지 않는다', () => {
    const { verdict } = normalizeScanResponse(response({ verdict: undefined, signals: [] }), TEST_URL);
    assert(verdict === 'inconclusive');
  });
  await test('검사 미완료 또는 알 수 없는 판정은 접속 허용 판정이 아니다', () => {
    assert(normalizeScanResponse(response({ status: 'running' }), TEST_URL).verdict === 'inconclusive');
    assert(normalizeScanResponse(response({ verdict: 'new-value' }), TEST_URL).verdict === 'inconclusive');
  });
  await test('다른 URL의 응답을 현재 검사 결과로 사용하지 않는다', async () => {
    await rejects(() => normalizeScanResponse(response({ requestedUrl: 'https://other.test/' }), TEST_URL), (error) => error.code === 'mismatched_response');
  });
  await test('유효하지 않은 최종 목적지는 정상 판정을 보류한다', () => {
    const result = normalizeScanResponse(response({ finalUrl: 'javascript:alert(1)' }), TEST_URL);
    assert(result.verdict === 'inconclusive' && result.finalUrl === null);
  });
  await test('외부 미리보기·임의 로컬 경로·실행 가능한 URL을 거부한다', () => {
    for (const invalid of ['https://outside.test/preview.png', '/private/user.png', 'data:image/svg+xml,test', '/assets/demo-clear.svg']) {
      assert(previewUrl(invalid) === null);
    }
    assert(previewUrl('/api/scans/test-123/screenshot') !== null);
    assert(previewUrl('/assets/demo-clear.svg', { demo: true }) !== null);
  });
  await test('미리보기는 외부 주소를 요청하지 않고 내부 이미지의 리다이렉트도 따르지 않는다', async () => {
    let called = 0;
    await withFetch(async (endpoint, options) => {
      called += 1;
      assert(new URL(endpoint).pathname === '/api/scans/test-123/screenshot');
      assert(options.redirect === 'error' && options.credentials === 'same-origin' && options.referrerPolicy === 'no-referrer' && options.cache === 'no-store');
      return new Response(new Uint8Array([137, 80, 78, 71]), { headers: { 'Content-Type': 'image/png' } });
    }, async () => {
      await rejects(() => loadPreviewImage('https://outside.test/screen.png'), (error) => error.code === 'invalid_preview');
      assert(called === 0);
      const blob = await loadPreviewImage('/api/scans/test-123/screenshot');
      assert(blob instanceof Blob && blob.type === 'image/png' && called === 1);
    });
  });
  await test('미리보기의 HTML·실서비스 SVG·미지원 MIME 응답은 표시하지 않는다', async () => {
    for (const type of ['text/html', 'image/svg+xml', 'application/octet-stream']) {
      await withFetch(async () => new Response('<svg></svg>', { headers: { 'Content-Type': type } }), async () => {
        await rejects(() => loadPreviewImage('/api/scans/test-123/screenshot'), (error) => error.code === 'preview_type');
      });
    }
  });
  await test('직접 제작한 고정 데모 자산에 한해서만 SVG를 허용한다', async () => {
    await withFetch(async () => new Response('<svg></svg>', { headers: { 'Content-Type': 'image/svg+xml' } }), async () => {
      const blob = await loadPreviewImage('/assets/demo-clear.svg', { demo: true });
      assert(blob.type === 'image/svg+xml');
      await rejects(() => loadPreviewImage('/api/scans/test-123/screenshot', { demo: true }), (error) => error.code === 'preview_type');
    });
  });
  await test('10MiB를 초과하는 미리보기와 빈 이미지 응답을 거부한다', async () => {
    await withFetch(async () => new Response('image', { headers: { 'Content-Type': 'image/png', 'Content-Length': String(11 * 1024 * 1024) } }), async () => {
      await rejects(() => loadPreviewImage('/api/scans/test-123/screenshot'), (error) => error.code === 'preview_size');
    });
    await withFetch(async () => new Response('', { headers: { 'Content-Type': 'image/png' } }), async () => {
      await rejects(() => loadPreviewImage('/api/scans/test-123/screenshot'), (error) => error.code === 'preview_size');
    });
  });
  await test('취소된 미리보기는 요청하지 않으며 진행 중 요청에 AbortSignal을 전달한다', async () => {
    const cancelled = new AbortController(); cancelled.abort();
    let called = 0;
    await withFetch(async (_endpoint, options) => {
      called += 1;
      return new Promise((_resolve, reject) => {
        options.signal.addEventListener('abort', () => reject(new DOMException('취소', 'AbortError')), { once: true });
      });
    }, async () => {
      await rejects(() => loadPreviewImage('/api/scans/test-123/screenshot', { signal: cancelled.signal }), (error) => error.name === 'AbortError');
      assert(called === 0);
      const controller = new AbortController();
      const loading = loadPreviewImage('/api/scans/test-123/screenshot', { signal: controller.signal });
      controller.abort();
      await rejects(() => loading, (error) => error.name === 'AbortError');
      assert(called === 1);
    });
  });
  await test('미확인 신고 건수는 0으로 바꾸지 않고 신고 이력과 사용자 완료를 구분한다', () => {
    const result = normalizeScanResponse(response({ reportCount: -1, isReported: true }), TEST_URL);
    assert(result.reportCount === null && result.isReported === true && result.reportedByUser === false);
  });
  await test('근거 ID·출처·관찰 시각을 보존하며 임의 데이터 필드는 전달하지 않는다', () => {
    const observedAt = '2026-10-31T00:00:00Z';
    const result = normalizeScanResponse(response({
      signals: [{ summary: '관찰된 모의 신호', source: 'fixture', evidenceIds: ['evidence-1'] }],
      evidence: [{ id: 'evidence-1', kind: 'form', source: 'fixture', summary: '모의 관찰 근거', observedAt, data: { secret: 'private' } }, { id: {}, summary: '무효' }],
    }), TEST_URL);
    assert(result.evidence.length === 1 && result.evidence[0].id === result.signals[0].evidenceIds[0]);
    assert(result.evidence[0].observedAt === observedAt && !('data' in result.evidence[0]));
  });
  await test('제공자 실패·미확인 상태를 미탐지로 바꾸지 않고 시각 누락을 null로 유지한다', () => {
    const result = normalizeScanResponse(response({
      providers: [{ name: '목록 조회', status: 'failed', matched: null, checkedAt: null }, { name: '알 수 없는 제공자', status: 'new-status', matched: 'false' }, { name: {} }],
      checkedAt: null,
    }), TEST_URL);
    assert(result.providers.length === 2 && result.providers.every((provider) => provider.status === 'failed' && provider.matched === null && provider.checkedAt === null));
    assert(result.checkedAt === null);
  });
  await test('실제 검사 요청은 우리 API의 POST 본문으로만 전송하고 작업 상태를 조회한다', async () => {
    const calls = [];
    await withFetch(async (endpoint, options) => {
      calls.push(`${options.method} ${new URL(endpoint).pathname}`);
      assert(options.redirect === 'error' && !endpoint.includes('example.test'));
      if (options.method === 'POST') {
        const body = JSON.parse(options.body);
        assert(body.url === TEST_URL && body.mode === 'sandbox');
        return new Response(JSON.stringify({ scanId: 'test-123', status: 'queued', mode: 'sandbox' }), { status: 202 });
      }
      return new Response(JSON.stringify(response()), { status: 200 });
    }, async () => {
      const result = await analyzeUrl(TEST_URL);
      assert(result.verdict === 'clear' && !result.demo);
      assert(calls.join() === 'POST /api/scans,GET /api/scans/test-123');
    });
  });
  await test('백엔드의 queued·running 상태를 기다렸다가 완료 보고서를 화면용 모델로 변환한다', async () => {
    const reports = [
      backendReport({ status: 'running', verdict: null, sandboxAnalysis: { ...backendReport().sandboxAnalysis, status: 'running' } }),
      backendReport(),
    ];
    const stages = [];
    await withFetch(async (_endpoint, options) => {
      if (options.method === 'POST') return new Response(JSON.stringify({ scanId: 'test-123', status: 'queued', mode: 'sandbox' }), { status: 202 });
      return new Response(JSON.stringify(reports.shift()), { status: 200 });
    }, async () => {
      const result = await analyzeUrl(TEST_URL, { onProgress: ({ stage }) => stages.push(stage) });
      assert(result.status === 'completed' && result.verdict === 'clear' && reports.length === 0);
      assert(stages.includes('preview'), '실제 백엔드 상태가 있을 때만 화면 확인 단계를 표시해야 합니다.');
    });
  });
  await test('백엔드 판정 수준을 화면 판정으로 변환하고 알 수 없는 값은 확인 불가로 둔다', () => {
    const level = (value) => normalizeScanResponse(backendReport({ verdict: { level: value, reasons: [], evidenceIds: [], limitations: [] } }), TEST_URL).verdict;
    assert(level('no_known_threat') === 'clear' && level('malicious') === 'phishing');
    assert(level('suspicious') === 'suspicious' && level('unknown') === 'inconclusive' && level('new-level') === 'inconclusive');
    assert(normalizeScanResponse(backendReport({ verdict: null }), TEST_URL).verdict === 'inconclusive');
  });
  await test('진행 중인 백엔드 보고서는 완료·정상으로 보정하지 않는다', () => {
    const queued = normalizeScanResponse(backendReport({ status: 'queued', verdict: null }), TEST_URL);
    assert(queued.status === 'pending' && queued.verdict === 'inconclusive');
    const running = normalizeScanResponse(backendReport({ status: 'running' }), TEST_URL);
    assert(running.verdict === 'inconclusive');
  });
  await test('격리 방문이 끝나지 않은 sandbox 모드의 정상 판정은 확인 불가로 낮춘다', () => {
    const blocked = backendReport({ sandboxAnalysis: { ...backendReport().sandboxAnalysis, status: 'blocked', finalUrl: null, screenshot: { status: 'not_requested', available: false } } });
    const result = normalizeScanResponse(blocked, TEST_URL);
    assert(result.verdict === 'inconclusive' && result.finalUrl === null && result.previewUrl === null);
    const staticOnly = backendReport({ mode: 'static', sandboxAnalysis: { status: 'not_requested', screenshot: { status: 'not_requested', available: false } } });
    assert(normalizeScanResponse(staticOnly, TEST_URL).verdict === 'clear');
  });
  await test('백엔드 보고서의 최종 주소·미리보기·제공자·근거·한계를 화면 모델로 옮긴다', () => {
    const observedAt = '2026-10-31T00:00:00Z';
    const result = normalizeScanResponse(backendReport({
      staticAnalysis: { ...backendReport().staticAnalysis, signals: [{ id: 's1', kind: 'threat_feed_match', severity: 'high', summary: '정적 신호', source: 'google-safebrowsing', evidenceIds: ['ev-1'] }] },
      sandboxAnalysis: { ...backendReport().sandboxAnalysis, signals: [{ id: 's2', kind: 'redirect', severity: 'info', summary: '격리 신호', source: 'browser', evidenceIds: [] }] },
      evidence: [{ id: 'ev-1', kind: 'threat_feed_match', source: 'google-safebrowsing', observedAt, summary: '근거', data: { secret: 'private' } }],
    }), TEST_URL);
    assert(result.finalUrl === validateUrl(TEST_URL) && result.previewUrl.endsWith('/api/scans/test-123/screenshot'));
    assert(result.providers[0].name === 'google-safebrowsing' && result.providers[0].matched === false);
    assert(result.signals.length === 2 && result.evidence[0].id === result.signals[0].evidenceIds[0] && !('data' in result.evidence[0]));
    assert(result.limitations.includes('정적 한계') && result.limitations.includes('판정 한계'));
    assert(result.reportCount === null && result.reportedByUser === false && result.checkedAt === '2026-10-31T00:00:02Z');
  });
  await test('스크린샷이 준비되지 않았거나 이용할 수 없으면 미리보기 주소를 만들지 않는다', () => {
    for (const screenshot of [{ status: 'pending', available: false }, { status: 'ready', available: false }, { status: 'failed', available: false }, {}]) {
      const report = backendReport({ sandboxAnalysis: { ...backendReport().sandboxAnalysis, screenshot } });
      assert(normalizeScanResponse(report, TEST_URL).previewUrl === null);
    }
  });
  await test('백엔드 보고서도 요청 URL이 다르면 거부한다', async () => {
    await rejects(() => normalizeScanResponse(backendReport({ requestedUrl: 'https://other.test/' }), TEST_URL), (error) => error.code === 'mismatched_response');
  });
  await test('API 오류를 데모 성공으로 대체하지 않는다', async () => {
    await withFetch(async () => new Response('', { status: 503 }), async () => {
      await rejects(() => analyzeUrl(TEST_URL), (error) => error.code === 'http');
    });
  });
  await test('잘못된 JSON을 검사 성공으로 처리하지 않는다', async () => {
    await withFetch(async () => new Response('not-json', { status: 200 }), async () => {
      await rejects(() => analyzeUrl(TEST_URL), (error) => error.code === 'invalid_response');
    });
  });
  await test('취소된 검사에서는 새 요청을 보내지 않는다', async () => {
    const controller = new AbortController(); controller.abort();
    await withFetch(async () => { throw new Error('전송하면 안 됩니다.'); }, async () => {
      await rejects(() => analyzeUrl(TEST_URL, { signal: controller.signal }), (error) => error.name === 'AbortError');
    });
  });
  await test('대기 중인 데모와 제한 시간은 AbortSignal로 정리된다', async () => {
    const controller = new AbortController();
    const waiting = analyzeUrl(TEST_URL, { mode: 'demo', signal: controller.signal });
    controller.abort();
    await rejects(() => waiting, (error) => error.name === 'AbortError');
    const scope = createRequestScope(undefined, 5);
    try {
      await rejects(() => waitFor(100, scope.signal), (error) => error.name === 'AbortError');
      assert(scope.timedOut);
    } finally { scope.dispose(); }
  });
  await test('피싱 결과만 명시적인 신고 요청으로 전송한다', async () => {
    await rejects(() => reportSite(normalizeScanResponse(response(), TEST_URL)), (error) => error.code === 'invalid_result');
    await withFetch(async (endpoint, options) => {
      assert(new URL(endpoint).pathname === '/api/scans/test-123/reports');
      assert(options.method === 'POST' && JSON.parse(options.body).scanId === 'test-123');
      return new Response(JSON.stringify({ reportCount: 61, reportedByUser: true }), { status: 200 });
    }, async () => {
      const result = await reportSite(normalizeScanResponse(response({ verdict: 'phishing' }), TEST_URL));
      assert(result.reportCount === 61 && result.reportedByUser);
    });
  });
  await test('서버의 접수 확인 없는 신고 응답을 성공으로 표시하지 않는다', async () => {
    await withFetch(async () => new Response(JSON.stringify({ reportCount: 62 }), { status: 200 }), async () => {
      await rejects(() => reportSite(normalizeScanResponse(response({ verdict: 'phishing' }), TEST_URL)), (error) => error.code === 'invalid_response');
    });
  });
  await test('서버가 반환한 신고 대상 ID가 다르면 성공 응답도 거부한다', async () => {
    await withFetch(async () => new Response(JSON.stringify({ scanId: 'another-scan', reportCount: 62, reportedByUser: true }), { status: 200 }), async () => {
      await rejects(() => reportSite(normalizeScanResponse(response({ verdict: 'phishing' }), TEST_URL)), (error) => error.code === 'mismatched_response');
    });
  });
  return results;
}

if (globalThis.document?.getElementById('results')) {
  const results = await runServiceTests();
  const list = document.getElementById('results');
  for (const result of results) {
    const item = document.createElement('li');
    item.dataset.pass = String(result.passed);
    item.textContent = `${result.passed ? '통과' : '실패'} — ${result.name}${result.message ? `: ${result.message}` : ''}`;
    list.append(item);
  }
  document.getElementById('summary').textContent = `${results.length}개 중 ${results.filter((item) => item.passed).length}개 통과`;
}
