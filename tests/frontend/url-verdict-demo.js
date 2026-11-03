import '../../src/main.js';
import { analyzeUrl } from '../../src/services/scan-api.js';
import { urlVerdictDemoResponse } from '../../src/data/url-verdict-demo.js';
import { validateUrl } from '../../src/utils/url.js';
import { frontendConfig } from '../../src/config.js';

const targets = [
  ['https://realistic-phishing-website.vercel.app', '로고와 주소 불일치'],
  ['HTTPS://FAKE-PHISHING-WEBSITE.VERCEL.APP:443/', '동적 판단에서 감지'],
];
const others = [
  'https://example.com/', 'http://example.test/path?step=1#section',
  'https://realistic-phishing-website.vercel.app/survey',
  'https://fake-phishing-website.vercel.app/?demo=1',
  'https://fake-phishing-website.vercel.app.evil.test/',
  'https://fake-phishing-website.vercel.app:8443/',
  'https://bücher.example.test/책', 'http://127.0.0.1:8080/',
];
const fixture = document.getElementById('fixture');
const results = [];
const originalFetch = window.fetch;
const originalOpen = window.open;
const originalState = history.state;
const originalUrl = location.href;
let requests = 0;
let opened = 0;

function assert(value, message = '기대 동작과 다릅니다.') { if (!value) throw new Error(message); }
async function test(name, run) {
  try { await run(); results.push({ name, passed:true }); }
  catch (error) { results.push({ name, passed:false, message:error.message }); }
  finally { fixture.replaceChildren(); history.replaceState(originalState, '', originalUrl); }
}
async function waitUntil(predicate) {
  const deadline = performance.now() + frontendConfig.demoDelayMs + 1500;
  while (!predicate()) {
    if (performance.now() > deadline) throw new Error('예상한 화면이 표시되지 않았습니다.');
    await new Promise((resolve) => setTimeout(resolve, 15));
  }
}
function enter(app, url) {
  const scan = app.shadowRoot.querySelector('qr-scan-page');
  scan.shadowRoot.querySelector('input').value = url;
  const event = new Event('submit', { bubbles:true, cancelable:true });
  scan.shadowRoot.querySelector('form').dispatchEvent(event);
  assert(event.defaultPrevented, '기본 폼 제출을 차단하지 않았습니다.');
}
function assertDemo(result, verdict) {
  assert(result.demo && result.urlVerdictDemo && result.status === 'completed' && result.verdict === verdict);
  assert(result.finalUrl === null && result.previewUrl === null && result.previewImage === null, '실제 방문·미리보기를 만들었습니다.');
  assert(result.reportAvailable === false && result.reportCount === null && result.isReported === null, '실제 신고 정보를 만들었습니다.');
}

window.fetch = async () => { requests += 1; throw new Error('활성 데모가 네트워크를 요청했습니다.'); };
window.open = () => { opened += 1; return null; };
try {
  await test('URL 데모 스위치가 실제로 활성화되어 있다', () => {
    for (const [url] of targets) assert(urlVerdictDemoResponse(validateUrl(url))?.verdict === 'phishing', '활성화한 소스 사본에서 실행해야 합니다.');
    assert(urlVerdictDemoResponse(others[0])?.verdict === 'clear', '모든 다른 URL의 모의 비피싱 분기가 활성화되지 않았습니다.');
  });
  if (results[0].passed) {
    await test('두 지정 URL만 서로 다른 피싱 사유를 반환한다', async () => {
      await Promise.all(targets.map(async ([url, reason]) => {
        const result = await analyzeUrl(url);
        assertDemo(result, 'phishing');
        assert(result.reasons.some((item) => item.includes(reason)), '지정 URL의 탐지 사유가 다릅니다.');
      }));
    });
    await test('다양한 다른 유효 URL은 모두 비피싱 데모이며 API를 호출하지 않는다', async () => {
      await Promise.all(others.map(async (url) => {
        const result = await analyzeUrl(url, { source:'manual' });
        assertDemo(result, 'clear');
        assert(result.reasons.includes('피싱 사이트가 아니에요. (모의 결과)'));
      }));
      assert(requests === 0 && opened === 0);
    });
    await test('활성화 상태에서도 잘못된 URL은 거부한다', async () => {
      for (const url of ['', 'not a URL', '/relative', 'javascript:alert(1)', 'ftp://example.test/', 'https://user:password@example.test/']) {
        let rejected = false;
        try { await analyzeUrl(url); } catch { rejected = true; }
        assert(rejected, '잘못된 URL을 모의 정상 결과로 바꿨습니다.');
      }
      assert(requests === 0);
    });
    await test('모의 결과를 기다리는 동안 서비스 요청을 취소할 수 있다', async () => {
      const controller = new AbortController();
      const waiting = analyzeUrl(others[0], { signal:controller.signal });
      controller.abort();
      let aborted = false;
      try { await waiting; } catch (error) { aborted = error.name === 'AbortError'; }
      assert(aborted && requests === 0);
    });
    await test('비피싱 UI는 모의 문구와 비활성 접속 버튼을 표시하고 재스캔으로 초기화된다', async () => {
      const app = document.createElement('qr-app'); fixture.append(app);
      enter(app, others[0]);
      const banner = app.shadowRoot.querySelector('.demo-banner');
      assert(!banner.hidden && app.shadowRoot.querySelector('qr-loading-page'));
      await waitUntil(() => app.shadowRoot.querySelector('qr-result-page'));
      const page = app.shadowRoot.querySelector('qr-result-page');
      const title = page.shadowRoot.querySelector('qr-verdict-summary').shadowRoot.querySelector('h2');
      assert(title.textContent === '피싱 사이트가 아니에요 (모의 결과)');
      const button = page.shadowRoot.querySelector('.main-action');
      assert(button.disabled && !banner.hidden);
      button.click();
      page.dispatchEvent(new CustomEvent('open-site-request', { bubbles:true, composed:true }));
      assert(opened === 0 && requests === 0, '모의 비피싱 UI에서 실제 사이트를 열었습니다.');
      page.shadowRoot.querySelector('.rescan').click();
      assert(banner.hidden && app.shadowRoot.querySelector('qr-scan-page'));
    });
    await test('검사 취소 후 늦은 결과가 촬영 화면을 덮어쓰지 않는다', async () => {
      const app = document.createElement('qr-app'); fixture.append(app);
      enter(app, targets[0][0]);
      app.shadowRoot.querySelector('qr-loading-page').shadowRoot.querySelector('.cancel').click();
      await new Promise((resolve) => setTimeout(resolve, frontendConfig.demoDelayMs + 50));
      assert(app.shadowRoot.querySelector('qr-scan-page') && !app.shadowRoot.querySelector('qr-result-page'));
      assert(app.shadowRoot.querySelector('.demo-banner').hidden && requests === 0 && opened === 0);
    });
  }
} finally {
  fixture.replaceChildren(); window.fetch = originalFetch; window.open = originalOpen;
  history.replaceState(originalState, '', originalUrl);
}
for (const result of results) {
  const item = document.createElement('li');
  item.dataset.pass = String(result.passed);
  item.textContent = `${result.passed ? '통과' : '실패'} · ${result.name}${result.message ? `: ${result.message}` : ''}`;
  document.getElementById('results').append(item);
}
const summary = document.getElementById('summary');
summary.textContent = `${results.length}개 중 ${results.filter((result) => result.passed).length}개 통과`;
summary.dataset.pass = String(results.every((result) => result.passed));
document.documentElement.dataset.testsComplete = 'true';
