import { frontendConfig } from '../config.js';
import { demoResponse } from '../data/demo-fixtures.js';
import { urlVerdictDemoResponse } from '../data/url-verdict-demo.js';
import { validateUrl } from '../utils/url.js';
import { createRequestScope, requestJson, scopedError, ServiceError, waitFor } from './http.js';
import { normalizeScanResponse, safeScanId } from './response-adapter.js';

const DEMO_SCENARIOS = new Set(['clear', 'phishing', 'suspicious', 'inconclusive', 'error', 'no-preview', 'report-error']);

export async function analyzeUrl(rawUrl, { signal, mode = 'live', source = 'qr', scenario = 'clear', onProgress } = {}) {
  const url = validateUrl(rawUrl);
  const scope = createRequestScope(signal);
  try {
    scope.signal.throwIfAborted();
    const urlDemo = mode === 'live' ? urlVerdictDemoResponse(url) : null;
    onProgress?.({ stage: 'analysis', message: mode === 'demo' || urlDemo ? '데모 검사 응답을 준비하고 있어요' : frontendConfig.scanMode === 'static' ? '주소를 검사하고 있어요' : '사이트를 검사하고 있어요' });
    if (mode === 'demo') {
      if (!DEMO_SCENARIOS.has(scenario)) throw new ServiceError('지원하지 않는 데모 시나리오입니다.', 'demo');
      await waitFor(frontendConfig.demoDelayMs, scope.signal);
      if (scenario === 'error') throw new ServiceError('검사 서버의 응답이 지연되는 상황을 재현한 데모입니다.', 'demo_error');
      return { ...normalizeScanResponse(demoResponse(url, scenario), url, { demo: true }), demoScenario: scenario };
    }
    if (mode !== 'live') throw new ServiceError('검사 모드 설정을 확인해 주세요.', 'configuration');
    if (!['qr', 'manual'].includes(source)) throw new ServiceError('검사 요청의 입력 출처를 확인해 주세요.', 'configuration');
    if (urlDemo) {
      await waitFor(frontendConfig.demoDelayMs, scope.signal);
      return { ...normalizeScanResponse(urlDemo, url, { demo: true }), urlVerdictDemo: true };
    }
    let raw;
    if (frontendConfig.scanTransport === 'direct') {
      raw = await requestJson(frontendConfig.analyzePath, { body: { url, source }, method: 'POST', signal: scope.signal });
    } else if (frontendConfig.scanTransport === 'job') {
      raw = await requestJson(frontendConfig.createScanPath, {
        body: { url, source, mode: frontendConfig.scanMode }, method: 'POST', signal: scope.signal,
      });
      const scanId = safeScanId(raw.scanId);
      if (!scanId) throw new ServiceError('검사 작업 식별자를 확인할 수 없습니다.', 'invalid_response');
      while (['queued', 'pending', 'running'].includes(raw.status)) {
        // Only backend-reported execution stages change the explanatory message.
        if (raw.stage === 'preview' || raw.sandboxAnalysis?.status === 'running') {
          onProgress?.({ stage: 'preview', message: '격리된 환경에서 사이트 화면을 확인하고 있어요' });
        }
        await waitFor(frontendConfig.pollIntervalMs, scope.signal);
        raw = await requestJson(frontendConfig.scanPath(scanId), { signal: scope.signal });
        if (raw.scanId !== scanId) throw new ServiceError('검사 작업 응답이 일치하지 않습니다.', 'mismatched_response');
      }
    } else {
      throw new ServiceError('검사 방식 설정을 확인해 주세요.', 'configuration');
    }
    const result = normalizeScanResponse(raw, url);
    if (['failed', 'cancelled'].includes(result.status)) {
      throw new ServiceError(result.reasons[0] || '검사를 완료하지 못했습니다. 안전 여부는 확인되지 않았습니다.', 'scan_failed');
    }
    if (['pending', 'running'].includes(result.status)) {
      throw new ServiceError('검사가 아직 완료되지 않았습니다. 서버의 응답 계약을 확인해 주세요.', 'scan_incomplete');
    }
    return result;
  } catch (error) {
    throw scopedError(error, scope);
  } finally {
    scope.dispose();
  }
}
