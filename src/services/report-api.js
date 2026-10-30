import { frontendConfig } from '../config.js';
import { demoReportResponse } from '../data/demo-fixtures.js';
import { createRequestScope, requestJson, scopedError, ServiceError, waitFor } from './http.js';
import { safeCount, safeScanId } from './response-adapter.js';

export async function reportSite(result, { signal } = {}) {
  if (!result || result.verdict !== 'phishing') {
    throw new ServiceError('신고할 수 있는 피싱 검사 결과가 없습니다.', 'invalid_result');
  }
  const scanId = safeScanId(result.scanId);
  if (!scanId) throw new ServiceError('신고 API에 필요한 검사 식별자가 없습니다.', 'invalid_result');
  const scope = createRequestScope(signal);
  try {
    scope.signal.throwIfAborted();
    let response;
    if (result.demo === true) {
      await waitFor(650, scope.signal);
      if (result.demoScenario === 'report-error') {
        throw new ServiceError('신고 전송 실패를 재현한 데모입니다. 다시 시도할 수 있습니다.', 'demo_report_error');
      }
      response = demoReportResponse;
    } else {
      response = await requestJson(frontendConfig.reportPath(scanId), {
        method: 'POST', body: { scanId }, signal: scope.signal,
      });
    }
    if (Object.hasOwn(response, 'scanId') && response.scanId !== scanId) {
      throw new ServiceError('현재 검사와 신고 응답이 일치하지 않습니다. 다시 시도해 주세요.', 'mismatched_response');
    }
    if (response.reportedByUser !== true) {
      throw new ServiceError('신고 접수 완료를 확인하지 못했습니다. 다시 시도해 주세요.', 'invalid_response');
    }
    return { reportCount: safeCount(response.reportCount), reportedByUser: true };
  } catch (error) {
    throw scopedError(error, scope);
  } finally {
    scope.dispose();
  }
}
