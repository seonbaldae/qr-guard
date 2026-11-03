import { validateUrl } from '../utils/url.js';
import { apiOrigin, ServiceError } from './http.js';

const STAGES = new Set(['pending', 'running', 'completed', 'failed', 'blocked', 'skipped', 'cancelled']);
const VERDICTS = new Map([
  ['clear', 'clear'], ['normal', 'clear'], ['phishing', 'phishing'],
  ['suspicious', 'suspicious'], ['inconclusive', 'inconclusive'],
]);

export function safeCount(value) {
  return Number.isSafeInteger(value) && value >= 0 ? value : null;
}

export function safeScanId(value) {
  return typeof value === 'string' && /^[a-zA-Z0-9_-]{1,128}$/.test(value) ? value : null;
}

function plainText(value, maxLength = 1000) {
  return typeof value === 'string' ? value.slice(0, maxLength) : '';
}

function timestamp(value) {
  return typeof value === 'string' && Number.isFinite(Date.parse(value)) ? value : null;
}

export function previewUrl(raw, { demo = false } = {}) {
  if (typeof raw !== 'string' || !raw) return null;
  try {
    const parsed = new URL(raw, apiOrigin());
    if (parsed.username || parsed.password || parsed.origin !== apiOrigin() || parsed.hash) return null;
    if (demo && ['/assets/demo-clear.svg', '/assets/demo-phishing.svg'].includes(parsed.pathname)) {
      return parsed.href;
    }
    const allowed = /^\/api\/screenshots\/[a-zA-Z0-9_./-]+$/.test(parsed.pathname)
      || /^\/api\/scans\/[a-zA-Z0-9_-]+\/screenshot(?:\.(?:png|jpe?g|webp))?$/.test(parsed.pathname);
    return allowed ? parsed.href : null;
  } catch {
    return null;
  }
}

const BACKEND_VERDICTS = new Map([
  ['malicious', 'phishing'], ['suspicious', 'suspicious'],
  ['no_known_threat', 'clear'], ['unknown', 'inconclusive'],
]);

const isObject = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);
const listOf = (value) => (Array.isArray(value) ? value : []);

export const MAX_INLINE_PREVIEW_BYTES = 1536 * 1024;
const PNG_SIGNATURE = [137, 80, 78, 71, 13, 10, 26, 10];

// Inline image bytes come from our analysis response, never from a target URL.
// Actual PNG decoding is performed by the server and again by the browser <img>.
export function decodeInlinePreview(raw, expectedScanId) {
  if (!isObject(raw) || !safeScanId(expectedScanId) || raw.scanId !== expectedScanId
      || raw.mimeType !== 'image/png' || typeof raw.base64 !== 'string'
      || !raw.base64.length || raw.base64.length > Math.ceil(MAX_INLINE_PREVIEW_BYTES / 3) * 4
      || raw.base64.length % 4 !== 0 || !/^[A-Za-z0-9+/]*={0,2}$/.test(raw.base64)) return null;
  try {
    const binary = atob(raw.base64);
    if (btoa(binary) !== raw.base64 || binary.length < PNG_SIGNATURE.length || binary.length > MAX_INLINE_PREVIEW_BYTES
        || !PNG_SIGNATURE.every((value, index) => binary.charCodeAt(index) === value)) return null;
    return Uint8Array.from(binary, (character) => character.charCodeAt(0));
  } catch {
    return null;
  }
}

export function normalizeInlinePreview(raw, expectedScanId) {
  if (!decodeInlinePreview(raw, expectedScanId)) return null;
  return Object.freeze({ scanId: expectedScanId, mimeType: 'image/png', base64: raw.base64 });
}

const WORKER_ERRORS = new Map([
  ['worker_not_configured', '격리 브라우저가 아직 연결되지 않았습니다.'],
  ['worker_egress_unverified', '격리 환경의 네트워크 검증이 완료되지 않아 방문하지 않았습니다.'],
  ['target_not_allowed', '이 주소는 격리 미리보기 허용 대상이 아닙니다.'],
  ['worker_blocked', '격리 브라우저의 접근 정책으로 방문이 차단되었습니다.'],
  ['worker_policy_blocked', '격리 환경의 접근 정책으로 일부 페이지를 확인하지 못했습니다.'],
  ['unsafe_target', '내부망 등 허용되지 않은 주소여서 방문하지 않았습니다.'],
  ['worker_destination_not_allowed', '허용되지 않은 주소로 이동하여 방문을 중단했습니다.'],
  ['worker_timeout', '제한 시간 안에 사이트 화면을 확인하지 못했습니다.'],
  ['worker_unreachable', '격리 브라우저에 연결하지 못했습니다.'],
  ['worker_navigation_incomplete', '사이트의 최종 도착 주소를 확인하지 못했습니다.'],
  ['worker_navigation_failed', '사이트가 오류를 반환하여 화면을 확인하지 못했습니다.'],
  ['invalid_screenshot', '촬영된 미리보기 이미지의 형식을 확인하지 못했습니다.'],
  ['worker_invalid_response', '격리 브라우저의 응답을 확인하지 못했습니다.'],
  ['worker_http_error', '격리 브라우저가 검사를 완료하지 못했습니다.'],
  ['worker_response_too_large', '격리 브라우저의 응답 크기가 허용 범위를 초과했습니다.'],
  ['worker_scan_mismatch', '격리 브라우저의 응답이 현재 검사와 일치하지 않습니다.'],
  ['worker_job_failed', '격리 브라우저에서 검사가 실패하거나 중단되었습니다.'],
  ['worker_screenshot_unavailable', '격리 브라우저가 미리보기 이미지를 제공하지 못했습니다.'],
  ['invalid_scan_id', '격리 검사 식별자를 확인하지 못했습니다.'],
  ['analysis_error', '격리 브라우저 결과를 처리하지 못했습니다.'],
]);

function previewMessage(sandbox, screenshot) {
  if (sandbox.skipReason === 'known_malicious') return '알려진 위협이 발견되어 사이트를 방문하지 않았어요';
  if (sandbox.skipReason === 'static_only') return '이번 검사는 사이트 화면을 촬영하지 않았어요';
  const error = WORKER_ERRORS.get(screenshot.errorCode) || WORKER_ERRORS.get(sandbox.errorCode);
  if (error) return error;
  if (screenshot.status === 'expired') return '미리보기 보관 기간이 지났어요. 다시 검사해 주세요';
  if (screenshot.status === 'failed' || sandbox.status === 'failed') return '사이트 화면을 촬영하지 못했어요';
  if (sandbox.status === 'blocked') return '접근 정책으로 사이트를 방문하지 않았어요';
  return '미리보기가 없어요';
}

// The Python backend (API contract v0.2) nests its report under staticAnalysis, sandboxAnalysis and
// verdict.level. Flatten it into the shape validated below. Flat responses pass through unchanged.
function flattenBackendReport(raw) {
  if (!isObject(raw.verdict) && !isObject(raw.staticAnalysis) && !isObject(raw.sandboxAnalysis)) return raw;
  const staticPart = isObject(raw.staticAnalysis) ? raw.staticAnalysis : {};
  const sandbox = isObject(raw.sandboxAnalysis) ? raw.sandboxAnalysis : {};
  const screenshot = isObject(sandbox.screenshot) ? sandbox.screenshot : {};
  const verdictPart = isObject(raw.verdict) ? raw.verdict : null;
  const scanId = safeScanId(raw.scanId);
  let verdict = verdictPart ? BACKEND_VERDICTS.get(verdictPart.level) : undefined;
  // In sandbox mode "no known threat" is only trusted once the isolated visit actually completed.
  if (verdict === 'clear' && raw.mode === 'sandbox' && sandbox.status !== 'completed') verdict = 'inconclusive';
  return {
    scanId: raw.scanId,
    requestedUrl: raw.requestedUrl,
    status: raw.status === 'queued' ? 'pending' : raw.status,
    verdict,
    finalUrl: sandbox.finalUrl,
    screenshotUrl: scanId && screenshot.status === 'ready' && screenshot.available === true
      ? `/api/scans/${scanId}/screenshot` : null,
    ...(Object.prototype.hasOwnProperty.call(raw, 'previewImage') ? {
      previewImage: raw.previewImage,
      inlinePreviewAvailable: screenshot.status === 'ready' && screenshot.available === true,
    } : {}),
    signals: [...listOf(staticPart.signals), ...listOf(sandbox.signals)],
    reasons: verdictPart?.reasons,
    verdictEvidenceIds: verdictPart?.evidenceIds,
    evidence: raw.evidence,
    reportCount: raw.reportCount,
    isReported: raw.isReported,
    reportedByUser: raw.reportedByUser,
    reportAvailable: raw.reportAvailable,
    analysisScope: raw.analysisScope === 'static' || raw.mode === 'static' ? 'static' : 'sandbox',
    previewMessage: raw.analysisScope === 'static' && sandbox.skipReason !== 'known_malicious'
      ? '사이트 화면 미리보기는 점검 중이에요' : previewMessage(sandbox, screenshot),
    previewStatus: screenshot.status,
    providers: staticPart.providers,
    limitations: [...new Set([
      ...listOf(staticPart.limitations), ...listOf(sandbox.limitations), ...listOf(verdictPart?.limitations),
      ...(WORKER_ERRORS.has(sandbox.errorCode) ? [WORKER_ERRORS.get(sandbox.errorCode)] : []),
    ])],
    checkedAt: raw.updatedAt,
  };
}

export function normalizeScanResponse(raw, expectedUrl, { demo = false } = {}) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    throw new ServiceError('검사 응답 형식이 올바르지 않습니다.', 'invalid_response');
  }
  raw = flattenBackendReport(raw);
  const analysisScope = raw.analysisScope === 'static' ? 'static' : raw.analysisScope === 'sandbox' ? 'sandbox' : null;
  const requestedUrl = validateUrl(expectedUrl);
  try {
    if (validateUrl(raw.requestedUrl) !== requestedUrl) throw new Error();
  } catch {
    throw new ServiceError('현재 검사 요청과 응답이 일치하지 않습니다. 다시 검사해 주세요.', 'mismatched_response');
  }
  const status = STAGES.has(raw.status) ? raw.status : 'failed';
  let verdict = VERDICTS.get(raw.verdict) || 'inconclusive';
  const limitations = Array.isArray(raw.limitations)
    ? raw.limitations.filter((item) => typeof item === 'string' && item.trim()).slice(0, 30).map((item) => plainText(item))
    : [];
  // A completed static analysis alone is never a final clear verdict.
  if (status !== 'completed' && verdict !== 'phishing') verdict = 'inconclusive';
  let finalUrl = null;
  if (raw.finalUrl != null && raw.finalUrl !== '') {
    try { finalUrl = validateUrl(raw.finalUrl); }
    catch {
      if (verdict === 'clear') verdict = 'inconclusive';
      limitations.push('최종 목적지 주소를 확인할 수 없습니다.');
    }
  }
  if (status !== 'completed') finalUrl = null;
  // A URL-only analysis cannot establish a visited destination or screenshot.
  if (analysisScope === 'static') finalUrl = null;
  if (!limitations.length) limitations.push('이번 검사 결과만으로 사이트의 완전한 안전이나 공식 운영 여부를 보증하지 않습니다.');
  const signals = Array.isArray(raw.signals) ? raw.signals.slice(0, 30).flatMap((item) => {
    if (!item || typeof item !== 'object' || typeof item.summary !== 'string') return [];
    return [{
      summary: plainText(item.summary),
      source: plainText(item.source, 100),
      evidenceIds: Array.isArray(item.evidenceIds) ? item.evidenceIds.filter((id) => safeScanId(id)).slice(0, 30) : [],
    }];
  }) : [];
  const evidence = Array.isArray(raw.evidence) ? raw.evidence.slice(0, 50).flatMap((item) => {
    if (!item || typeof item !== 'object' || !safeScanId(item.id) || typeof item.summary !== 'string') return [];
    return [{
      id: item.id,
      kind: plainText(item.kind, 100),
      source: plainText(item.source, 100),
      summary: plainText(item.summary),
      observedAt: timestamp(item.observedAt),
    }];
  }) : [];
  const providers = Array.isArray(raw.providers) ? raw.providers.slice(0, 30).flatMap((item) => {
    if (!item || typeof item !== 'object' || typeof item.name !== 'string' || !item.name.trim()) return [];
    return [{
      name: plainText(item.name, 100),
      status: ['checked', 'failed', 'stale'].includes(item.status) ? item.status : 'failed',
      matched: typeof item.matched === 'boolean' ? item.matched : null,
      checkedAt: timestamp(item.checkedAt),
    }];
  }) : [];
  const scanId = safeScanId(raw.scanId);
  const inlineProvided = Object.prototype.hasOwnProperty.call(raw, 'previewImage');
  const inlineImage = analysisScope === 'sandbox' && raw.previewStatus === 'ready' && raw.inlinePreviewAvailable !== false
    ? normalizeInlinePreview(raw.previewImage, scanId) : null;
  const invalidInline = analysisScope !== 'static' && inlineProvided && !inlineImage
    && (raw.previewImage != null || raw.previewStatus === 'ready');
  if (invalidInline) limitations.push('미리보기 이미지의 형식을 확인하지 못해 표시하지 않았습니다.');
  return {
    scanId,
    requestedUrl,
    finalUrl,
    status,
    verdict,
    analysisScope,
    reportAvailable: raw.reportAvailable === undefined ? true : raw.reportAvailable === true,
    reasons: listOf(raw.reasons).filter((item) => typeof item === 'string' && item.trim()).slice(0, 20).map((item) => plainText(item)),
    verdictEvidenceIds: listOf(raw.verdictEvidenceIds).filter((id) => safeScanId(id)).slice(0, 50),
    previewUrl: analysisScope === 'static' || inlineProvided ? null : previewUrl(raw.screenshotUrl, { demo }),
    previewImage: inlineImage,
    previewMessage: invalidInline ? '미리보기 이미지의 형식을 확인하지 못했어요' : plainText(raw.previewMessage) || '미리보기가 없어요',
    previewStatus: invalidInline ? 'failed' : ['not_requested', 'pending', 'ready', 'failed', 'skipped', 'expired', 'cancelled'].includes(raw.previewStatus) ? raw.previewStatus : null,
    reportCount: safeCount(raw.reportCount),
    isReported: typeof raw.isReported === 'boolean' ? raw.isReported : null,
    reportedByUser: raw.reportedByUser === true,
    signals,
    evidence,
    providers,
    limitations,
    checkedAt: timestamp(raw.checkedAt),
    demo,
  };
}
