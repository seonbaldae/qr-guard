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

export function normalizeScanResponse(raw, expectedUrl, { demo = false } = {}) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    throw new ServiceError('검사 응답 형식이 올바르지 않습니다.', 'invalid_response');
  }
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
  return {
    scanId: safeScanId(raw.scanId),
    requestedUrl,
    finalUrl,
    status,
    verdict,
    previewUrl: previewUrl(raw.screenshotUrl, { demo }),
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
