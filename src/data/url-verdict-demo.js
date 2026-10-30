// URL별 해커톤 시연 결과. 기본은 비활성화이며 URL·저장소·환경 변수로 켤 수 없습니다.
let enabled = false;
// enabled = true; // 이 한 줄의 주석만 해제하면 아래 두 URL의 고정 결과를 사용합니다.

const cases = new Map([
  ['https://realistic-phishing-website.vercel.app/', {
    id: 'demo-logo-domain-mismatch',
    kind: 'brand_domain_mismatch',
    reason: '로고와 주소 불일치로 피싱 사이트로 판정됐어요. (모의 결과)',
    summary: '네이버를 연상시키는 로고와 realistic-phishing-website.vercel.app 주소가 일치하지 않는 상황을 재현합니다.',
  }],
  ['https://fake-phishing-website.vercel.app/', {
    id: 'demo-dynamic-detection',
    kind: 'dynamic_detection',
    reason: '동적 판단에서 감지되어 피싱 사이트로 판정됐어요. (모의 결과)',
    summary: '페이지 동작을 검사하는 동적 판단에서 피싱이 감지된 상황을 재현합니다.',
  }],
]);

// 입력은 validateUrl()로 정규화한 절대 주소입니다. 경로·쿼리·해시가 다르면 적용하지 않습니다.
export function urlVerdictDemoResponse(requestedUrl) {
  if (!enabled) return null;
  const scenario = cases.get(requestedUrl);
  if (!scenario) return null;
  const source = '해커톤 시연용 고정 결과';
  return {
    scanId: scenario.id,
    requestedUrl,
    finalUrl: null,
    status: 'completed',
    verdict: 'phishing',
    reasons: [scenario.reason],
    verdictEvidenceIds: [scenario.id],
    signals: [{ summary: scenario.summary, source, evidenceIds: [scenario.id] }],
    evidence: [{ id: scenario.id, kind: scenario.kind, source, summary: scenario.summary, observedAt: null }],
    screenshotUrl: null,
    previewStatus: 'not_requested',
    previewMessage: '고정된 데모 결과이므로 실제 사이트 방문이나 화면 촬영을 하지 않았어요.',
    reportAvailable: false,
    reportCount: null,
    isReported: null,
    reportedByUser: false,
    providers: [],
    checkedAt: null,
    limitations: [
      '데모 응답 · 실제 검사 아님. 지정한 URL에 미리 준비한 피싱 판정과 사유를 표시합니다.',
      '실제 로고 비교·동적 분석·위협 목록 조회를 수행하지 않았습니다.',
      '실제 목적지·스크린샷·신고 이력은 확인하지 않았으며 신고를 접수하지 않습니다.',
    ],
  };
}
