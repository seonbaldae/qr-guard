// Local demonstration responses. They never contact or inspect these destinations.
export const demoUrls = Object.freeze({
  clear: 'https://example.com/',
  phishing: 'https://account-check.example.test/survey',
});

export function demoResponse(requestedUrl, scenario) {
  const phishing = ['phishing', 'report-error'].includes(scenario);
  const verdict = phishing ? 'phishing' : ['suspicious', 'inconclusive'].includes(scenario) ? scenario : 'clear';
  const checkedAt = new Date().toISOString();
  return {
    scanId: `demo-${scenario}`,
    requestedUrl,
    finalUrl: scenario === 'inconclusive' ? null : requestedUrl,
    status: 'completed',
    verdict,
    screenshotUrl: ['no-preview', 'inconclusive'].includes(scenario)
      ? null : phishing || verdict === 'suspicious' ? '/assets/demo-phishing.svg' : '/assets/demo-clear.svg',
    reportCount: phishing ? 128 : scenario === 'inconclusive' ? null : 0,
    isReported: phishing,
    reportedByUser: false,
    signals: phishing ? [
      { summary: '모의 피싱 목록에 일치하는 주소입니다.', source: '데모 fixture', evidenceIds: ['demo-known-url'] },
      { summary: '로그인을 요구하는 화면의 모의 예시입니다.', source: '데모 fixture', evidenceIds: ['demo-preview'] },
    ] : verdict === 'suspicious' ? [
      { summary: '공식 주소와 유사한 다른 도메인이라는 모의 분석 결과입니다.', source: '데모 fixture', evidenceIds: ['demo-lookalike'] },
    ] : [],
    evidence: phishing ? [
      { id: 'demo-known-url', kind: 'known_url', source: '데모 fixture', summary: '해커톤 시연용 모의 피싱 주소 목록에 포함된 것으로 설정했습니다.', observedAt: checkedAt },
      { id: 'demo-preview', kind: 'preview', source: '데모 fixture', summary: '로그인 유도 화면을 표현한 고정 미리보기 이미지입니다.', observedAt: checkedAt },
    ] : verdict === 'suspicious' ? [
      { id: 'demo-lookalike', kind: 'lookalike', source: '데모 fixture', summary: '유사 도메인 사칭 정황을 설명하기 위해 준비한 예시입니다.', observedAt: checkedAt },
    ] : [],
    providers: [{ name: '로컬 데모 fixture', status: 'checked', matched: phishing, checkedAt }],
    checkedAt,
    limitations: [
      '데모 응답 · 실제 검사 아님. 화면과 판정은 미리 준비한 예시입니다.',
      '실제 사이트를 방문하거나 위협 데이터베이스를 조회하지 않았습니다.',
      ...(scenario === 'inconclusive' ? ['격리 방문 시간 초과를 가정한 예시이며, 안전 여부를 확인하지 못했습니다.'] : []),
    ],
  };
}

export const demoReportResponse = Object.freeze({ reportCount: 129, reportedByUser: true });
