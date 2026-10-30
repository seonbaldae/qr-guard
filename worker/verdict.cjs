function decideVerdict({
  staticAnalysis,
  threatAnalysis,
  browserAnalysis,
  brandAnalysis,
}) {
  const reasons = [];

  const matchedProvider = threatAnalysis?.providers?.find(
    provider => provider.status === "checked" && provider.matched === true
  );
  if (matchedProvider) {
    return {
      verdict: "block",
      reasons: [`${matchedProvider.name} 유해 URL 목록과 일치합니다.`],
    };
  }

  const blockedDestination = browserAnalysis?.signals?.find(
    signal => signal.kind === "blocked_destination"
  );
  if (blockedDestination) {
    return {
      verdict: "block",
      reasons: [blockedDestination.summary],
    };
  }

  if (
    brandAnalysis?.status === "completed" &&
    brandAnalysis.signal === "brand_domain_inconsistency"
  ) {
    return {
      verdict: "block",
      reasons: [
        `화면에서 ${brandAnalysis.candidateBrand || "알려진 브랜드"} 로고를 탐지했지만 공식 도메인과 일치하지 않습니다.`,
      ],
    };
  }

  const required = [
    ["정적 분석", staticAnalysis?.status],
    ["유해 URL 조회", threatAnalysis?.status],
    ["브라우저 분석", browserAnalysis?.status],
    ["브랜드 분석", brandAnalysis?.status],
  ];
  for (const [name, status] of required) {
    if (status !== "completed") {
      reasons.push(`${name} 단계를 완료하지 못했습니다.`);
    }
  }

  const checkedProviders = threatAnalysis?.providers?.filter(
    provider => provider.status === "checked"
  ) || [];
  if (threatAnalysis?.status === "completed" && checkedProviders.length === 0) {
    reasons.push("정상적으로 조회된 유해 URL 제공자가 없습니다.");
  }

  if (
    brandAnalysis?.status === "completed" &&
    brandAnalysis.signal === "brand_unidentified"
  ) {
    reasons.push("화면의 브랜드를 식별하지 못했습니다.");
  }

  if (reasons.length > 0) {
    return { verdict: "unknown", reasons };
  }

  const noteworthySignals = [
    ...(staticAnalysis?.signals || []),
    ...(browserAnalysis?.signals || []),
  ].filter(signal => ["medium", "high"].includes(signal.severity));

  if (noteworthySignals.length > 0) {
    return {
      verdict: "warn",
      reasons: noteworthySignals.map(signal => signal.summary),
    };
  }

  return {
    verdict: "allow",
    reasons: ["필수 검사를 완료했고 차단 신호를 발견하지 못했습니다."],
  };
}

module.exports = { decideVerdict };
