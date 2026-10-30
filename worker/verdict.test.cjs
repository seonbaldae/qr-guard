const test = require("node:test");
const assert = require("node:assert/strict");
const { decideVerdict } = require("./verdict.cjs");

function completed(overrides = {}) {
  return {
    staticAnalysis: { status: "completed", signals: [] },
    threatAnalysis: {
      status: "completed",
      providers: [{ name: "test-feed", status: "checked", matched: false }],
    },
    browserAnalysis: { status: "completed", signals: [] },
    brandAnalysis: { status: "completed", signal: "brand_domain_match" },
    ...overrides,
  };
}

test("유해 URL 제공자 일치는 즉시 차단한다", () => {
  const input = completed();
  input.threatAnalysis.providers[0].matched = true;
  assert.equal(decideVerdict(input).verdict, "block");
});

test("브랜드와 도메인이 다르면 즉시 차단한다", () => {
  const result = decideVerdict(completed({
    brandAnalysis: {
      status: "completed",
      signal: "brand_domain_inconsistency",
      candidateBrand: "PayPal",
    },
  }));
  assert.equal(result.verdict, "block");
});

test("내부망 목적지 요청은 즉시 차단한다", () => {
  const result = decideVerdict(completed({
    browserAnalysis: {
      status: "blocked",
      signals: [{
        kind: "blocked_destination",
        severity: "high",
        summary: "내부망 요청을 차단했습니다.",
      }],
    },
  }));
  assert.equal(result.verdict, "block");
});

test("필수 단계가 실패하거나 실행되지 않으면 unknown이다", () => {
  assert.equal(decideVerdict(completed({
    threatAnalysis: { status: "failed", providers: [] },
  })).verdict, "unknown");
  assert.equal(decideVerdict(completed({
    staticAnalysis: { status: "not_run", signals: [] },
  })).verdict, "unknown");
});

test("브랜드 미식별을 정상으로 판정하지 않는다", () => {
  assert.equal(decideVerdict(completed({
    brandAnalysis: { status: "completed", signal: "brand_unidentified" },
  })).verdict, "unknown");
});

test("중간 이상 휴리스틱 신호가 있으면 경고한다", () => {
  const result = decideVerdict(completed({
    staticAnalysis: {
      status: "completed",
      signals: [{ severity: "medium", summary: "IP 주소를 사용합니다." }],
    },
  }));
  assert.equal(result.verdict, "warn");
});

test("모든 검사가 완료되고 신호가 없을 때만 허용한다", () => {
  assert.equal(decideVerdict(completed()).verdict, "allow");
});
