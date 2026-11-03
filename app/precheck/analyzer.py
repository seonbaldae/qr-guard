"""B(정적 분석)의 진입점. API 계약 v0.2(8장) StaticAnalyzer.analyze에 대응한다.

사이트에는 접속하지 않는다. URL 문자열 규칙과 Google Safe Browsing 조회 결과를 합친다.
OpenPhish 피드와 브랜드 유사도는 이 범위에 없다. 최종 판정은 A(decideVerdict)가 한다.
"""

from typing import Callable

from app.precheck.safebrowsing import SafeBrowsingCheck, check_safe_browsing
from app.precheck.schema import StaticAnalysisResult
from app.precheck.url_rules import parse, structure_signals

_FAILED_LIMITATION = "Google Safe Browsing 조회를 완료하지 못했습니다."


def analyze(
    url: str,
    check: Callable[[str], SafeBrowsingCheck] = check_safe_browsing,
) -> StaticAnalysisResult:
    """입력이 검사 불가이면 payload.InvalidPayload를 그대로 낸다."""
    parsed = parse(url)
    lookup = check(parsed.url)
    return StaticAnalysisResult(
        status="completed",
        registeredDomain=parsed.registered_domain,
        signals=lookup.signals + structure_signals(parsed),
        evidence=lookup.evidence,
        providers=[lookup.provider],
        limitations=[_FAILED_LIMITATION] if lookup.provider.status == "failed" else [],
    )
