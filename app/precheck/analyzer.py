"""B(정적 분석)의 진입점. API 계약 v0.2(8장) StaticAnalyzer.analyze에 대응한다.

사이트에는 접속하지 않고 URL 문자열만 본다. 위협 피드(OpenPhish, Safe Browsing)와
브랜드 유사도는 이 범위에 없다. 그래서 "검사하지 않은 범위"를 limitations에 항상 적고,
신호가 없다는 결과가 안전을 뜻하지 않게 한다. 최종 판정은 A(decideVerdict)가 한다.
"""

from app.precheck.schema import StaticAnalysisResult
from app.precheck.url_rules import parse, structure_signals

_LIMITATIONS = [
    "URL 구조만 검사했습니다.",
    "악성 URL 목록은 조회하지 않았습니다.",
    "웹페이지는 방문하지 않았습니다.",
]


def analyze(url: str) -> StaticAnalysisResult:
    """입력이 검사 불가이면 payload.InvalidPayload를 그대로 낸다."""
    parsed = parse(url)
    return StaticAnalysisResult(
        status="completed",
        registeredDomain=parsed.registered_domain,
        signals=structure_signals(parsed),
        evidence=[],
        providers=[],
        limitations=list(_LIMITATIONS),
    )
