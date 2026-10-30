"""Preserve B's Google result and lift its evidence into the public report."""

from typing import Callable

from app.models import Evidence, StaticAnalysisResult
from app.precheck.analyzer import analyze
from app.precheck.safebrowsing import SafeBrowsingCheck

ThreatCheck = Callable[[str], SafeBrowsingCheck]


def analyze_static(url: str, check: ThreatCheck):
    result = analyze(url, check)
    static = StaticAnalysisResult.model_validate(result.model_dump(exclude={"evidence"}))
    evidence = [Evidence.model_validate(item.model_dump()) for item in result.evidence]
    static.limitations.append("정적 검사는 페이지 내용과 실제 정보 전송을 관찰하지 않습니다.")
    static.limitations.append("위협 조회 시 검사 URL이 Google에 전송됩니다. 미탐지는 안전 보장이 아닙니다.")
    return static, evidence
