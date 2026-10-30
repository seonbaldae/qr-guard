"""B(정적 분석)의 반환 타입. API 계약 v0.2(2장)의 JSON 형태를 그대로 옮긴 것.

팀 공용 models.py가 아니라 B 내부 구조다. A가 공용 위치로 옮기기로 하면 그때 이동한다.
필드 이름은 JSON 키와 같게 camelCase로 둔다.
"""

from typing import Literal

from pydantic import BaseModel, Field

Severity = Literal["info", "low", "medium", "high"]
ProviderStatus = Literal["checked", "failed", "stale"]
StageStatus = Literal[
    "not_requested", "pending", "running",
    "completed", "failed", "blocked", "skipped", "cancelled",
]


class Evidence(BaseModel):
    id: str
    kind: str
    source: str
    observedAt: str
    summary: str
    # URL 쿼리, 토큰, 개인정보 원문은 넣지 않는다.
    data: dict[str, str | int | float | bool | None] | None = None


class Signal(BaseModel):
    id: str
    kind: str
    severity: Severity
    summary: str
    source: str
    # 같은 응답의 Evidence.id를 가리킨다. 증거가 필요 없는 보조 신호는 빈 배열.
    evidenceIds: list[str] = Field(default_factory=list)


class ProviderResult(BaseModel):
    name: str
    status: ProviderStatus
    # True: 일치, False: 조회 성공 후 미탐지, None: 조회 실패(깨끗함이 아님)
    matched: bool | None
    checkedAt: str | None


class StaticAnalysisResult(BaseModel):
    status: StageStatus
    registeredDomain: str | None
    signals: list[Signal] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)
    providers: list[ProviderResult] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
