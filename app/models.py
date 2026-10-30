"""Public camelCase wire models, separate from B's internal result types."""

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, StrictStr, field_validator
from pydantic.alias_generators import to_camel

from app.precheck.payload import normalize

Mode = Literal["static", "sandbox"]
StageStatus = Literal["not_requested", "pending", "running", "completed", "failed", "blocked", "skipped"]


class WireModel(BaseModel):
    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True, extra="forbid")


class ScanRequest(WireModel):
    url: StrictStr
    source: Literal["qr", "manual"] = "qr"
    mode: Mode = "static"
    expected_brand: StrictStr | None = Field(default=None, max_length=80)

    @field_validator("url")
    @classmethod
    def validate_url(cls, value: str) -> str:
        normalize(value)
        return value


class ScanAccepted(WireModel):
    scan_id: str
    status: Literal["queued"] = "queued"
    mode: Mode


class ReportRequest(WireModel):
    scan_id: StrictStr = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9_-]+$")


class ReportReceipt(WireModel):
    scan_id: str
    report_count: int = Field(ge=0)
    is_reported: bool
    reported_by_user: bool


class Evidence(WireModel):
    id: str
    kind: str
    source: str
    observed_at: datetime
    summary: str
    data: dict[str, str | int | float | bool | None] | None = None


class Signal(WireModel):
    id: str
    kind: str
    severity: Literal["info", "low", "medium", "high"]
    summary: str
    source: str
    evidence_ids: list[str] = Field(default_factory=list)


class ProviderResult(WireModel):
    name: str
    status: Literal["checked", "stale", "failed"]
    matched: bool | None
    checked_at: datetime | None


class StaticAnalysisResult(WireModel):
    status: StageStatus
    registered_domain: str | None
    signals: list[Signal] = Field(default_factory=list)
    providers: list[ProviderResult] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)


class ScreenshotState(WireModel):
    status: Literal["not_requested", "pending", "ready", "failed", "skipped"] = "not_requested"
    available: bool = False
    captured_at: datetime | None = None
    expires_at: None = None
    error_code: str | None = None


class SandboxResult(WireModel):
    status: StageStatus = "not_requested"
    skip_reason: Literal["known_malicious", "static_only"] | None = None
    final_url: str | None = None
    http_status: int | None = None
    screenshot: ScreenshotState = Field(default_factory=ScreenshotState)
    signals: list[Signal] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    error_code: str | None = None


class VerdictResult(WireModel):
    level: Literal["malicious", "suspicious", "no_known_threat", "unknown"]
    reasons: list[str]
    evidence_ids: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)


class ScanReport(WireModel):
    scan_id: str
    status: Literal["queued", "running", "completed", "failed"]
    mode: Mode
    requested_url: str
    static_analysis: StaticAnalysisResult | None = None
    sandbox_analysis: SandboxResult = Field(default_factory=SandboxResult)
    evidence: list[Evidence] = Field(default_factory=list)
    verdict: VerdictResult | None = None
    updated_at: datetime
    report_count: int = Field(default=0, ge=0)
    is_reported: bool = False
    reported_by_user: bool = False
