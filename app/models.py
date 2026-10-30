"""Public camelCase wire models, separate from B's internal result types."""

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictStr, field_validator
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


class FormObservation(WireModel):
    method: StrictStr = Field(max_length=16)
    action_host: StrictStr | None = Field(default=None, max_length=255, pattern=r"^[A-Za-z0-9._:\[\]-]+$")


class DomAnalysis(WireModel):
    page_title: StrictStr | None = Field(max_length=500)
    password_field_count: int = Field(strict=True, ge=0, le=1000)
    sensitive_field_types: list[Literal['password', 'otp', 'payment_card']] = Field(max_length=3)
    forms: list[FormObservation] = Field(max_length=100)


class NetworkAnalysis(WireModel):
    request_hosts: list[StrictStr] = Field(max_length=200)
    request_count: int = Field(strict=True, ge=0, le=10000)
    blocked_request_count: int = Field(strict=True, ge=0, le=10000)


class RedirectEdge(WireModel):
    from_url: StrictStr = Field(alias='from', max_length=4096)
    to: StrictStr = Field(max_length=4096)
    status_code: int | None = Field(strict=True, ge=100, le=599)
    type: Literal['http', 'client_navigation', 'unknown']
    blocked: StrictBool


class RedirectAnalysis(WireModel):
    redirected: StrictBool
    final_url: StrictStr | None = Field(max_length=4096)
    redirect_chain: list[RedirectEdge] = Field(max_length=100)


class LogoAnalysis(WireModel):
    status: Literal['completed', 'unknown', 'failed', 'not_available']
    detected_brand: StrictStr | None = Field(default=None, max_length=100)
    similarity_score: float | None = Field(default=None, allow_inf_nan=False)
    method: StrictStr | None = Field(default=None, max_length=100)
    reference_version: StrictStr | None = Field(default=None, max_length=128)


class DomainAnalysis(WireModel):
    status: Literal['completed', 'unknown', 'not_available']
    official_domain: StrictStr | None = Field(default=None, max_length=255)
    observed_domain: StrictStr | None = Field(default=None, max_length=255)
    domain_mismatch: StrictBool | None = None


class SandboxResult(WireModel):
    status: StageStatus = "not_requested"
    skip_reason: Literal["known_malicious", "static_only"] | None = None
    final_url: str | None = None
    http_status: int | None = None
    screenshot: ScreenshotState = Field(default_factory=ScreenshotState)
    signals: list[Signal] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    error_code: str | None = None
    logo_analysis: LogoAnalysis | None = None
    domain_analysis: DomainAnalysis | None = None
    dom_analysis: DomAnalysis | None = None
    network_analysis: NetworkAnalysis | None = None
    redirect_analysis: RedirectAnalysis | None = None


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
