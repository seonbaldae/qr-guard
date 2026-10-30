"""Single-process scan orchestration. Target webpages are visited only by C."""

import asyncio
from datetime import datetime, timezone
from uuid import uuid4

import httpx

from app.brands import OFFICIAL_BRAND_DOMAINS
from app.config import Settings
from app.models import (
    Evidence, SandboxResult, ScanReport, ScanRequest, ScreenshotState, Signal, VerdictResult,
)
from app.phishpedia import PhishpediaAnalyzer, PhishpediaError
from app.precheck.safebrowsing import check_safe_browsing
from app.precheck.url_rules import parse
from app.static_adapter import ThreatCheck, analyze_static
from app.worker import WorkerClient, WorkerError


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class ScanCapacityError(Exception):
    pass


class ScanService:
    def __init__(
        self, settings: Settings, worker_transport: httpx.AsyncBaseTransport | None = None,
        threat_check: ThreatCheck | None = None, brand_analyzer: PhishpediaAnalyzer | None = None,
    ) -> None:
        self.settings = settings
        self.threat_check = threat_check or check_safe_browsing
        self.worker = WorkerClient(settings, worker_transport)
        self.brand_analyzer = brand_analyzer or PhishpediaAnalyzer(settings)
        self.worker_slots = asyncio.Semaphore(settings.max_worker_concurrency)
        self.reports: dict[str, ScanReport] = {}
        self.screenshots: dict[str, bytes] = {}

    def create(self, request: ScanRequest) -> ScanReport:
        if len(self.reports) >= self.settings.max_scans:
            raise ScanCapacityError
        report = ScanReport(
            scan_id=uuid4().hex, status="queued", mode=request.mode,
            requested_url=request.url, updated_at=utcnow(),
        )
        self.reports[report.scan_id] = report
        return report

    async def run(self, scan_id: str, request: ScanRequest) -> None:
        report = self.reports[scan_id]
        report.status = "running"
        report.updated_at = utcnow()
        try:
            report.static_analysis, report.evidence = await asyncio.to_thread(
                analyze_static, request.url, self.threat_check,
            )
            report.sandbox_analysis = SandboxResult(
                status="not_requested", skip_reason="static_only",
            )
            if report.static_analysis.providers[0].matched:
                if request.mode == "sandbox":
                    report.sandbox_analysis = SandboxResult(
                        status="skipped", skip_reason="known_malicious",
                        screenshot=ScreenshotState(status="skipped"),
                    )
                report.verdict = VerdictResult(
                    level="malicious", reasons=["Google Safe Browsing에서 알려진 위협이 발견되었습니다."],
                    evidence_ids=[item.id for item in report.evidence if item.kind == "known_threat_match"],
                    limitations=["웹페이지를 방문하지 않았습니다."],
                )
            else:
                report.verdict = VerdictResult(
                    level="unknown", reasons=["위협 정보를 충분히 확인하지 못했습니다."],
                    limitations=["웹페이지를 방문하지 않았습니다."],
                )
                if request.mode == "sandbox":
                    await self._run_worker(report, request)
                elif (report.static_analysis.providers[0].status == "checked"
                      and request.expected_brand is None):
                    report.verdict = VerdictResult(
                        level="no_known_threat", reasons=["정적 검사 범위에서 알려진 위협이 발견되지 않았습니다."],
                        limitations=["페이지 내용은 검사하지 않았습니다.", "검사 결과는 안전을 보증하지 않습니다."],
                    )
            report.status = "completed"
        except Exception:
            # Never serialize an exception containing a target URL or query token.
            report.status = "failed"
            if report.sandbox_analysis.status in {"running", "pending"}:
                report.sandbox_analysis = SandboxResult(
                    status="failed", error_code="analysis_error",
                    screenshot=ScreenshotState(status="failed"),
                    limitations=["격리 브라우저 결과 처리 중 오류가 발생했습니다."],
                )
                self.screenshots.pop(scan_id, None)
            report.verdict = VerdictResult(
                level="unknown", reasons=["분석을 완료하지 못했습니다."],
                limitations=["분석 중 내부 오류가 발생했습니다."],
            )
        report.updated_at = utcnow()

    async def _run_worker(self, report: ScanReport, request: ScanRequest) -> None:
        report.sandbox_analysis = SandboxResult(
            status="running", screenshot=ScreenshotState(status="pending"),
        )
        try:
            async with self.worker_slots:
                result, png = await self.worker.analyze(report.scan_id, request.url)
        except WorkerError as exc:
            report.sandbox_analysis = SandboxResult(
                status="blocked" if exc.blocked else "failed", error_code=exc.code,
                screenshot=ScreenshotState(status="skipped" if exc.blocked else "failed"),
                limitations=["격리 브라우저 검사를 완료하지 못했습니다."],
            )
            report.verdict = VerdictResult(
                level="unknown", reasons=["동적 검사 결과가 충분하지 않습니다."],
                limitations=["Worker 차단·실패는 안전을 뜻하지 않습니다."],
            )
            return
        self.screenshots[report.scan_id] = png
        report.evidence.extend(result.evidence)
        report.sandbox_analysis = SandboxResult(
            status="completed", final_url=result.final_url, http_status=result.http_status,
            screenshot=ScreenshotState(status="ready", available=True, captured_at=utcnow()),
            signals=result.signals,
            limitations=["폼 제출과 실제 정보 유출은 검사하지 않았습니다.", *result.limitations],
        )
        assert report.static_analysis is not None
        assert result.final_url is not None
        provider = report.static_analysis.providers[0]
        final_lookup = await asyncio.to_thread(self.threat_check, result.final_url)
        final_provider = final_lookup.provider
        if final_provider.matched:
            final_evidence = [Evidence.model_validate(item.model_dump()) for item in final_lookup.evidence]
            report.evidence.extend(final_evidence)
            report.sandbox_analysis.signals.extend(
                Signal.model_validate(item.model_dump()) for item in final_lookup.signals
            )
            report.verdict = VerdictResult(
                level="malicious", reasons=["Google에서 최종 도착 URL에 대한 알려진 위협이 발견되었습니다."],
                evidence_ids=[item.id for item in final_evidence], limitations=["폼 제출과 실제 정보 유출은 검사하지 않았습니다.",
                                                        *result.limitations],
            )
            return
        brand_complete = not self.brand_analyzer.enabled
        brand_signal = None
        if self.brand_analyzer.enabled:
            try:
                brand = await self.brand_analyzer.analyze(report.scan_id, result.final_url, png)
                brand_signal = brand.signal
                brand_complete = brand.signal == "brand_domain_match"
                if brand.signal == "brand_domain_inconsistency":
                    evidence_id = "ev-phishpedia-brand"
                    report.evidence.append(Evidence(
                        id=evidence_id, kind="brand_domain_mismatch", source="phishpedia",
                        observed_at=utcnow(),
                        summary="화면에서 식별한 브랜드의 기준 도메인과 실제 도착 도메인이 다릅니다.",
                        data={
                            "candidateBrand": brand.candidate_brand,
                            "observedDomain": brand.domain_comparison.actual_host,
                            "similarity": brand.raw_similarity,
                        },
                    ))
                    report.sandbox_analysis.signals.append(Signal(
                        id="sig-phishpedia-brand", kind="brand_domain_mismatch", severity="high",
                        source="phishpedia",
                        summary=f"{brand.candidate_brand or '알려진 브랜드'} 화면과 실제 도메인이 일치하지 않습니다.",
                        evidence_ids=[evidence_id],
                    ))
                    report.verdict = VerdictResult(
                        level="suspicious",
                        reasons=["정상 브랜드를 사칭한 화면일 가능성이 있습니다."],
                        evidence_ids=[evidence_id],
                        limitations=["로고 유사도 분석은 브랜드 운영 주체를 확정하지 않습니다.",
                                     "실제 계정 정보 제출이나 유출을 검증한 것은 아닙니다.",
                                     *result.limitations],
                    )
                    return
            except PhishpediaError:
                report.sandbox_analysis.limitations.append("브랜드 로고 분석을 완료하지 못했습니다.")
        official = OFFICIAL_BRAND_DOMAINS.get(request.expected_brand or "")
        observed = parse(result.final_url).registered_domain
        mismatch = official is not None and observed != official
        if mismatch:
            report.evidence.append(Evidence(
                id="ev-brand", kind="brand_domain_mismatch", source="local-rule", observed_at=utcnow(),
                summary="선택한 브랜드의 공식 도메인과 실제 도착 도메인이 다릅니다.",
                data={"expectedDomain": official, "observedDomain": observed},
            ))
        if result.password_field_count:
            report.evidence.append(Evidence(
                id="ev-password", kind="password_field", source="browser", observed_at=utcnow(),
                summary="렌더링된 페이지에서 비밀번호 필드가 관찰되었습니다.",
                data={"count": result.password_field_count},
            ))
        if mismatch and result.password_field_count:
            ids = ["ev-brand", "ev-password"]
            report.sandbox_analysis.signals.append(Signal(
                id="sig-brand-login", kind="brand_login_mismatch", severity="high", source="local-rule",
                summary="브랜드 공식 도메인이 아닌 페이지에서 비밀번호 필드가 관찰되었습니다.",
                evidence_ids=ids,
            ))
            report.verdict = VerdictResult(
                level="suspicious", reasons=["선택한 브랜드와 다른 도메인에서 로그인을 요구하는 징후가 있습니다."],
                evidence_ids=ids,
                limitations=["실제 계정 정보 제출이나 유출을 검증한 것은 아닙니다.", *result.limitations],
            )
            return
        complete = (provider.status == "checked" and final_provider.status == "checked"
                    and result.inspection_complete
                    and (request.expected_brand is None or official is not None)
                    and brand_complete)
        brand_limitations = []
        if self.brand_analyzer.enabled and brand_signal == "brand_unidentified":
            brand_limitations.append("화면에서 비교 가능한 브랜드 로고를 식별하지 못했습니다.")
        elif self.brand_analyzer.enabled and brand_signal is None:
            brand_limitations.append("브랜드 로고 분석 결과를 확인하지 못했습니다.")
        report.verdict = VerdictResult(
            level="no_known_threat" if complete else "unknown",
            reasons=["검사 범위에서 알려진 위협이 발견되지 않았습니다." if complete
                     else "검사 범위에 제한이 있어 결론을 내리지 못했습니다."],
            limitations=["검사 결과는 안전을 보증하지 않습니다.", "폼 제출과 실제 정보 유출은 검사하지 않았습니다.",
                         *brand_limitations, *result.limitations],
        )
