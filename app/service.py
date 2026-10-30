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
from app.precheck.url_rules import parse
from app.static_adapter import FeedSnapshot, analyze_static
from app.worker import WorkerClient, WorkerError


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class ScanCapacityError(Exception):
    pass


class ScanService:
    def __init__(self, settings: Settings, worker_transport: httpx.AsyncBaseTransport | None = None) -> None:
        self.settings = settings
        self.feed = FeedSnapshot.load(settings)
        self.worker = WorkerClient(settings, worker_transport)
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
                analyze_static, request.url, self.feed, self.settings,
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
                    level="malicious", reasons=["알려진 피싱 URL로 확인되었습니다."],
                    evidence_ids=["ev-feed"], limitations=["웹페이지를 방문하지 않았습니다."],
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
        report.sandbox_analysis = SandboxResult(
            status="completed", final_url=result.final_url, http_status=result.http_status,
            screenshot=ScreenshotState(status="ready", available=True, captured_at=utcnow()),
            limitations=["폼 제출과 실제 정보 유출은 검사하지 않았습니다.", *result.limitations],
        )
        assert report.static_analysis is not None
        assert result.final_url is not None
        provider = report.static_analysis.providers[0]
        final_provider = self.feed.lookup(result.final_url, self.settings.feed_max_age_seconds)
        if final_provider.matched:
            assert final_provider.checked_at is not None
            report.evidence.append(Evidence(
                id="ev-feed", kind="threat_feed_match", source="openphish",
                observed_at=final_provider.checked_at,
                summary="최종 도착 URL이 피싱 URL 목록과 정확히 일치했습니다.",
            ))
            report.sandbox_analysis.signals.append(Signal(
                id="sig-feed", kind="threat_feed_match", severity="high", source="openphish",
                summary="최종 도착 URL이 피싱 URL 목록에 일치합니다.", evidence_ids=["ev-feed"],
            ))
            report.verdict = VerdictResult(
                level="malicious", reasons=["최종 도착 URL이 알려진 피싱 URL로 확인되었습니다."],
                evidence_ids=["ev-feed"], limitations=["폼 제출과 실제 정보 유출은 검사하지 않았습니다.",
                                                        *result.limitations],
            )
            return
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
                    and not result.limitations
                    and (request.expected_brand is None or official is not None))
        report.verdict = VerdictResult(
            level="no_known_threat" if complete else "unknown",
            reasons=["검사 범위에서 알려진 위협이 발견되지 않았습니다." if complete
                     else "검사 범위에 제한이 있어 결론을 내리지 못했습니다."],
            limitations=["검사 결과는 안전을 보증하지 않습니다.", "폼 제출과 실제 정보 유출은 검사하지 않았습니다.",
                         *result.limitations],
        )
