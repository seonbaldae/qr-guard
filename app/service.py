"""Single-process scan orchestration. Target webpages are visited only by C."""

import asyncio
from datetime import datetime, timezone
from uuid import uuid4

import httpx

from app.brand import BrandClient
from app.correlation import correlate
from app.config import Settings
from app.models import (
    Evidence, SandboxResult, ScanReport, ScanRequest, ScreenshotState, Signal, StaticAnalysisResult, VerdictResult,
)
from app.precheck.safebrowsing import check_safe_browsing
from app.precheck.payload import normalize
from app.normalization import BrandAssessment, normalize_brand
from app.static_adapter import ThreatCheck, analyze_static
from app.worker import WorkerClient, WorkerError, public_limitations


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class ScanCapacityError(Exception):
    pass


class ScanService:
    def __init__(
        self, settings: Settings, worker_transport: httpx.AsyncBaseTransport | None = None,
        threat_check: ThreatCheck | None = None,
    ) -> None:
        self.settings = settings
        self.threat_check = threat_check or check_safe_browsing
        self.worker = WorkerClient(settings, worker_transport)
        self.brand = BrandClient(settings)
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
        final_static = None
        brand = BrandAssessment()
        try:
            report.static_analysis, report.evidence = await asyncio.to_thread(
                analyze_static, request.url, self.threat_check,
            )
            report.sandbox_analysis = SandboxResult(
                status="not_requested", skip_reason="static_only",
            )
            if any(p.name == 'google_safe_browsing' and p.status == 'checked' and p.matched is True
                   for p in report.static_analysis.providers):
                if request.mode == "sandbox":
                    report.sandbox_analysis = SandboxResult(
                        status="skipped", skip_reason="known_malicious",
                        screenshot=ScreenshotState(status="skipped"),
                    )
            else:
                if request.mode == "sandbox":
                    final_static, brand = await self._run_worker(report, request)
            report.status = "completed"
            report.verdict = correlate(report, brand=brand, final_static=final_static)
        except Exception:
            # Never serialize an exception containing a target URL or query token.
            report.status = "failed"
            if report.sandbox_analysis.status in {"running", "pending"}:
                report.sandbox_analysis.status = 'failed'
                report.sandbox_analysis.error_code = 'analysis_error'
                if not report.sandbox_analysis.screenshot.available:
                    report.sandbox_analysis.screenshot = ScreenshotState(status='failed')
            report.verdict = VerdictResult(
                level="unknown", reasons=["분석을 완료하지 못했습니다."],
                limitations=["분석 중 내부 오류가 발생했습니다."],
            )
        report.updated_at = utcnow()

    async def _run_worker(self, report: ScanReport, request: ScanRequest) -> tuple[StaticAnalysisResult | None, BrandAssessment]:
        report.sandbox_analysis = SandboxResult(
            status="running", screenshot=ScreenshotState(status="pending"),
        )
        captured_url = None
        async def progress(job, png):
            nonlocal captured_url
            captured_url = job._lookup_url or job.final_url
            self.screenshots[report.scan_id] = png
            report.sandbox_analysis.screenshot = ScreenshotState(
                status='ready', available=True, captured_at=job.captured_at)
            report.sandbox_analysis.final_url = job.final_url
            report.sandbox_analysis.http_status = job.http_status
            report.updated_at = utcnow()

        try:
            async with self.worker_slots:
                result, png = await self.worker.analyze(report.scan_id, request.url, on_progress=progress)
        except WorkerError as exc:
            sandbox = report.sandbox_analysis
            sandbox.status = 'blocked' if exc.blocked else 'failed'
            sandbox.error_code = exc.code
            if not sandbox.screenshot.available:
                sandbox.screenshot = ScreenshotState(status='skipped' if exc.blocked else 'failed')
            sandbox.limitations.append('Worker 차단·실패는 안전을 뜻하지 않습니다.')
            return None, BrandAssessment()

        sandbox = report.sandbox_analysis
        sandbox.status = result.status
        sandbox.final_url, sandbox.http_status = result.final_url, result.http_status
        sandbox.dom_analysis = result.dom_analysis
        sandbox.network_analysis = result.network_analysis
        sandbox.redirect_analysis = result.redirect_analysis
        sandbox.limitations = public_limitations(result.limitations)
        sandbox.error_code = result.error_code if result.error_code in {'browser_error','worker_timeout','worker_error'} else None
        if result.status == 'failed':
            sandbox.limitations.append('브라우저 분석이 실패했습니다. 이미 검증된 PNG는 유지합니다.')
        if png is None:
            sandbox.screenshot = ScreenshotState(status='failed', error_code='screenshot_unavailable')
            sandbox.limitations.append('검증된 PNG가 없습니다.')

        # Rebuild bounded public evidence from typed observations. Never pass through arbitrary C text/data.
        data = [
            ('dom_observation', sandbox.dom_analysis, {'passwordFieldCount':sandbox.dom_analysis.password_field_count,
                'formCount':len(sandbox.dom_analysis.forms)} if sandbox.dom_analysis else {}),
            ('network_observation', sandbox.network_analysis, {'requestCount':sandbox.network_analysis.request_count,
                'blockedRequestCount':sandbox.network_analysis.blocked_request_count} if sandbox.network_analysis else {}),
            ('redirect_observation', sandbox.redirect_analysis, {'redirected':sandbox.redirect_analysis.redirected,
                'hopCount':len(sandbox.redirect_analysis.redirect_chain)} if sandbox.redirect_analysis else {}),
        ]
        for kind, observed, metadata in data:
            if observed is None:
                continue
            key = f'{report.scan_id}-{kind}'
            report.evidence.append(Evidence(id=key,kind=kind,source='browser',observed_at=utcnow(),
                summary='격리 브라우저에서 관찰한 메타데이터입니다. 실제 입력·제출은 하지 않았습니다.',data=metadata))
            sandbox.signals.append(Signal(id=key+'-signal',kind=kind,severity='info',source='browser',
                summary='관찰 사실이며 단독 피싱 판정은 아닙니다.',evidence_ids=[key]))

        final_static = None
        if result.final_url:
            lookup_url = result._lookup_url or result.final_url
            final_static, evidence = await asyncio.to_thread(analyze_static,lookup_url,self.threat_check)
            # Provider fixtures and cached lookups may reuse IDs; final checks get their own namespace.
            mapping = {item.id:f'{report.scan_id}-final-{item.id}' for item in evidence}
            for item in evidence:
                item.id = mapping[item.id]
            for signal in final_static.signals:
                signal.id = f'{report.scan_id}-final-{signal.id}'
                signal.evidence_ids = [mapping[key] for key in signal.evidence_ids if key in mapping]
            report.evidence.extend(evidence)
            sandbox.signals.extend(final_static.signals)
            if any(p.name == 'google_safe_browsing' and p.status == 'checked' and p.matched is True
                   for p in final_static.providers):
                return final_static, BrandAssessment()

        raw = None
        destination_proven = bool(result.redirect_analysis and result._lookup_url and (
            result.redirect_analysis.redirected or result._lookup_url == normalize(request.url)))
        screenshot_bound = (destination_proven and captured_url == result._lookup_url and not (
            result.redirect_analysis and any(e.type == 'client_navigation' and not e.blocked
                                             for e in result.redirect_analysis.redirect_chain)))
        screenshot_bound = screenshot_bound and not any('blank screenshot' in text.lower() for text in result.limitations)
        # Current C v0.3 already strips query/path secrets. A cannot recover them.
        # Redirection plus a redacted-only endpoint cannot establish a complete final-URL check.
        upstream_redacted = bool(not destination_proven or (
            result.redirect_analysis and result.redirect_analysis.redirected
            and result._lookup_url == result.final_url))
        if upstream_redacted:
            sandbox.limitations.append('Worker가 비식별화한 이동 URL만 제공해 전체 최종 URL의 위협 조회·PNG 동일성 확인이 제한됩니다.')
            screenshot_bound = False
        if png and not screenshot_bound:
            sandbox.limitations.append('초기 PNG와 최종 도착 페이지의 동일성을 확인하지 못해 브랜드 비교에 사용하지 않았습니다.')
        if png and screenshot_bound and result.final_url and result.status == 'completed':
            # One bounded model execution at a time; PNG remains publicly available throughout.
            async with self.worker_slots:
                raw = await self.brand.analyze(report.scan_id, result.final_url, png)
        brand, evidence = normalize_brand(raw,sandbox,scan_id=report.scan_id,observed_at=utcnow())
        report.evidence.extend(evidence)
        if not brand.reliable:
            sandbox.limitations.append('Phishpedia 식별·기준 도메인·모델 실행 근거를 신뢰 가능하게 확인하지 못했습니다.')
        return final_static, brand
