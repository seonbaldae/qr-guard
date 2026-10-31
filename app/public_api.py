"""One request owns its static lookup and optional disposable cloud visit.

No job, screenshot, or report state is retained in the serverless instance.
The independently maintained development Docker client is not imported here.
"""

import asyncio
import base64
from datetime import datetime, timezone
import os
from urllib.parse import urlsplit
from uuid import uuid4

from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import field_validator

from app.config import configured_origin
from app.cloud_phishpedia import (
    BrandEnvelope, CloudBrandAnalysis, CloudPhishpediaAnalyzer, validate_brand_result,
)
from app.cloud_worker import CloudBrowserResult, CloudWorkerClient, CloudWorkerError, _decode_png, _public_url
from app.models import (
    Evidence, ProviderResult, SandboxResult, ScanReport, ScanRequest, ScreenshotState, Signal,
    StaticAnalysisResult, VerdictResult,
)
from app.precheck.safebrowsing import check_safe_browsing
from app.static_adapter import ThreatCheck, analyze_static

MAX_REQUEST_BYTES = 16 * 1024
LOOKUP_TIMEOUT_SECONDS = 12
ANALYSIS_TIMEOUT_SECONDS = 230
SCOPE_NOTICE = "현재는 주소만 검사하며 사이트 화면은 확인하지 않았습니다."
WORKER_NOTICE = "Docker 미리보기는 점검 중입니다."
REPORT_NOTICE = "신고 접수는 준비 중입니다."
BRAND_UNAVAILABLE_NOTICE = "브랜드 사칭 판별 모델은 연결되지 않아 화면이 정상처럼 보여도 사칭 여부를 확정할 수 없습니다."
CLOUD_LIMITATIONS = [
    "초기 화면과 짧은 관찰 구간만 확인했으며 로그인·입력·폼 제출은 수행하지 않았습니다.",
    BRAND_UNAVAILABLE_NOTICE,
    "검사 결과는 안전을 보증하지 않습니다.",
]
_CLOUD_ERROR_CODES = {
    "worker_timeout", "worker_unreachable", "worker_invalid_response", "invalid_screenshot",
    "worker_not_configured", "unsafe_target", "worker_policy_blocked",
}


def capabilities(cloud_worker=None, brand_analyzer=None):
    enabled = bool(cloud_worker is not None and cloud_worker.enabled)
    return {
        "scanTransport": "direct", "scanMode": "sandbox" if enabled else "static",
        "analysisScope": "sandbox" if enabled else "static",
        "previewAvailable": enabled, "reportAvailable": False,
        "brandAnalysisAvailable": bool(enabled and brand_analyzer is not None and brand_analyzer.enabled),
    }


def configured_cloud_worker():
    """An image name alone cannot turn on an unverified public browser."""
    if os.getenv("QR_GUARD_CLOUD_WORKER_VERIFIED") != "true":
        return CloudWorkerClient(None)
    try:
        return CloudWorkerClient(os.getenv("QR_GUARD_CLOUD_WORKER_IMAGE"),
                                 snapshot_id=os.getenv("QR_GUARD_CLOUD_WORKER_SNAPSHOT"))
    except ValueError:
        return CloudWorkerClient(None)


def configured_brand_analyzer():
    try:
        return CloudPhishpediaAnalyzer(os.getenv("QR_GUARD_PHISHPEDIA_SNAPSHOT"))
    except ValueError:
        return CloudPhishpediaAnalyzer(None)


async def _static_lookup(url, check, timeout=LOOKUP_TIMEOUT_SECONDS):
    try:
        async with asyncio.timeout(timeout):
            return await asyncio.to_thread(analyze_static, url, check)
    except Exception:
        # Transport exceptions may include API keys and URL tokens.
        return StaticAnalysisResult(status="failed", registered_domain=None, providers=[
            ProviderResult(name="google_safe_browsing", status="failed", matched=None, checked_at=None),
        ], limitations=["위협 정보 조회를 완료하지 못했습니다."]), []


def _cloud_observations(result, scan_id):
    """Project trusted schema fields into primitive facts, without raw VM logs."""
    evidence, signals = [], []
    observed_at = result.captured_at or datetime.now(timezone.utc)

    def add(kind, summary, data, severity="info"):
        item = Evidence(id=f"ev-cloud-{scan_id}-{kind}", kind=kind, source="cloud_browser",
                        observed_at=observed_at, summary=summary, data=data)
        evidence.append(item)
        signals.append(Signal(id=f"sig-cloud-{scan_id}-{kind}", kind=kind, source="cloud_browser",
                              severity=severity, summary=summary, evidence_ids=[item.id]))

    if result.dom_analysis is not None:
        dom = result.dom_analysis
        add("dom_observation", f"비밀번호 입력 필드 {dom.password_field_count}개를 관찰했습니다.", {
            "passwordFieldCount": dom.password_field_count, "formCount": len(dom.forms),
            "sensitiveFieldTypeCount": len(dom.sensitive_field_types), "pageTitle": dom.page_title,
        }, "medium" if dom.password_field_count else "info")
    if result.network_analysis is not None:
        network = result.network_analysis
        add("network_observation", f"네트워크 요청 {network.request_count}건과 정책 차단 {network.blocked_request_count}건을 관찰했습니다.", {
            "requestCount": network.request_count, "blockedRequestCount": network.blocked_request_count,
            "hostCount": len(network.request_hosts),
        }, "medium" if network.blocked_request_count else "info")
    if result.redirect_analysis is not None:
        redirect = result.redirect_analysis
        add("redirect_observation", f"페이지 이동 {len(redirect.redirect_chain)}건을 관찰했습니다.", {
            "redirected": redirect.redirected, "redirectCount": len(redirect.redirect_chain),
        })
    return evidence, signals


async def _cloud_report(worker, scan_id, url, check, deadline):
    png = None
    try:
        async with asyncio.timeout(max(0.001, deadline - asyncio.get_running_loop().time())):
            result, png = await worker.analyze(scan_id, url)
        # Revalidate injected adapters too; one request must own its exact result.
        result = CloudBrowserResult.model_validate(result.model_dump(by_alias=True))
        if result.scan_id != scan_id:
            raise CloudWorkerError("worker_invalid_response")
        if result.final_url:
            _public_url(result.final_url)
        if png is not None:
            png = _decode_png(png)
        if result.screenshot_status != "ready":
            png = None
        policy_blocked = bool(result.error_code in {"unsafe_target", "worker_policy_blocked"} or (
            result.network_analysis and result.network_analysis.blocked_request_count > 0
        ))
        complete = bool(result.status == "completed" and result.inspection_complete and png and result.final_url
                        and result.http_status is not None and result.http_status < 400
                        and result.dom_analysis and result.network_analysis and result.redirect_analysis and not policy_blocked)
        evidence, signals = _cloud_observations(result, scan_id)
        sandbox = SandboxResult(
            status="completed" if complete else "blocked" if policy_blocked else "failed", final_url=result.final_url,
            http_status=result.http_status, signals=signals,
            screenshot=ScreenshotState(status="ready" if png else "failed", available=bool(png),
                                       captured_at=result.captured_at if png else None,
                                       error_code=None if png else "invalid_screenshot"),
            limitations=list(dict.fromkeys([*result.limitations, *CLOUD_LIMITATIONS])),
            error_code=result.error_code if result.error_code in _CLOUD_ERROR_CODES else None,
        )
        verdict = VerdictResult(
            level="unknown", reasons=[
                "격리 환경에서 페이지를 관찰했지만 사칭 여부를 충분히 판별하지 못했습니다." if complete
                else "격리 환경의 검사를 완료하지 못해 판단을 보류했습니다."
            ], evidence_ids=[item.id for item in evidence], limitations=sandbox.limitations,
        )
        if result.final_url:
            final_static, final_evidence = await _static_lookup(
                result.final_url, check,
                min(LOOKUP_TIMEOUT_SECONDS, max(0.001, deadline - asyncio.get_running_loop().time())),
            )
            final_provider = final_static.providers[0] if final_static.providers else None
            final_id_map = {item.id: f"final-{item.id}" for item in final_evidence}
            final_evidence = [item.model_copy(update={"id": final_id_map[item.id]}) for item in final_evidence]
            evidence.extend(final_evidence)
            sandbox.signals.extend(item.model_copy(update={
                "id": f"final-{item.id}", "evidence_ids": [final_id_map[key] for key in item.evidence_ids if key in final_id_map],
            }) for item in final_static.signals)
            provider_evidence = Evidence(
                id=f"ev-cloud-{scan_id}-final-provider", kind="final_url_threat_lookup", source="google_safe_browsing",
                observed_at=datetime.now(timezone.utc), summary="실제로 확인한 도착 주소의 위협 목록 조회 결과입니다.",
                data={"status": final_provider.status if final_provider else "failed",
                      "matched": final_provider.matched if final_provider else None},
            )
            evidence.append(provider_evidence)
            if final_provider is not None and final_provider.status == "checked" and final_provider.matched is True:
                verdict = VerdictResult(level="malicious", reasons=["실제 도착 주소에서 Google Safe Browsing의 알려진 위협이 발견되었습니다."],
                                        evidence_ids=[item.id for item in final_evidence if item.kind == "known_threat_match"],
                                        limitations=sandbox.limitations)
            elif final_provider is None or final_provider.status != "checked":
                sandbox.limitations.append("실제 도착 주소의 위협 정보 조회를 완료하지 못했습니다.")
                verdict.limitations = list(sandbox.limitations)
        return sandbox, verdict, evidence, png
    except Exception as error:
        code = "worker_timeout" if isinstance(error, TimeoutError) else getattr(error, "code", "worker_unreachable")
        code = code if code in _CLOUD_ERROR_CODES else "worker_unreachable"
        blocked = isinstance(error, CloudWorkerError) and error.blocked
        limitations = ["격리 브라우저 검사를 완료하지 못했습니다.", *CLOUD_LIMITATIONS]
        return SandboxResult(status="blocked" if blocked else "failed", error_code=code, limitations=limitations,
                             screenshot=ScreenshotState(status="failed", error_code=code)), VerdictResult(
            level="unknown", reasons=["격리 환경의 검사를 완료하지 못해 판단을 보류했습니다."], limitations=limitations,
        ), [], None


async def _brand_report(analyzer, scan_id, sandbox, verdict, png, evidence, deadline):
    """Inference failure never discards a valid screenshot or grants access."""
    if verdict.level == "malicious":
        return {"engine": "phishpedia", "status": "skipped", "reason": "known_malicious"}, verdict
    if not analyzer.enabled:
        return {"engine": "phishpedia", "status": "not_configured"}, verdict

    # The browser's own statement is still correct for that process, but an
    # independently running model must not be described as never connected.
    stale_notices = {
        BRAND_UNAVAILABLE_NOTICE,
        "로그인·입력·폼 제출과 브랜드 모델 분석은 수행하지 않았습니다.",
    }
    sandbox.limitations = [item for item in sandbox.limitations if item not in stale_notices]
    if sandbox.status != "completed" or not png or not sandbox.final_url:
        sandbox.limitations.append("화면과 실제 도착 주소의 관찰을 완료하지 못해 브랜드 로고 분석을 생략했습니다.")
        verdict.limitations = list(sandbox.limitations)
        return {"engine": "phishpedia", "status": "skipped", "reason": "browser_incomplete"}, verdict
    try:
        remaining = max(0.001, deadline - asyncio.get_running_loop().time())
        async with asyncio.timeout(remaining):
            brand = await analyzer.analyze(scan_id, sandbox.final_url, png)
        # Validate injected adapters with the same strict wire schema.
        brand = CloudBrandAnalysis.model_validate(brand.model_dump(by_alias=True))
        brand = validate_brand_result(BrandEnvelope(scan_id=scan_id, final_url=sandbox.final_url,
                                                   brand_analysis=brand), scan_id, sandbox.final_url)
    except Exception as error:
        code = "phishpedia_timeout" if isinstance(error, TimeoutError) else getattr(error, "code", "phishpedia_failed")
        if code not in {"phishpedia_timeout", "phishpedia_failed", "phishpedia_unreachable",
                        "phishpedia_invalid_response", "phishpedia_result_mismatch", "phishpedia_invalid_input"}:
            code = "phishpedia_failed"
        sandbox.limitations.append("Phishpedia 브랜드 로고 분석을 완료하지 못했습니다.")
        verdict.reasons = ["브랜드 로고 분석을 완료하지 못해 사칭 여부의 판단을 보류했습니다."]
        verdict.limitations = list(sandbox.limitations)
        return {"engine": "phishpedia", "status": "failed", "errorCode": code}, verdict

    limitations = [
        "Phishpedia는 기준 자료에 포함된 로고의 시각적 유사도를 비교하며 모든 사칭 사이트를 탐지하지는 못합니다.",
        "로고 유사도와 도메인 비교는 공식 운영 인증이나 실제 정보 유출의 증명이 아닙니다.",
    ]
    sandbox.limitations = list(dict.fromkeys([*sandbox.limitations, *limitations]))
    kind = {"brand_domain_inconsistency": "brand_domain_mismatch",
            "brand_domain_match": "brand_domain_match", "brand_unidentified": "brand_unidentified"}[brand.signal]
    mismatch = brand.signal == "brand_domain_inconsistency"
    if mismatch:
        summary = f"Phishpedia가 식별한 {brand.candidate_brand} 로고 후보의 기준 도메인과 실제 도착 도메인이 다릅니다."
    elif brand.signal == "brand_domain_match":
        summary = f"Phishpedia가 식별한 {brand.candidate_brand} 로고 후보의 기준 도메인 범위에 실제 도착 도메인이 포함됩니다."
    else:
        summary = "Phishpedia의 기준 로고 자료에서 신뢰 기준을 충족하는 브랜드 후보를 식별하지 못했습니다."
    evidence_id = f"ev-phishpedia-{scan_id}-brand"
    evidence.append(Evidence(
        id=evidence_id, kind=kind, source="phishpedia", observed_at=datetime.now(timezone.utc), summary=summary,
        data={"candidateBrand": brand.candidate_brand, "observedDomain": brand.domain_comparison.actual_host,
              "referenceDomains": ", ".join(brand.reference_domains), "similarity": brand.raw_similarity,
              "detectedLogoCount": brand.detected_logo_count, "domainComparison": brand.domain_comparison.status},
    ))
    sandbox.signals.append(Signal(
        id=f"sig-phishpedia-{scan_id}-brand", kind=kind, source="phishpedia",
        severity="high" if mismatch else "info", summary=summary, evidence_ids=[evidence_id],
    ))
    if mismatch:
        verdict = VerdictResult(level="suspicious", reasons=[summary, "브랜드 사칭이 의심되어 사이트 연결을 제공하지 않습니다."],
                                evidence_ids=[evidence_id], limitations=list(sandbox.limitations))
    else:
        # Even a matching logo/domain pair cannot establish a site's safety.
        verdict = VerdictResult(level="unknown", reasons=[summary, "이 결과만으로 사이트의 안전 여부를 확정할 수 없습니다."],
                                evidence_ids=[*verdict.evidence_ids, evidence_id], limitations=list(sandbox.limitations))
    return {**brand.model_dump(mode="json", by_alias=True), "evidenceIds": [evidence_id]}, verdict


class PublicScanRequest(ScanRequest):
    @field_validator("url")
    @classmethod
    def reject_credentials(cls, value):
        parts = urlsplit(value.strip())
        if "@" in parts.netloc or parts.username is not None or parts.password is not None:
            raise ValueError("Credentials are not allowed")
        return value


class PublicBoundaryMiddleware:
    """Bound bodies before parsing and reject cross-origin browser requests.

    Origin checks are browser protections, not authentication or a rate limiter.
    Non-browser clients without Origin remain supported by this public API.
    """

    def __init__(self, app, allowed_origins):
        self.app = app
        self.allowed_origins = frozenset(allowed_origins)

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or not scope.get("path", "").startswith("/api/"):
            return await self.app(scope, receive, send)

        async def private_send(message):
            if message["type"] == "http.response.start":
                message = dict(message)
                headers = [(key, value) for key, value in message.get("headers", [])
                           if key.lower() not in {b"cache-control", b"x-content-type-options"}]
                message["headers"] = [*headers, (b"cache-control", b"no-store"),
                                      (b"x-content-type-options", b"nosniff")]
            await send(message)

        async def reject(status, code, message):
            return await JSONResponse(status_code=status, content={
                "error": {"code": code, "message": message},
            })(scope, receive, private_send)

        headers = scope.get("headers", [])
        origins = [value.decode("latin1") for key, value in headers if key.lower() == b"origin"]
        host = next((value.decode("latin1") for key, value in headers if key.lower() == b"host"), "")
        if len(origins) > 1:
            return await reject(400, "invalid_origin", "요청 출처를 확인하지 못했습니다.")
        if origins:
            try:
                origin = configured_origin(origins[0])
                # With no allowlist, only the browser's current host is accepted.
                allowed = origin in self.allowed_origins if self.allowed_origins else (
                    urlsplit(origin).netloc.casefold() == host.casefold()
                )
            except ValueError:
                allowed = False
            if not allowed:
                return await reject(403, "origin_not_allowed", "허용되지 않은 요청 출처입니다.")
        elif any(key.lower() == b"sec-fetch-site" and value.lower() == b"cross-site"
                 for key, value in headers):
            return await reject(403, "origin_required", "요청 출처를 확인하지 못했습니다.")

        for key, value in headers:
            if key.lower() == b"content-length":
                try:
                    declared = int(value)
                    if declared < 0:
                        raise ValueError
                except ValueError:
                    return await reject(400, "invalid_length", "요청 길이가 올바르지 않습니다.")
                if declared > MAX_REQUEST_BYTES:
                    return await reject(413, "request_too_large", "검사 요청이 너무 큽니다.")

        body = bytearray()
        more = True
        while more:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            if message["type"] != "http.request":
                return await reject(400, "invalid_request", "요청 형식이 올바르지 않습니다.")
            chunk = message.get("body", b"")
            if len(body) + len(chunk) > MAX_REQUEST_BYTES:
                return await reject(413, "request_too_large", "검사 요청이 너무 큽니다.")
            body.extend(chunk)
            more = message.get("more_body", False)
        replayed = False

        async def bounded_receive():
            nonlocal replayed
            if not replayed:
                replayed = True
                return {"type": "http.request", "body": bytes(body), "more_body": False}
            return await receive()

        await self.app(scope, bounded_receive, private_send)


def create_public_app(*, threat_check: ThreatCheck | None = None,
                      allowed_origins: tuple[str, ...] | None = None, cloud_worker=None, brand_analyzer=None) -> FastAPI:
    check = threat_check or check_safe_browsing
    if allowed_origins is None:
        allowed_origins = tuple(value.strip() for value in
                                os.getenv("QR_GUARD_PUBLIC_ORIGINS", "").split(",") if value.strip())
    allowed_origins = tuple(configured_origin(value) for value in allowed_origins)
    application = FastAPI(title="QR Guard Public API", version="0.4.0",
                          docs_url=None, redoc_url=None, openapi_url=None)
    if allowed_origins:
        application.add_middleware(CORSMiddleware, allow_origins=list(allowed_origins),
                                   allow_methods=["GET", "POST"], allow_headers=["Content-Type"],
                                   allow_credentials=False)
    application.add_middleware(PublicBoundaryMiddleware, allowed_origins=allowed_origins)

    def current_worker():
        return cloud_worker if cloud_worker is not None else configured_cloud_worker()

    def current_brand_analyzer():
        return brand_analyzer if brand_analyzer is not None else configured_brand_analyzer()

    @application.exception_handler(RequestValidationError)
    async def validation_error(_request, exc):
        # Default validation includes rejected input. Never echo URLs or credentials.
        return JSONResponse(status_code=422, content={"detail": [
            # An unknown JSON key is itself user input, so omit it from loc too.
            {"loc": ["body"], "msg": "Invalid request value", "type": error["type"]}
            for error in exc.errors()
        ]})

    @application.get("/api/health")
    async def health():
        return {"status": "ok", **capabilities(current_worker(), current_brand_analyzer())}

    @application.get("/api/capabilities")
    async def get_capabilities():
        return capabilities(current_worker(), current_brand_analyzer())

    @application.post("/api/analyze")
    async def analyze(request: PublicScanRequest):
        deadline = asyncio.get_running_loop().time() + ANALYSIS_TIMEOUT_SECONDS
        scan_id = uuid4().hex
        worker = current_worker()
        cloud_enabled = bool(worker.enabled)
        static, evidence = await _static_lookup(request.url, check, LOOKUP_TIMEOUT_SECONDS)
        provider = static.providers[0] if static.providers else None
        matched = provider is not None and provider.status == "checked" and provider.matched is True
        checked = provider is not None and provider.status == "checked" and provider.matched is False
        if matched:
            verdict = VerdictResult(
                level="malicious", reasons=["Google Safe Browsing에서 알려진 위협이 발견되었습니다."],
                evidence_ids=[item.id for item in evidence if item.kind == "known_threat_match"],
                limitations=[SCOPE_NOTICE, WORKER_NOTICE],
            )
        elif checked:
            verdict = VerdictResult(
                level="unknown", reasons=["알려진 위협 목록에서는 발견되지 않았지만 사이트 화면과 동작을 검사하지 않아 판단을 보류했습니다."],
                limitations=[SCOPE_NOTICE, WORKER_NOTICE, "검사 결과는 안전을 보증하지 않습니다."],
            )
        else:
            verdict = VerdictResult(
                level="unknown", reasons=["필요한 위협 정보 또는 브랜드 사칭 여부를 확인하지 못했습니다."],
                limitations=[SCOPE_NOTICE, WORKER_NOTICE, "조회 실패와 미확인은 안전을 뜻하지 않습니다."],
            )
        sandbox = SandboxResult(status="not_requested", skip_reason="static_only",
                                screenshot=ScreenshotState(status="not_requested"),
                                limitations=[SCOPE_NOTICE, WORKER_NOTICE])
        png = None
        if cloud_enabled and matched:
            sandbox = SandboxResult(status="skipped", skip_reason="known_malicious",
                                    screenshot=ScreenshotState(status="skipped"),
                                    limitations=["알려진 위협 주소이므로 격리 브라우저에서도 방문하지 않았습니다."])
            verdict.limitations = list(sandbox.limitations)
        elif cloud_enabled:
            sandbox, verdict, cloud_evidence, png = await _cloud_report(worker, scan_id, request.url, check, deadline)
            evidence.extend(cloud_evidence)
        brand_result, verdict = await _brand_report(current_brand_analyzer(), scan_id, sandbox, verdict,
                                                    png, evidence, deadline)
        report = ScanReport(
            scan_id=scan_id, status="completed", mode="sandbox" if cloud_enabled else "static", requested_url=request.url,
            static_analysis=static, evidence=evidence, verdict=verdict, updated_at=datetime.now(timezone.utc),
            sandbox_analysis=sandbox,
        ).model_dump(mode="json", by_alias=True)
        # No shared report database exists in the public deployment. Missing
        # statistics are unknown, not a fabricated zero or a successful receipt.
        report.update(reportCount=None, isReported=None, reportedByUser=None,
                      previewAvailable=bool(png), reportAvailable=False,
                      analysisScope="sandbox" if cloud_enabled else "static", brandAnalysis=brand_result)
        if png is not None:
            report["previewImage"] = {"scanId": scan_id, "mimeType": "image/png", "base64": base64.b64encode(png).decode("ascii")}
        return report

    @application.post("/api/scans/{scan_id}/reports")
    async def reports_unavailable(scan_id: str):
        return JSONResponse(status_code=503, content={
            "error": {"code": "reports_unavailable", "message": REPORT_NOTICE},
            "reportAvailable": False,
        })

    return application


app = create_public_app()
