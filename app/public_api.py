"""Stateless public API for the mobile deployment while Worker is maintained.

One request completes its own static lookup. No job, screenshot, or report state
is kept in a serverless instance. The separate local Docker integration remains
in app.main and is deliberately not imported here.
"""

import asyncio
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
from app.models import (
    ProviderResult, SandboxResult, ScanReport, ScanRequest, ScreenshotState,
    StaticAnalysisResult, VerdictResult,
)
from app.precheck.safebrowsing import check_safe_browsing
from app.static_adapter import ThreatCheck, analyze_static

MAX_REQUEST_BYTES = 16 * 1024
LOOKUP_TIMEOUT_SECONDS = 12
SCOPE_NOTICE = "현재는 주소만 검사하며 사이트 화면은 확인하지 않았습니다."
WORKER_NOTICE = "Docker 미리보기는 점검 중입니다."
REPORT_NOTICE = "신고 접수는 준비 중입니다."


def capabilities():
    return {
        "scanTransport": "direct", "scanMode": "static", "analysisScope": "static",
        "previewAvailable": False, "reportAvailable": False,
    }


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
                      allowed_origins: tuple[str, ...] | None = None) -> FastAPI:
    check = threat_check or check_safe_browsing
    if allowed_origins is None:
        allowed_origins = tuple(value.strip() for value in
                                os.getenv("QR_GUARD_PUBLIC_ORIGINS", "").split(",") if value.strip())
    allowed_origins = tuple(configured_origin(value) for value in allowed_origins)
    application = FastAPI(title="QR Guard Public API", version="0.3.0",
                          docs_url=None, redoc_url=None, openapi_url=None)
    if allowed_origins:
        application.add_middleware(CORSMiddleware, allow_origins=list(allowed_origins),
                                   allow_methods=["GET", "POST"], allow_headers=["Content-Type"],
                                   allow_credentials=False)
    application.add_middleware(PublicBoundaryMiddleware, allowed_origins=allowed_origins)

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
        return {"status": "ok", **capabilities()}

    @application.get("/api/capabilities")
    async def get_capabilities():
        return capabilities()

    @application.post("/api/analyze")
    async def analyze(request: PublicScanRequest):
        try:
            async with asyncio.timeout(LOOKUP_TIMEOUT_SECONDS):
                static, evidence = await asyncio.to_thread(analyze_static, request.url, check)
        except Exception:
            # Exceptions from transports may contain API keys or URL tokens.
            static = StaticAnalysisResult(status="failed", registered_domain=None, providers=[
                ProviderResult(name="google_safe_browsing", status="failed", matched=None, checked_at=None),
            ], limitations=["위협 정보 조회를 완료하지 못했습니다."])
            evidence = []
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
        report = ScanReport(
            scan_id=uuid4().hex, status="completed", mode="static", requested_url=request.url,
            static_analysis=static, evidence=evidence, verdict=verdict, updated_at=datetime.now(timezone.utc),
            sandbox_analysis=SandboxResult(status="not_requested", skip_reason="static_only",
                                           screenshot=ScreenshotState(status="not_requested"),
                                           limitations=[SCOPE_NOTICE, WORKER_NOTICE]),
        ).model_dump(mode="json", by_alias=True)
        # No shared report database exists in the public deployment. Missing
        # statistics are unknown, not a fabricated zero or a successful receipt.
        report.update(reportCount=None, isReported=None, reportedByUser=None,
                      previewAvailable=False, reportAvailable=False, analysisScope="static")
        return report

    @application.post("/api/scans/{scan_id}/reports")
    async def reports_unavailable(scan_id: str):
        return JSONResponse(status_code=503, content={
            "error": {"code": "reports_unavailable", "message": REPORT_NOTICE},
            "reportAvailable": False,
        })

    return application


app = create_public_app()
