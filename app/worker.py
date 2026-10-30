"""Internal C adapter. It never opens a target itself and fails closed by default.

An allowlist here is not an egress firewall. Enable only after C's actual
network isolation has been independently checked for the controlled demo.
"""

import asyncio
import base64
import binascii
from io import BytesIO
import warnings
import re
from datetime import datetime
from typing import Awaitable, Callable, Literal

import httpx
from PIL import Image
from pydantic import Field, PrivateAttr, StrictStr, ValidationError

from app.config import Settings, configured_origin, origin
from app.models import WireModel, DomAnalysis, NetworkAnalysis, RedirectAnalysis, LogoAnalysis, DomainAnalysis
from app.precheck.payload import normalize

MAX_PNG_BYTES = 4 * 1024 * 1024
MAX_RESPONSE_BYTES = 6 * 1024 * 1024


class WorkerError(Exception):
    def __init__(self, code: str, blocked: bool = False):
        self.code = code
        self.blocked = blocked
        super().__init__(code)


def public_limitations(items: list[str]) -> list[str]:
    """Retain bounded reason categories, never arbitrary Worker text or URL tokens."""
    messages = []
    for item in items[:10]:
        text = item[:1000].casefold()
        if "captcha" in text:
            message = "CAPTCHA로 필요한 페이지 관찰이 제한되었습니다."
        elif "dom" in text or "render" in text:
            message = "DOM 렌더링 관찰이 불완전합니다."
        elif "timeout" in text:
            message = "시간 제한으로 페이지 관찰이 제한되었습니다."
        elif "redirect" in text or "navigation" in text:
            message = "페이지 이동 관찰에 제한이 있습니다."
        else:
            message = "Worker가 추가 검사 범위 제한을 보고했습니다."
        if message not in messages:
            messages.append(message)
    return messages


def decode_png(encoded: str) -> bytes:
    try:
        if len(encoded) > ((MAX_PNG_BYTES + 2) // 3) * 4:
            raise ValueError("image too large")
        data = base64.b64decode(encoded, validate=True)
        if len(data) > MAX_PNG_BYTES:
            raise ValueError("image too large")
        with warnings.catch_warnings():
            warnings.simplefilter("error", Image.DecompressionBombWarning)
            with Image.open(BytesIO(data)) as image:
                if image.format != "PNG" or image.width * image.height > 16_000_000:
                    raise ValueError("not a bounded PNG")
                image.verify()
            # verify() only checks chunk structure/CRCs, not compressed pixel data.
            with Image.open(BytesIO(data)) as image:
                image.load()
        return data
    except (ValueError, OSError, SyntaxError, binascii.Error,
            Image.DecompressionBombError, Image.DecompressionBombWarning) as exc:
        raise WorkerError("invalid_screenshot") from exc


class JobAccepted(WireModel):
    scan_id: StrictStr
    status: Literal['queued', 'running', 'completed', 'failed']
    accepted_at: datetime


class WorkerJob(JobAccepted):
    # Transient transport-only destination: excluded from model dumps and public reports.
    _lookup_url: str | None = PrivateAttr(default=None)
    final_url: StrictStr | None = Field(default=None, max_length=4096)
    http_status: int | None = Field(default=None, strict=True, ge=100, le=599)
    screenshot_status: Literal['pending', 'ready', 'failed']
    screenshot_ref: StrictStr | None = Field(default=None, max_length=200)
    captured_at: datetime | None = None
    dom_analysis: DomAnalysis | None = None
    network_analysis: NetworkAnalysis | None = None
    redirect_analysis: RedirectAnalysis | None = None
    logo_analysis: LogoAnalysis | None = None
    domain_analysis: DomainAnalysis | None = None
    signals: list[dict] = Field(default_factory=list, max_length=100)
    evidence: list[dict] = Field(default_factory=list, max_length=101)
    limitations: list[StrictStr] = Field(default_factory=list, max_length=100)
    error_code: StrictStr | None = Field(default=None, max_length=100)


def safe_url(value: str | None) -> str | None:
    if value is None:
        return None
    from urllib.parse import urlsplit, urlunsplit
    parts = urlsplit(normalize(value))
    if parts.username is not None or parts.password is not None:
        raise ValueError('embedded credentials')
    segments = parts.path.split('/')
    for i, segment in enumerate(segments):
        if (i and re.match(r'^(token|auth|session|password|secret|key|code|reset|verify)$', segments[i-1], re.I)) or len(segment) > 64:
            segments[i] = '[redacted]'
    return urlunsplit((parts.scheme, parts.netloc, '/'.join(segments), '', ''))


class WorkerClient:
    def __init__(self, settings: Settings, transport: httpx.AsyncBaseTransport | None = None):
        self.settings = settings
        self.transport = transport
        self.allowed = {configured_origin(value) for value in settings.demo_origins}

    async def analyze(self, scan_id: str, url: str, *,
                      on_progress: Callable[[WorkerJob, bytes], Awaitable[None]] | None = None
                      ) -> tuple[WorkerJob, bytes | None]:
        settings = self.settings
        if not settings.worker_url:
            raise WorkerError("worker_not_configured", blocked=True)
        if not settings.worker_egress_verified:
            raise WorkerError("worker_egress_unverified", blocked=True)
        try:
            allowed = origin(url) in self.allowed
        except ValueError:
            allowed = False
        if not allowed:
            raise WorkerError("target_not_allowed", blocked=True)
        if not re.fullmatch(r'[A-Za-z0-9_-]{1,64}', scan_id):
            raise WorkerError('invalid_scan_id')
        base = configured_origin(settings.worker_url)

        async def read(client, method, path, *, image=False, payload=None, accepted=(200,)):
            async with client.stream(method, base + path, json=payload) as response:
                if response.status_code in {403, 422}:
                    raise WorkerError('worker_blocked', blocked=True)
                if response.status_code not in accepted:
                    raise WorkerError('worker_http_error')
                limit = MAX_PNG_BYTES if image else MAX_RESPONSE_BYTES
                data = bytearray()
                async for chunk in response.aiter_bytes():
                    if len(data) + len(chunk) > limit:
                        raise WorkerError('invalid_screenshot' if image else 'worker_response_too_large')
                    data.extend(chunk)
                if image and response.headers.get('content-type', '').split(';')[0] != 'image/png':
                    raise WorkerError('invalid_screenshot')
                return bytes(data)

        def validate(job):
            if job.scan_id != scan_id:
                raise WorkerError('worker_job_mismatch')
            if job.dom_analysis and job.dom_analysis.page_title:
                title = re.sub(r'https?://\S+|www\.\S+', '[redacted]', job.dom_analysis.page_title, flags=re.I)
                title = re.sub(r'\b(?:token|secret|password|authorization|api[_-]?key|code)\s*[:=]\s*\S+', '[redacted]', title, flags=re.I)
                job.dom_analysis.page_title = re.sub(r'[\x00-\x1f\x7f]', ' ', title).strip()[:200] or None
            if job.final_url:
                if origin(job.final_url) not in self.allowed:
                    raise WorkerError('worker_destination_not_allowed', blocked=True)
                job._lookup_url = normalize(job.final_url)
                job.final_url = safe_url(job.final_url)
            if job.network_analysis:
                n = job.network_analysis
                if n.blocked_request_count > n.request_count:
                    raise WorkerError('worker_invalid_response')
                for host in n.request_hosts:
                    if len(host) > 255 or not re.fullmatch(r'[A-Za-z0-9._:\[\]-]+', host):
                        raise WorkerError('worker_invalid_response')
                n.request_hosts = sorted(set(n.request_hosts))
            if job.redirect_analysis:
                r = job.redirect_analysis
                if r.final_url is not None and normalize(r.final_url) != job._lookup_url:
                    raise WorkerError('worker_navigation_incomplete')
                r.final_url = safe_url(r.final_url)
                if r.final_url != job.final_url:
                    raise WorkerError('worker_navigation_incomplete')
                for edge in r.redirect_chain:
                    edge.from_url = safe_url(edge.from_url)
                    edge.to = safe_url(edge.to)
            if job.status == 'completed' and (not job.final_url or job.http_status is None or job.http_status >= 400):
                raise WorkerError('worker_navigation_incomplete')
            return job

        try:
            # Do not inherit HTTP proxy settings or follow redirects from the internal service.
            async with asyncio.timeout(settings.worker_timeout_ms / 1000 + 2):
                async with httpx.AsyncClient(
                    transport=self.transport, trust_env=False, follow_redirects=False,
                    timeout=settings.worker_timeout_ms / 1000 + 1,
                ) as client:
                    body = await read(client, 'POST', '/internal/jobs', payload={
                        'scanId': scan_id, 'url': normalize(url), 'timeoutMs': settings.worker_timeout_ms}, accepted=(200, 202))
                    accepted = JobAccepted.model_validate_json(body)
                    if accepted.scan_id != scan_id:
                        raise WorkerError('worker_job_mismatch')
                    png = None
                    blank = False
                    while True:
                        body = await read(client, 'GET', f'/internal/jobs/{scan_id}')
                        result = validate(WorkerJob.model_validate_json(body))
                        if result.screenshot_status == 'ready' and png is None:
                            if result.final_url is None:
                                raise WorkerError('worker_navigation_incomplete')
                            raw_png = await read(client, 'GET', f'/internal/jobs/{scan_id}/screenshot', image=True)
                            png = decode_png(base64.b64encode(raw_png).decode('ascii'))
                            with Image.open(BytesIO(png)) as image:
                                blank = all(low == high for low, high in image.convert('RGB').getextrema())
                            if blank:
                                result.limitations.append('Blank screenshot; visual inspection incomplete.')
                            if on_progress:
                                await on_progress(result, png)
                        if result.status in {'completed', 'failed'}:
                            if blank and 'Blank screenshot; visual inspection incomplete.' not in result.limitations:
                                result.limitations.append('Blank screenshot; visual inspection incomplete.')
                            return result, png
                        await asyncio.sleep(settings.worker_poll_interval_ms / 1000)
        except (httpx.TimeoutException, TimeoutError) as exc:
            raise WorkerError("worker_timeout") from exc
        except httpx.HTTPError as exc:
            raise WorkerError("worker_unreachable") from exc
        except (ValidationError, ValueError) as exc:
            raise WorkerError("worker_invalid_response") from exc
