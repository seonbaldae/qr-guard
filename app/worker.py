"""Internal C adapter. It never opens a target itself and fails closed by default.

An allowlist here is not an egress firewall. Enable only after C's actual
network isolation has been independently checked for the controlled demo.
"""

import asyncio
import base64
import binascii
from io import BytesIO
import warnings

import httpx
from PIL import Image
from pydantic import Field, StrictBool, StrictStr, ValidationError

from app.config import Settings, configured_origin, origin
from app.models import WireModel
from app.precheck.payload import normalize

MAX_PNG_BYTES = 4 * 1024 * 1024
MAX_RESPONSE_BYTES = 6 * 1024 * 1024


class WorkerError(Exception):
    def __init__(self, code: str, blocked: bool = False):
        self.code = code
        self.blocked = blocked
        super().__init__(code)


class WorkerForm(WireModel):
    method: StrictStr = Field(max_length=16)
    action_host: StrictStr | None = Field(default=None, max_length=255, pattern=r"^[A-Za-z0-9._:\-]+$")


class WorkerResult(WireModel):
    final_url: StrictStr | None
    http_status: int | None = Field(strict=True, ge=100, le=599)
    page_title: StrictStr | None = Field(max_length=2000)
    password_field_count: int = Field(strict=True, ge=0, le=10000)
    sensitive_field_types: list[StrictStr] = Field(max_length=100)
    forms: list[WorkerForm] = Field(max_length=200)
    request_hosts: list[StrictStr] = Field(max_length=200)
    redirected: StrictBool
    screenshot_base64: StrictStr = Field(max_length=MAX_RESPONSE_BYTES)
    limitations: list[StrictStr] = Field(max_length=100)


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


class WorkerClient:
    def __init__(self, settings: Settings, transport: httpx.AsyncBaseTransport | None = None):
        self.settings = settings
        self.transport = transport
        self.allowed = {configured_origin(value) for value in settings.demo_origins}

    async def analyze(self, scan_id: str, url: str) -> tuple[WorkerResult, bytes]:
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
        try:
            # Do not inherit HTTP proxy settings or follow redirects from the internal service.
            async with asyncio.timeout(settings.worker_timeout_ms / 1000 + 2):
                async with httpx.AsyncClient(
                    transport=self.transport, trust_env=False, follow_redirects=False,
                    timeout=settings.worker_timeout_ms / 1000 + 1,
                ) as client:
                    async with client.stream(
                        "POST", configured_origin(settings.worker_url) + "/internal/analyze",
                        json={"scanId": scan_id, "url": normalize(url), "timeoutMs": settings.worker_timeout_ms},
                    ) as response:
                        if response.status_code == 403:
                            raise WorkerError("worker_blocked", blocked=True)
                        if response.status_code != 200:
                            raise WorkerError("worker_http_error")
                        body = bytearray()
                        async for chunk in response.aiter_bytes():
                            body.extend(chunk)
                            if len(body) > MAX_RESPONSE_BYTES:
                                raise WorkerError("worker_response_too_large")
            result = WorkerResult.model_validate_json(body)
            if result.final_url is None or result.http_status is None:
                raise WorkerError("worker_navigation_incomplete")
            if origin(result.final_url) not in self.allowed:
                raise WorkerError("worker_destination_not_allowed", blocked=True)
            if result.http_status >= 400:
                raise WorkerError("worker_navigation_failed")
            result.limitations = public_limitations(result.limitations)
            return result, decode_png(result.screenshot_base64)
        except (httpx.TimeoutException, TimeoutError) as exc:
            raise WorkerError("worker_timeout") from exc
        except httpx.HTTPError as exc:
            raise WorkerError("worker_unreachable") from exc
        except (ValidationError, ValueError) as exc:
            raise WorkerError("worker_invalid_response") from exc
