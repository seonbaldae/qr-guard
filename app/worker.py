"""Bounded jobs/PNG adapter. Only the separately isolated Worker visits targets.

The container transport uses Docker exec solely to reach the Worker's loopback
HTTP server while its network stays disabled. It never accepts a command or a
network destination from a scan request.
"""

import asyncio
import base64
import binascii
import json
import os
import re
from io import BytesIO
from typing import Literal
import warnings
from datetime import datetime, timezone
from contextlib import asynccontextmanager
import ipaddress
from urllib.parse import urlsplit

import httpx
from PIL import Image
from pydantic import ConfigDict, Field, StrictBool, StrictStr, ValidationError

from app.config import Settings, configured_origin, origin
from app.models import Evidence, Signal, WireModel
from app.precheck.payload import normalize

MAX_PNG_BYTES = 4 * 1024 * 1024
MAX_RESPONSE_BYTES = 6 * 1024 * 1024
INTERNAL_PATH = re.compile(r"^/internal/jobs(?:/[A-Za-z0-9_-]{1,64}(?:/screenshot)?)?$")

# Constant code, fixed host/port, and bounded request/response bodies. No shell.
DOCKER_HTTP_CLIENT = r"""
const http = require('node:http');
let input = '';
process.stdin.on('data', chunk => {
  input += chunk;
  if (Buffer.byteLength(input) > 8192) process.exit(2);
});
process.stdin.on('end', () => {
  try {
    const data = JSON.parse(input);
    const get = data.method === 'GET' && /^\/internal\/(health|jobs\/[A-Za-z0-9_-]{1,64}(\/screenshot)?)$/.test(data.path);
    const post = data.method === 'POST' && data.path === '/internal/jobs';
    if (!get && !post) process.exit(2);
    const body = post ? Buffer.from(data.body, 'base64') : Buffer.alloc(0);
    const req = http.request({host:'127.0.0.1', port:4000, method:data.method, path:data.path,
      headers:post ? {'Content-Type':'application/json','Content-Length':body.length} : {}}, res => {
      const chunks = []; let size = 0;
      res.on('data', chunk => {
        size += chunk.length;
        if (size > 6 * 1024 * 1024) { res.destroy(); process.exit(3); }
        chunks.push(chunk);
      });
      res.on('end', () => process.stdout.write(JSON.stringify({status:res.statusCode,
        type:res.headers['content-type'] || '', body:Buffer.concat(chunks).toString('base64')})));
      res.on('error', () => process.exit(3));
    });
    req.setTimeout(10000, () => { req.destroy(); process.exit(4); });
    req.on('error', () => process.exit(3));
    req.end(body);
  } catch { process.exit(2); }
});
"""


class WorkerError(Exception):
    def __init__(self, code: str, blocked: bool = False):
        self.code = code
        self.blocked = blocked
        super().__init__(code)


class DockerWorkerTransport(httpx.AsyncBaseTransport):
    """Narrow, private HTTP bridge into a network=none Worker container."""

    def __init__(self, container: str):
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", container):
            raise ValueError("Invalid Worker container name")
        self.container = container

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        allowed = ((request.method == "POST" and path == "/internal/jobs") or
                   (request.method == "GET" and (path == "/internal/health" or
                    INTERNAL_PATH.fullmatch(path) and path != "/internal/jobs")))
        if not allowed or request.url.query or request.url.fragment:
            raise httpx.TransportError("Unsupported Worker request")
        body = await request.aread()
        if len(body) > 4096:
            raise httpx.TransportError("Worker request too large")
        payload = json.dumps({"method": request.method, "path": path,
                              "body": base64.b64encode(body).decode()}).encode()
        # The Google key and unrelated server credentials never enter this process.
        environment = {key: os.environ[key] for key in (
            "PATH", "HOME", "DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_CONFIG",
        ) if key in os.environ}
        process = None
        try:
            async with asyncio.timeout(15):
                process = await asyncio.create_subprocess_exec(
                    "docker", "exec", "-i", self.container, "node", "-e", DOCKER_HTTP_CLIENT,
                    stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.DEVNULL, env=environment,
                )
                process.stdin.write(payload)
                await process.stdin.drain()
                process.stdin.close()
                output = bytearray()
                while chunk := await process.stdout.read(65536):
                    output.extend(chunk)
                    if len(output) > ((MAX_RESPONSE_BYTES + 2) // 3) * 4 + 4096:
                        raise httpx.TransportError("Worker response too large")
                await process.wait()
                if process.returncode:
                    raise httpx.TransportError("Worker container unavailable")
            data = json.loads(output)
            status = data["status"]
            if type(status) is not int or not 100 <= status <= 599:
                raise ValueError
            content = base64.b64decode(data["body"], validate=True)
            if len(content) > MAX_RESPONSE_BYTES:
                raise ValueError
            content_type = data.get("type", "")
            if not isinstance(content_type, str) or len(content_type) > 200:
                raise ValueError
            return httpx.Response(status, headers={"content-type": content_type}, content=content)
        except TimeoutError as exc:
            raise httpx.ReadTimeout("Worker container timed out") from exc
        except (OSError, ValueError, KeyError, TypeError, binascii.Error) as exc:
            raise httpx.TransportError("Invalid Worker container response") from exc
        finally:
            if process is not None and process.returncode is None:
                try:
                    process.kill()
                except ProcessLookupError:
                    pass
                await process.wait()


class WorkerForm(WireModel):
    method: StrictStr = Field(max_length=16)
    action_host: StrictStr | None = Field(default=None, max_length=255, pattern=r"^[A-Za-z0-9._:\-]+$")


class WorkerDom(WireModel):
    page_title: StrictStr | None = Field(max_length=2000)
    password_field_count: int = Field(strict=True, ge=0, le=10000)
    sensitive_field_types: list[StrictStr] = Field(max_length=100)
    forms: list[WorkerForm] = Field(max_length=200)


class WorkerNetwork(WireModel):
    request_hosts: list[StrictStr] = Field(max_length=200)
    request_count: int = Field(strict=True, ge=0, le=100000)
    blocked_request_count: int = Field(strict=True, ge=0, le=100000)


class WorkerRedirect(WireModel):
    redirected: StrictBool
    final_url: StrictStr | None
    redirect_chain: list[dict] = Field(max_length=100)


class WorkerJob(WireModel):
    # Additive observation fields are not trusted public report objects.
    model_config = ConfigDict(alias_generator=WireModel.model_config['alias_generator'],
                              populate_by_name=True, extra="ignore")
    scan_id: StrictStr = Field(pattern=r"^[A-Za-z0-9_-]{1,64}$")
    status: Literal["queued", "running", "completed", "failed", "cancelled"]
    final_url: StrictStr | None = None
    http_status: int | None = Field(default=None, strict=True, ge=100, le=599)
    screenshot_status: Literal["pending", "ready", "failed", "cancelled"] = "pending"
    dom_analysis: WorkerDom | None = None
    network_analysis: WorkerNetwork | None = None
    redirect_analysis: WorkerRedirect | None = None
    limitations: list[StrictStr] = Field(default_factory=list, max_length=100)
    error_code: StrictStr | None = Field(default=None, max_length=100)


class WorkerResult(WorkerDom):
    password_field_count: int | None = Field(default=None, strict=True, ge=0, le=10000)
    final_url: StrictStr | None
    http_status: int | None = Field(strict=True, ge=100, le=599)
    request_hosts: list[StrictStr] = Field(max_length=200)
    redirected: StrictBool
    screenshot_base64: StrictStr = Field(max_length=MAX_RESPONSE_BYTES)
    limitations: list[StrictStr] = Field(max_length=100)
    inspection_complete: StrictBool = True
    evidence: list[Evidence] = Field(default_factory=list)
    signals: list[Signal] = Field(default_factory=list)


# These are ordinary scope limits, not failed observations. Any other limitation
# remains blocking until explicitly classified; unexpected messages fail closed.
SCOPE_LIMITATIONS = {
    "개발용 테스트 페이지 방문·캡처만 수행합니다.": "허가된 테스트 페이지에서만 격리 방문을 수행했습니다.",
    "악성 여부 판정과 고급 동적 분석은 수행하지 않았습니다.": "브라우저 관찰만으로 악성 여부를 확정하지 않습니다.",
    "초기 로딩과 짧은 관찰 구간만 검사했으며 사용자 상호작용은 수행하지 않았습니다.": "초기 로딩과 짧은 관찰 구간만 검사했으며 사용자 상호작용은 수행하지 않았습니다.",
    "Only accessible rendered DOM and open shadow roots are inspected; closed shadow roots are not observable.": "접근 가능한 DOM과 열린 Shadow DOM만 관찰했으며 닫힌 Shadow DOM은 확인하지 못했습니다.",
    "Official-domain comparison unavailable without a verified domain and resolver.": "브라우저는 공식 운영 주체를 인증하지 않았습니다.",
    "공개 웹 페이지를 읽기 전용으로 관찰했으며 로그인·입력·폼 제출은 수행하지 않았습니다.": "공개 웹 페이지를 읽기 전용으로 관찰했으며 로그인·입력·폼 제출은 수행하지 않았습니다.",
}


def public_target(url: str) -> bool:
    """Early URL checks only; the egress relay validates and pins every DNS answer."""
    try:
        parts = urlsplit(normalize(url))
        if parts.scheme not in {"http", "https"} or parts.username is not None or parts.password is not None:
            return False
        if parts.port not in {None, 80 if parts.scheme == "http" else 443}:
            return False
        host = (parts.hostname or "").lower().rstrip(".")
        if not host or host == "localhost" or host.endswith((".localhost", ".local", ".internal")):
            return False
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            return "." in host and re.fullmatch(r"[a-z0-9.-]+", host) is not None
        return address.version == 4 and address.is_global
    except ValueError:
        return False


@asynccontextmanager
async def no_public_tunnel():
    yield None


def public_limitations(items: list[str]) -> list[str]:
    """Keep bounded reason categories, never arbitrary Worker URL/token text."""
    messages = []
    for item in items[:100]:
        text = item[:1000].casefold()
        if item in SCOPE_LIMITATIONS:
            message = SCOPE_LIMITATIONS[item]
        elif "captcha" in text:
            message = "CAPTCHA로 필요한 페이지 관찰이 제한되었습니다."
        elif "dom" in text or "render" in text or "frame" in text or "field" in text:
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
            with Image.open(BytesIO(data)) as image:
                image.load()
        return data
    except (ValueError, OSError, SyntaxError, binascii.Error,
            Image.DecompressionBombError, Image.DecompressionBombWarning) as exc:
        raise WorkerError("invalid_screenshot") from exc


class WorkerClient:
    def __init__(self, settings: Settings, transport: httpx.AsyncBaseTransport | None = None):
        self.settings = settings
        self.transport = transport or (DockerWorkerTransport(settings.worker_container)
                                       if settings.worker_container else None)
        self.allowed = {configured_origin(value) for value in settings.demo_origins}

    async def _read(self, client, method, path, **kwargs):
        async with client.stream(method, path, **kwargs) as response:
            if response.status_code in {403, 422}:
                raise WorkerError("worker_blocked", blocked=True)
            if response.status_code not in ({200, 202} if method == "POST" else {200}):
                raise WorkerError("worker_http_error")
            body = bytearray()
            async for chunk in response.aiter_bytes():
                body.extend(chunk)
                if len(body) > MAX_RESPONSE_BYTES:
                    raise WorkerError("worker_response_too_large")
            return bytes(body), response.headers.get("content-type", "")

    async def analyze(self, scan_id: str, url: str) -> tuple[WorkerResult, bytes]:
        settings = self.settings
        if not settings.worker_url and not settings.worker_container:
            raise WorkerError("worker_not_configured", blocked=True)
        if not settings.worker_egress_verified:
            raise WorkerError("worker_egress_unverified", blocked=True)
        try:
            controlled = origin(url) in self.allowed
            use_public = not controlled and settings.public_preview and bool(settings.worker_container) and public_target(url)
            allowed = controlled or use_public
        except ValueError:
            allowed = False
        if not allowed:
            raise WorkerError("target_not_allowed", blocked=True)
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", scan_id):
            raise WorkerError("invalid_scan_id")
        try:
            if use_public:
                from app.egress_tunnel import PublicEgressTunnel
                tunnel_context = PublicEgressTunnel(settings.worker_container, timeout_seconds=settings.worker_timeout_ms / 1000 + 5)
            else:
                tunnel_context = no_public_tunnel()
            async with tunnel_context as tunnel:
                result, png = await self._analyze_job(scan_id, url, use_public)
                if tunnel is not None and tunnel.blocked_count:
                    result.inspection_complete = False
                    result.limitations.append("네트워크 정책으로 차단된 요청이 있어 페이지 관찰이 불완전합니다.")
                return result, png
        except (httpx.TimeoutException, TimeoutError) as exc:
            raise WorkerError("worker_timeout") from exc
        except httpx.HTTPError as exc:
            raise WorkerError("worker_unreachable") from exc
        except OSError as exc:
            raise WorkerError("worker_unreachable") from exc
        except (ValidationError, ValueError, TypeError, AttributeError) as exc:
            raise WorkerError("worker_invalid_response") from exc

    async def _analyze_job(self, scan_id: str, url: str, use_public: bool):
        settings = self.settings
        try:
            async with asyncio.timeout(settings.worker_timeout_ms / 1000 + 5):
                async with httpx.AsyncClient(
                    transport=self.transport, trust_env=False, follow_redirects=False,
                    base_url=configured_origin(settings.worker_url) if settings.worker_url else "http://worker.internal",
                    timeout=settings.worker_timeout_ms / 1000 + 1,
                ) as client:
                    body, _ = await self._read(client, "POST", "/internal/jobs", json={
                        "scanId": scan_id, "url": normalize(url), "timeoutMs": settings.worker_timeout_ms,
                    })
                    accepted = json.loads(body)
                    if accepted.get("scanId") != scan_id or accepted.get("status") not in {
                        "queued", "running", "completed", "failed", "cancelled",
                    }:
                        raise WorkerError("worker_invalid_response")
                    while True:
                        body, _ = await self._read(client, "GET", f"/internal/jobs/{scan_id}")
                        job = WorkerJob.model_validate_json(body)
                        if job.scan_id != scan_id:
                            raise WorkerError("worker_scan_mismatch")
                        if job.status not in {"queued", "running"}:
                            break
                        await asyncio.sleep(0.25)
                    if job.status != "completed":
                        raise WorkerError("worker_job_failed")
                    if job.final_url is None or job.http_status is None:
                        raise WorkerError("worker_navigation_incomplete")
                    if not (public_target(job.final_url) if use_public else origin(job.final_url) in self.allowed):
                        raise WorkerError("worker_destination_not_allowed", blocked=True)
                    if job.http_status >= 400:
                        raise WorkerError("worker_navigation_failed")
                    if job.screenshot_status != "ready":
                        raise WorkerError("worker_screenshot_unavailable")
                    png, media_type = await self._read(client, "GET", f"/internal/jobs/{scan_id}/screenshot")
                    if media_type.split(";", 1)[0].strip().lower() != "image/png":
                        raise WorkerError("invalid_screenshot")
            png = decode_png(base64.b64encode(png).decode())
            incomplete = any(item not in SCOPE_LIMITATIONS for item in job.limitations)
            dom = job.dom_analysis
            if dom is None:
                # Preserve the screenshot without claiming an observed zero.
                limitations = [*job.limitations, "DOM inspection incomplete."]
            else:
                limitations = job.limitations
            complete = dom is not None and job.network_analysis is not None and job.redirect_analysis is not None and not incomplete
            if job.network_analysis and job.network_analysis.blocked_request_count:
                complete = False
                limitations = [*limitations, "Network policy blocked requests; inspection incomplete."]
            evidence = []
            signals = []
            def observed(kind, summary, data):
                key = f"{scan_id}-{kind}"
                evidence.append(Evidence(id=key, kind=kind, source="browser", observed_at=datetime.now(timezone.utc), summary=summary, data=data))
                signals.append(Signal(id=f"{key}-signal", kind=kind, severity="info", source="browser", summary=summary, evidence_ids=[key]))
            observed("navigation", "격리 브라우저에서 페이지 응답을 확인했습니다.", {"httpStatus": job.http_status})
            if dom:
                observed("dom_observation", "입력값을 읽거나 제출하지 않고 폼과 필드를 관찰했습니다.",
                         {"passwordFieldCount": dom.password_field_count, "formCount": len(dom.forms)})
                for i, form in enumerate(dom.forms):
                    observed(f"form_observation_{i}", "폼에 지정된 제출 대상과 메서드를 관찰했습니다. 제출은 수행하지 않았습니다.",
                             {"method": form.method, "actionHost": form.action_host})
            if job.network_analysis:
                network = job.network_analysis
                observed("network_observation", "브라우저 요청 수와 정책으로 차단된 요청 수를 관찰했습니다.",
                         {"requestCount": network.request_count, "blockedRequestCount": network.blocked_request_count,
                          "hostCount": len(network.request_hosts)})
            if job.redirect_analysis:
                redirect = job.redirect_analysis
                observed("redirect_observation", "실제로 완료된 페이지 이동과 이동 시도를 구분해 관찰했습니다.",
                         {"redirected": redirect.redirected, "redirectCount": len(redirect.redirect_chain)})
            result = WorkerResult(
                final_url=job.final_url, http_status=job.http_status,
                page_title=dom.page_title if dom else None,
                password_field_count=dom.password_field_count if dom else None,
                sensitive_field_types=dom.sensitive_field_types if dom else [], forms=dom.forms if dom else [],
                request_hosts=job.network_analysis.request_hosts if job.network_analysis else [],
                redirected=job.redirect_analysis.redirected if job.redirect_analysis else False,
                screenshot_base64="", limitations=public_limitations(limitations),
                inspection_complete=complete, evidence=evidence, signals=signals,
            )
            return result, png
        except (httpx.TimeoutException, TimeoutError) as exc:
            raise WorkerError("worker_timeout") from exc
        except httpx.HTTPError as exc:
            raise WorkerError("worker_unreachable") from exc
        except (ValidationError, ValueError, TypeError, AttributeError) as exc:
            raise WorkerError("worker_invalid_response") from exc
