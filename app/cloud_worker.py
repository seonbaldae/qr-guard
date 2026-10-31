"""Per-request, disposable cloud execution of the pinned browser Worker image.

This module deliberately does not import the development Docker Worker client.
Vercel's SDK resolves its own OIDC identity; credentials are never sent to the VM.
"""

from __future__ import annotations

import asyncio
import io
import ipaddress
import json
import re
import socket
import unicodedata
import warnings
from collections.abc import Awaitable, Callable
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Annotated, Any, Literal
from urllib.parse import urlsplit, urlunsplit

from PIL import Image
from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictStr, ValidationError
from pydantic.alias_generators import to_camel

MAX_RESULT_BYTES = 256 * 1024
MAX_PNG_BYTES = 1536 * 1024
MAX_PIXELS = 16_000_000
CLEANUP_OPERATION_TIMEOUT_SECONDS = 5
INPUT_PATH = "/tmp/qr-input.json"
RESULT_PATH = "/tmp/qr-result.json"
SCREENSHOT_PATH = "/tmp/qr-shot.png"
DENIED_SUBNETS = (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
    "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
    "192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24",
    "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4", "168.63.129.16/32",
)
# Vercel's custom subnet policy currently accepts IPv4 CIDRs only. Before the
# untrusted page runs, disable IPv6 in the VM kernel and verify every interface.
IPV6_SYSCTL_ARGS = ["-w", "net.ipv6.conf.all.disable_ipv6=1", "net.ipv6.conf.default.disable_ipv6=1",
                    "net.ipv6.conf.lo.disable_ipv6=1"]
VERIFY_IPV6_DISABLED = """const fs = require('node:fs');
try {
  const root = '/proc/sys/net/ipv6/conf';
  const entries = fs.readdirSync(root);
  if (!['all', 'default', 'lo'].every(name => entries.includes(name))) process.exit(1);
  for (const name of entries) {
    if (fs.readFileSync(root + '/' + name + '/disable_ipv6', 'utf8').trim() !== '1') process.exit(1);
  }
  if (fs.readFileSync('/proc/net/if_inet6', 'utf8').trim()) process.exit(1);
} catch { process.exit(1); }
"""
_DENIED_NETWORKS = tuple(ipaddress.ip_network(item) for item in DENIED_SUBNETS)
_IMAGE = re.compile(r"^(?:vcr\.vercel\.com/)?[a-z0-9][a-z0-9._-]*(?:/[a-z0-9][a-z0-9._-]*){0,2}@sha256:[0-9a-f]{64}$")
_SNAPSHOT = re.compile(r"^snap_[A-Za-z0-9_-]{1,128}$")
_SCAN_ID = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
_HOST = re.compile(r"^[A-Za-z0-9._:\[\]-]{1,255}$")
_SAFE_ERRORS = {"unsafe_target", "worker_policy_blocked", "worker_timeout", "worker_unreachable", "worker_invalid_response", "invalid_screenshot"}
BoundedText = Annotated[StrictStr, Field(max_length=1000)]
HostText = Annotated[StrictStr, Field(max_length=255, pattern=_HOST.pattern)]
UrlText = Annotated[StrictStr, Field(max_length=2048)]
RUNNER_ENV = {"NODE_PATH": "/opt/qr-deps/node_modules", "NODE_OPTIONS": "--max-old-space-size=512",
              "PLAYWRIGHT_BROWSERS_PATH": "/ms-playwright"}


class CloudWorkerError(Exception):
    """A fixed public code, never a remote error message or process output."""

    def __init__(self, code: str, *, blocked: bool = False):
        self.code = code
        self.blocked = blocked
        super().__init__(code)


class _WireModel(BaseModel):
    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True, extra="ignore")


class CloudForm(_WireModel):
    method: StrictStr = Field(max_length=16)
    action_host: HostText | None = None


class CloudDom(_WireModel):
    page_title: StrictStr | None = Field(default=None, max_length=2000)
    password_field_count: int = Field(strict=True, ge=0, le=10000)
    sensitive_field_types: list[Annotated[StrictStr, Field(max_length=100)]] = Field(max_length=100)
    forms: list[CloudForm] = Field(max_length=200)


class CloudNetwork(_WireModel):
    request_hosts: list[HostText] = Field(max_length=200)
    request_count: int = Field(strict=True, ge=0, le=100000)
    blocked_request_count: int = Field(strict=True, ge=0, le=100000)


class CloudRedirectEdge(_WireModel):
    from_url: UrlText = Field(alias="from")
    to: UrlText
    status_code: int | None = Field(default=None, strict=True, ge=100, le=599)
    type: Literal["http", "client_navigation", "unknown"]
    blocked: StrictBool


class CloudRedirect(_WireModel):
    redirected: StrictBool
    final_url: UrlText | None
    redirect_chain: list[CloudRedirectEdge] = Field(max_length=100)


class CloudBrowserResult(_WireModel):
    scan_id: StrictStr = Field(pattern=_SCAN_ID.pattern)
    status: Literal["completed", "failed"]
    final_url: UrlText | None = None
    http_status: int | None = Field(default=None, strict=True, ge=100, le=599)
    screenshot_status: Literal["ready", "failed", "cancelled", "pending"] = "failed"
    dom_analysis: CloudDom | None = None
    network_analysis: CloudNetwork | None = None
    redirect_analysis: CloudRedirect | None = None
    limitations: list[BoundedText] = Field(default_factory=list, max_length=100)
    error_code: StrictStr | None = Field(default=None, max_length=100)
    inspection_complete: StrictBool = False
    captured_at: datetime | None = None


def _public_ipv4(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return isinstance(address, ipaddress.IPv4Address) and address.is_global and not any(
        address in network for network in _DENIED_NETWORKS if network.version == 4
    )


def _public_url(value: str) -> tuple[str, str, int]:
    """Reject ambiguous authority syntax before DNS or VM creation."""
    try:
        if not isinstance(value, str) or not 1 <= len(value) <= 2048:
            raise ValueError
        if any(char.isspace() or unicodedata.category(char).startswith("C") for char in value) or "\\" in value:
            raise ValueError
        parts = urlsplit(value)
        if parts.scheme not in {"http", "https"} or not parts.netloc or "@" in parts.netloc:
            raise ValueError
        host = parts.hostname
        if not host or parts.username is not None or parts.password is not None:
            raise ValueError
        host = host.rstrip(".").encode("idna").decode("ascii").lower()
        port = parts.port or (443 if parts.scheme == "https" else 80)
        if port != (443 if parts.scheme == "https" else 80):
            raise ValueError
        try:
            ipaddress.ip_address(host)
        except ValueError:
            if (len(host) > 253 or "." not in host or not _HOST.fullmatch(host)
                    or host.endswith((".localhost", ".local", ".internal", ".lan", ".home"))
                    or any(not label or len(label) > 63 or label.startswith("-") or label.endswith("-") for label in host.split("."))):
                raise ValueError
            # WHATWG browsers normalize shortened/octal/hex numeric IPv4 hosts.
            if re.fullmatch(r"(?:0x[0-9a-f]+|[0-9]+)(?:\.(?:0x[0-9a-f]+|[0-9]+))*", host):
                raise ValueError
        else:
            if not _public_ipv4(host):
                raise ValueError
        normalized = urlunsplit((parts.scheme, host, parts.path or "/", parts.query, parts.fragment))
        return normalized, host, port
    except (ValueError, UnicodeError):
        raise CloudWorkerError("unsafe_target", blocked=True) from None


async def _resolve(host: str, port: int) -> list[str]:
    results = await asyncio.get_running_loop().getaddrinfo(host, port, type=socket.SOCK_STREAM)
    return list({result[4][0] for result in results})


def _decode_png(data: bytes) -> bytes:
    try:
        if not data or len(data) > MAX_PNG_BYTES or not data.startswith(b"\x89PNG\r\n\x1a\n"):
            raise ValueError
        with warnings.catch_warnings():
            warnings.simplefilter("error", Image.DecompressionBombWarning)
            with Image.open(io.BytesIO(data)) as image:
                if image.format != "PNG" or image.width * image.height > MAX_PIXELS or getattr(image, "n_frames", 1) != 1:
                    raise ValueError
                image.verify()
            with Image.open(io.BytesIO(data)) as image:
                image.load()
        return data
    except (ValueError, OSError, SyntaxError, Image.DecompressionBombError, Image.DecompressionBombWarning):
        raise CloudWorkerError("invalid_screenshot") from None


async def _read_bounded(fs: Any, path: str, maximum: int) -> bytes:
    async with fs.open(path, "rb") as reader:
        data = await reader.read(maximum + 1)
    if not isinstance(data, bytes) or len(data) > maximum:
        raise CloudWorkerError("invalid_screenshot" if path == SCREENSHOT_PATH else "worker_invalid_response")
    return data


async def _disable_ipv6(box: Any) -> None:
    try:
        applied = await box.run_process("sysctl", IPV6_SYSCTL_ARGS, sudo=True,
                                        kill_after=5, capture_output=True, check=True)
        if applied.returncode != 0:
            raise ValueError
        verified = await box.run_process("node", ["-e", VERIFY_IPV6_DISABLED],
                                         kill_after=3, capture_output=True, check=True)
        if verified.returncode != 0:
            raise ValueError
    except Exception:
        # A missing kernel control or unavailable sudo must never fall through
        # to visiting the page with a partially applied network policy.
        raise CloudWorkerError("worker_policy_blocked", blocked=True) from None


def _discard_cleanup_exception(task: asyncio.Task) -> None:
    # A timed-out SDK operation is cancelled and may finish asynchronously.
    # Consume its exception without ever printing URLs or authentication data.
    if not task.cancelled():
        task.exception()


async def _cleanup_sandbox(box: Any, *, delete_orphan_snapshots: bool = True) -> None:
    failed = False
    # Bound the operations separately so a stalled stop never prevents a destroy
    # attempt. These are the same public SDK calls used by its context manager.
    for operation in (box.stop, lambda: box.destroy(delete_orphan_snapshots=delete_orphan_snapshots)):
        task = None
        try:
            task = asyncio.create_task(operation())
            done, _ = await asyncio.wait({task}, timeout=CLEANUP_OPERATION_TIMEOUT_SECONDS)
            if not done:
                failed = True
                task.cancel()
                task.add_done_callback(_discard_cleanup_exception)
                continue
            task.result()
        except (Exception, asyncio.CancelledError):
            failed = True
    if failed:
        raise CloudWorkerError("worker_unreachable")


async def _finish_cleanup(box: Any, *, delete_orphan_snapshots: bool = True) -> None:
    # Shield only the independently bounded cleanup, never browser execution.
    cleanup = asyncio.create_task(_cleanup_sandbox(box, delete_orphan_snapshots=delete_orphan_snapshots))
    cancellation = None
    while not cleanup.done():
        try:
            await asyncio.shield(cleanup)
        except asyncio.CancelledError as error:
            cancellation = error
        except Exception:
            break
    if cancellation is not None:
        # Retrieve any safe cleanup error before preserving caller cancellation.
        if not cleanup.cancelled():
            cleanup.exception()
        raise cancellation
    cleanup.result()


@asynccontextmanager
async def _managed_sandbox(operation, *, delete_orphan_snapshots: bool = True):
    # Awaiting create_sandbox is a supported SDK API for explicit ownership.
    box = await operation
    body_error = None
    try:
        yield box
    except BaseException as error:
        body_error = error
        raise
    finally:
        try:
            await _finish_cleanup(box, delete_orphan_snapshots=delete_orphan_snapshots)
        except Exception:
            if isinstance(body_error, asyncio.CancelledError):
                raise body_error
            raise


class CloudWorkerClient:
    def __init__(self, image: str | None = None, *, snapshot_id: str | None = None, factory: Callable[..., Any] | None = None,
                 resolver: Callable[[str, int], Awaitable[list[str]]] | None = None):
        self.image = image or ""
        scoped = self.image.removeprefix("vcr.vercel.com/").split("@", 1)[0]
        if self.image and (not _IMAGE.fullmatch(self.image) or ("/" in scoped and "." in scoped.split("/", 1)[0])):
            raise ValueError("Cloud Worker image must be a VCR reference pinned by sha256 digest")
        self.snapshot_id = snapshot_id or ""
        if self.snapshot_id and (not isinstance(self.snapshot_id, str) or not _SNAPSHOT.fullmatch(self.snapshot_id)):
            raise ValueError("Cloud Worker snapshot must be a bounded snap_ identifier")
        if self.image and self.snapshot_id:
            raise ValueError("Cloud Worker requires exactly one image or snapshot source")
        self.enabled = bool(self.image or self.snapshot_id)
        self._factory = factory
        self._resolver = resolver or _resolve

    async def analyze(self, scan_id: str, url: str) -> tuple[CloudBrowserResult, bytes | None]:
        if not self.enabled:
            raise CloudWorkerError("worker_not_configured")
        if not isinstance(scan_id, str) or not _SCAN_ID.fullmatch(scan_id):
            raise CloudWorkerError("worker_invalid_response")
        url, host, port = _public_url(url)
        try:
            async with asyncio.timeout(5):
                addresses = await self._resolver(host, port)
            # IPv6 egress is deliberately disabled, including mixed A/AAAA hosts.
            # Public AAAA records are harmless when an allowed A record exists.
            ipv4 = [item for item in addresses if ":" not in item]
            if not ipv4 or any(not _public_ipv4(item) for item in ipv4):
                raise CloudWorkerError("unsafe_target", blocked=True)
            for item in addresses:
                address = ipaddress.ip_address(item)
                if address.version == 6 and not address.is_global:
                    raise CloudWorkerError("unsafe_target", blocked=True)
        except CloudWorkerError:
            raise
        except (OSError, ValueError, TimeoutError):
            raise CloudWorkerError("worker_unreachable") from None

        try:
            from vercel import sandbox
            from vercel.sandbox import NetworkPolicy, NetworkPolicySubnets, SandboxResources, SnapshotSource

            factory = self._factory or sandbox.create_sandbox
            policy = NetworkPolicy.custom(allow={"*": ()}, subnets=NetworkPolicySubnets(deny=DENIED_SUBNETS))
            source = {"source": SnapshotSource(snapshot_id=self.snapshot_id)} if self.snapshot_id else {"image": self.image}
            async with asyncio.timeout(65):
                async with _managed_sandbox(factory(**source, persistent=False, execution_time_limit=45,
                                                   resources=SandboxResources(vcpus=1, memory=2048), network_policy=policy),
                                            delete_orphan_snapshots=not bool(self.snapshot_id)) as box:
                    await _disable_ipv6(box)
                    await box.fs.write_text(INPUT_PATH, json.dumps({"scanId": scan_id, "url": url, "timeoutMs": 20000}))
                    process = await box.run_process("node", ["--max-old-space-size=512", "/app/cloud/run.cjs"],
                                                    cwd="/app", kill_after=25, capture_output=True, check=False,
                                                    env=dict(RUNNER_ENV))
                    if process.returncode not in (0, 1):
                        raise CloudWorkerError("worker_unreachable")
                    data = await _read_bounded(box.fs, RESULT_PATH, MAX_RESULT_BYTES)
                    try:
                        result = CloudBrowserResult.model_validate(json.loads(data))
                    except (ValueError, ValidationError, RecursionError):
                        raise CloudWorkerError("worker_invalid_response") from None
                    if result.scan_id != scan_id:
                        raise CloudWorkerError("worker_invalid_response")
                    for target in (result.final_url, result.redirect_analysis.final_url if result.redirect_analysis else None):
                        if target:
                            _public_url(target)
                    result.error_code = result.error_code if result.error_code in _SAFE_ERRORS else None
                    png = None
                    if result.screenshot_status == "ready":
                        try:
                            png = _decode_png(await _read_bounded(box.fs, SCREENSHOT_PATH, MAX_PNG_BYTES))
                        except Exception:
                            result.screenshot_status = "failed"
                            result.error_code = "invalid_screenshot"
                    result.inspection_complete = bool(
                        process.returncode == 0 and result.inspection_complete and result.status == "completed" and result.final_url
                        and result.http_status is not None and result.http_status < 400 and png and result.dom_analysis
                        and result.network_analysis and result.network_analysis.blocked_request_count == 0
                        and result.redirect_analysis
                    )
                    if not result.inspection_complete:
                        result.status = "failed"
                    return result, png
        except CloudWorkerError:
            raise
        except TimeoutError:
            raise CloudWorkerError("worker_timeout") from None
        except Exception:
            # SDK errors can contain request URLs, auth headers and remote logs.
            raise CloudWorkerError("worker_unreachable") from None
