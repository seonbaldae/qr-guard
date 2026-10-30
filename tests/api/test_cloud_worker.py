"""Cloud boundary tests use the real SDK policy and a disposable fake VM."""

import asyncio
import io
import json
from types import SimpleNamespace

import pytest
from PIL import Image

from app.cloud_worker import (
    CloudWorkerClient, CloudWorkerError, DENIED_SUBNETS, INPUT_PATH, MAX_PNG_BYTES,
    MAX_RESULT_BYTES, RESULT_PATH, SCREENSHOT_PATH,
)

IMAGE = "team/project/qr-worker@sha256:" + "a" * 64
TARGET = "https://example.com/path?token=private-value"


def png_bytes():
    buffer = io.BytesIO()
    Image.new("RGB", (2, 2), "white").save(buffer, format="PNG")
    return buffer.getvalue()


def result_body(**changes):
    body = {
        "scanId": "scan_123", "status": "completed", "finalUrl": TARGET,
        "httpStatus": 200, "screenshotStatus": "ready", "inspectionComplete": True,
        "domAnalysis": {"pageTitle": "모의 화면", "passwordFieldCount": 0, "sensitiveFieldTypes": [], "forms": []},
        "networkAnalysis": {"requestHosts": ["example.com"], "requestCount": 1, "blockedRequestCount": 0},
        "redirectAnalysis": {"redirected": False, "finalUrl": TARGET, "redirectChain": []},
        "limitations": [], "capturedAt": "2026-10-31T03:00:00Z",
        "evidence": [{"untrustedExtra": "ignored"}],
    }
    body.update(changes)
    return body


class Reader:
    def __init__(self, fs, path):
        self.fs, self.path = fs, path

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        self.fs.closed.append(self.path)

    async def read(self, maximum):
        self.fs.reads.append((self.path, maximum))
        return self.fs.files[self.path][:maximum]


class FakeFS:
    def __init__(self, body, png):
        self.files = {RESULT_PATH: json.dumps(body).encode(), SCREENSHOT_PATH: png}
        self.writes, self.reads, self.closed = [], [], []

    async def write_text(self, path, content):
        self.writes.append((path, content))

    def open(self, path, mode):
        assert mode == "rb"
        return Reader(self, path)


class FakeBox:
    def __init__(self, body=None, png=None, process_error=None, returncode=0):
        self.fs = FakeFS(body or result_body(), png if png is not None else png_bytes())
        self.calls, self.exited, self.process_error = [], False, process_error
        self.returncode = returncode

    async def run_process(self, command, args, **kwargs):
        self.calls.append((command, args, kwargs))
        if self.process_error:
            raise self.process_error
        return SimpleNamespace(returncode=self.returncode, stdout="private remote output", stderr="private remote error")


class Factory:
    def __init__(self, box):
        self.box, self.options = box, []

    def __call__(self, **kwargs):
        self.options.append(kwargs)
        return self

    async def __aenter__(self):
        return self.box

    async def __aexit__(self, *args):
        self.box.exited = True


async def public_dns(host, port):
    assert host == "example.com"
    assert port == 443
    return ["93.184.216.34", "2606:4700:4700::1111"]


def run(box=None, *, url=TARGET, resolver=public_dns, scan_id="scan_123"):
    box = box or FakeBox()
    factory = Factory(box)
    client = CloudWorkerClient(IMAGE, factory=factory, resolver=resolver)
    return asyncio.run(client.analyze(scan_id, url)), factory, box


def test_real_sdk_policy_and_process_contract_keep_credentials_out_of_vm():
    from vercel.sandbox._internal.models import _serialize_network_policy

    (result, png), factory, box = run()
    assert result.inspection_complete and result.status == "completed"
    assert png == png_bytes() and box.exited
    assert result.model_dump(by_alias=True)["domAnalysis"]["passwordFieldCount"] == 0
    assert "evidence" not in result.model_dump()
    options = factory.options[0]
    assert set(options) == {"image", "persistent", "execution_time_limit", "resources", "network_policy"}
    assert options["image"] == IMAGE and options["persistent"] is False
    assert options["execution_time_limit"] == 45
    assert options["resources"].vcpus == 1 and options["resources"].memory == 2048
    policy = options["network_policy"]
    assert policy.mode == "custom" and dict(policy.allow) == {"*": ()}
    assert policy.subnets.deny == DENIED_SUBNETS and policy.subnets.allow is None
    assert _serialize_network_policy(policy) == {"allow": {"*": []}, "subnets": {"deny": list(DENIED_SUBNETS)}}
    assert "::/0" in policy.subnets.deny and "168.63.129.16/32" in policy.subnets.deny
    assert box.calls == [("node", ["--max-old-space-size=512", "/app/cloud/run.cjs"],
                         {"cwd": "/app", "kill_after": 25, "capture_output": True, "check": False})]
    assert box.fs.writes[0][0] == INPUT_PATH
    assert json.loads(box.fs.writes[0][1]) == {"scanId": "scan_123", "url": TARGET, "timeoutMs": 20000}
    assert box.fs.reads == [(RESULT_PATH, MAX_RESULT_BYTES + 1), (SCREENSHOT_PATH, MAX_PNG_BYTES + 1)]
    assert set(box.fs.closed) == {RESULT_PATH, SCREENSHOT_PATH}


@pytest.mark.parametrize("url", [
    "http://127.0.0.1/", "https://10.1.2.3/", "http://169.254.169.254/latest/meta-data/",
    "http://168.63.129.16/", "https://[::1]/", "https://[2606:4700:4700::1111]/",
    "http://localhost/", "https://service.internal/", "https://user:pass@example.com/",
    "https://example.com:444/", "http://2130706433/", "http://0177.0.0.1/",
    "http://0x7f000001/", "file:///tmp/file", "https://example.com\\@127.0.0.1/",
])
def test_unsafe_targets_never_create_vm(url):
    factory = Factory(FakeBox())
    client = CloudWorkerClient(IMAGE, factory=factory, resolver=public_dns)
    with pytest.raises(CloudWorkerError, match="unsafe_target"):
        asyncio.run(client.analyze("scan_123", url))
    assert factory.options == []


@pytest.mark.parametrize("addresses", [["127.0.0.1"], ["93.184.216.34", "10.0.0.1"],
                                         ["93.184.216.34", "::1"], ["2606:4700:4700::1111"], []])
def test_dns_private_mixed_records_and_ipv6_only_fail_closed(addresses):
    async def resolve(*args):
        return addresses
    with pytest.raises(CloudWorkerError, match="unsafe_target"):
        run(resolver=resolve)


@pytest.mark.parametrize("changes", [
    {"scanId": "another_scan"}, {"httpStatus": "200"}, {"inspectionComplete": "true"},
    {"networkAnalysis": {"requestHosts": ["a"] * 201, "requestCount": 1, "blockedRequestCount": 0}},
    {"limitations": ["x" * 1001]}, {"status": "queued"},
])
def test_malformed_results_cleanup_vm(changes):
    box = FakeBox(result_body(**changes))
    with pytest.raises(CloudWorkerError, match="worker_invalid_response"):
        run(box)
    assert box.exited


def test_json_size_is_bounded_before_parsing():
    box = FakeBox()
    box.fs.files[RESULT_PATH] = b" " * (MAX_RESULT_BYTES + 2)
    with pytest.raises(CloudWorkerError, match="worker_invalid_response"):
        run(box)
    assert box.fs.reads == [(RESULT_PATH, MAX_RESULT_BYTES + 1)] and box.exited


@pytest.mark.parametrize("png", [b"not a png", b"\x89PNG\r\n\x1a\n" + b"x" * MAX_PNG_BYTES])
def test_invalid_or_oversize_png_cannot_be_ready(png):
    (result, image), _, box = run(FakeBox(png=png))
    assert result.status == "failed" and not result.inspection_complete
    assert result.screenshot_status == "failed" and result.error_code == "invalid_screenshot"
    assert image is None and box.exited


def test_pixel_limit_is_checked_before_decoding():
    buffer = io.BytesIO()
    Image.new("1", (4001, 4000)).save(buffer, format="PNG")
    (result, image), _, box = run(FakeBox(png=buffer.getvalue()))
    assert result.screenshot_status == "failed" and image is None and box.exited


@pytest.mark.parametrize("changes", [{"domAnalysis": None}, {"inspectionComplete": False},
                                        {"status": "failed", "errorCode": "remote secret"}])
def test_partial_observation_preserves_valid_screenshot_without_success(changes):
    (result, image), _, box = run(FakeBox(result_body(**changes)))
    assert result.status == "failed" and not result.inspection_complete and image == png_bytes()
    assert result.error_code is None and box.exited


@pytest.mark.parametrize("status", ["failed", "completed"])
def test_exit_one_partial_png_is_preserved_without_success(status):
    (result, image), _, box = run(FakeBox(result_body(status=status), returncode=1))
    assert result.status == "failed" and not result.inspection_complete
    assert result.screenshot_status == "ready" and image == png_bytes() and box.exited


def test_policy_block_preserves_screen_but_prevents_complete_inspection():
    body = result_body()
    body["networkAnalysis"]["blockedRequestCount"] = 1
    (result, image), _, box = run(FakeBox(body))
    assert result.status == "failed" and not result.inspection_complete and image
    assert box.exited


def test_redacted_redirect_metadata_does_not_discard_query_url_screenshot():
    body = result_body()
    body["redirectAnalysis"]["finalUrl"] = "https://example.com/path"
    (result, image), _, _ = run(FakeBox(body))
    assert result.inspection_complete and image


def test_private_final_url_is_rejected_and_vm_cleaned_up():
    box = FakeBox(result_body(finalUrl="http://169.254.169.254/"))
    with pytest.raises(CloudWorkerError, match="unsafe_target"):
        run(box)
    assert box.exited


@pytest.mark.parametrize("error,code", [(TimeoutError("secret"), "worker_timeout"),
                                        (RuntimeError("remote secret"), "worker_unreachable")])
def test_process_error_does_not_expose_remote_logs_and_cleans_vm(error, code):
    box = FakeBox(process_error=error)
    with pytest.raises(CloudWorkerError, match=code) as caught:
        run(box)
    assert str(caught.value) == code and box.exited


def test_missing_image_disables_client_and_tags_are_rejected():
    client = CloudWorkerClient(None)
    assert client.enabled is False
    with pytest.raises(CloudWorkerError, match="worker_not_configured"):
        asyncio.run(client.analyze("scan_123", TARGET))
    for image in ["worker:latest", "https://vcr.vercel.com/image", "worker@sha256:short", "mcr.microsoft.com/playwright@sha256:" + "a" * 64]:
        with pytest.raises(ValueError, match="pinned"):
            CloudWorkerClient(image)
