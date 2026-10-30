"""Actual jobs wire contract and network-disabled container bridge boundaries."""

import asyncio
import base64
import json

import httpx
import pytest

from app.config import Settings
from app.main import create_app
from app.worker import DOCKER_HTTP_CLIENT, DockerWorkerTransport, SCOPE_LIMITATIONS
from .support import fake_google
from .test_scans import png_bytes

TARGET = "http://127.0.0.1:4000/demo/normal"


def jobs_fixture(*, changes=None, running_once=False, image_type="image/png", target=TARGET):
    calls = []
    scan_id = None
    polls = 0

    def handle(request):
        nonlocal scan_id, polls
        calls.append((request.method, request.url.path))
        if request.method == "POST":
            assert request.url.path == "/internal/jobs"
            body = json.loads(request.content)
            assert body["url"] == target
            assert set(body) == {"scanId", "url", "timeoutMs"}
            scan_id = body["scanId"]
            return httpx.Response(202, json={"scanId": scan_id, "status": "queued"})
        if request.url.path.endswith("/screenshot"):
            return httpx.Response(200, headers={"content-type": image_type}, content=png_bytes())
        assert request.url.path == f"/internal/jobs/{scan_id}"
        polls += 1
        job = {
            "scanId": scan_id, "status": "running" if running_once and polls == 1 else "completed",
            "finalUrl": target, "httpStatus": 200, "screenshotStatus": "ready",
            "domAnalysis": {"pageTitle": "통제된 테스트", "passwordFieldCount": 0,
                            "sensitiveFieldTypes": [], "forms": []},
            "networkAnalysis": {"requestHosts": ["127.0.0.1"], "requestCount": 1,
                                "blockedRequestCount": 0},
            "redirectAnalysis": {"redirected": False, "finalUrl": target, "redirectChain": []},
            "limitations": list(SCOPE_LIMITATIONS),
            "evidence": [{"data": {"ignoredUntrustedNestedField": {"secret": "not serialized"}}}],
        }
        job.update(changes or {})
        return httpx.Response(200, json=job)
    return handle, calls


def scan_jobs(**fixture_options):
    handle, calls = jobs_fixture(**fixture_options)

    async def scenario():
        app = create_app(Settings(worker_url="http://worker.test", demo_origins=("http://127.0.0.1:4000",),
                                  worker_egress_verified=True),
                         worker_transport=httpx.MockTransport(handle), threat_check=fake_google())
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://api.test") as client:
            accepted = await client.post("/api/scans", json={"url": TARGET, "mode": "sandbox"})
            key = accepted.json()["scanId"]
            report = (await client.get(f"/api/scans/{key}")).json()
            image = await client.get(f"/api/scans/{key}/screenshot")
            return report, image, calls
    return asyncio.run(scenario())


def test_jobs_polling_png_and_scope_limitations_keep_actual_observations():
    report, image, calls = scan_jobs(running_once=True)
    assert [method for method, _ in calls] == ["POST", "GET", "GET", "GET"]
    assert report["verdict"]["level"] == "no_known_threat"
    assert image.content == png_bytes()
    assert report["sandboxAnalysis"]["limitations"]
    observed = {item["kind"]: item for item in report["evidence"]}
    assert observed["dom_observation"]["data"]["passwordFieldCount"] == 0
    assert observed["network_observation"]["data"] == {
        "requestCount": 1, "blockedRequestCount": 0, "hostCount": 1,
    }
    assert observed["redirect_observation"]["data"]["redirected"] is False
    known = {item["id"] for item in report["evidence"]}
    assert all(set(signal["evidenceIds"]) <= known for signal in report["sandboxAnalysis"]["signals"])
    assert "ignoredUntrustedNestedField" not in str(report)


def test_missing_dom_preserves_png_without_claiming_zero_observed_fields():
    report, image, _ = scan_jobs(changes={"domAnalysis": None})
    assert image.status_code == 200
    assert report["verdict"]["level"] == "unknown"
    assert not any(item["kind"] == "dom_observation" for item in report["evidence"])
    assert any("DOM" in message for message in report["sandboxAnalysis"]["limitations"])


@pytest.mark.parametrize("changes,code", [
    ({"scanId": "wrong-job"}, "worker_scan_mismatch"),
    ({"status": "failed", "errorCode": "secret-internal-data"}, "worker_job_failed"),
    ({"finalUrl": "http://169.254.169.254/"}, "worker_destination_not_allowed"),
    ({"screenshotStatus": "pending"}, "worker_screenshot_unavailable"),
])
def test_jobs_failures_never_publish_a_clean_verdict(changes, code):
    report, image, _ = scan_jobs(changes=changes)
    assert report["verdict"]["level"] == "unknown"
    assert report["sandboxAnalysis"]["errorCode"] == code
    assert image.status_code == 409
    assert "secret-internal-data" not in str(report)


def test_png_endpoint_must_really_return_png_media_type():
    report, image, _ = scan_jobs(image_type="text/html")
    assert report["sandboxAnalysis"]["errorCode"] == "invalid_screenshot"
    assert image.status_code == 409


@pytest.mark.parametrize("method,path", [
    ("GET", "/internal/jobs"), ("DELETE", "/internal/jobs/a"),
    ("POST", "/internal/jobs/a/cancel"), ("GET", "/internal/jobs/a?url=other"),
    ("GET", "/arbitrary"),
])
def test_docker_bridge_rejects_unapproved_operations_before_spawning(monkeypatch, method, path):
    async def forbidden(*args, **kwargs):
        pytest.fail("Forbidden Docker process was spawned")
    monkeypatch.setattr(asyncio, "create_subprocess_exec", forbidden)

    async def scenario():
        transport = DockerWorkerTransport("qr-guard-worker-live")
        with pytest.raises(httpx.TransportError):
            await transport.handle_async_request(httpx.Request(method, "http://worker.test" + path))
    asyncio.run(scenario())


def test_docker_bridge_uses_fixed_command_stdin_and_secret_free_child_environment(monkeypatch):
    captured = {}
    monkeypatch.setenv("GOOGLE_SAFE_BROWSING_API_KEY", "test-secret-do-not-inherit")
    monkeypatch.setenv("SAFE_BROWSING_API_KEY", "legacy-secret-do-not-inherit")
    monkeypatch.setenv("UNRELATED_SERVER_TOKEN", "other-secret-do-not-inherit")

    class Input:
        def write(self, data):
            captured["stdin"] = json.loads(data)
        async def drain(self):
            pass
        def close(self):
            pass

    class Process:
        def __init__(self):
            self.stdin = Input()
            self.stdout = asyncio.StreamReader()
            self.stdout.feed_data(json.dumps({"status": 200, "type": "application/json",
                "body": base64.b64encode(b'{"status":"ok"}').decode()}).encode())
            self.stdout.feed_eof()
            self.returncode = 0
        async def wait(self):
            return 0

    async def spawn(*args, **kwargs):
        captured["args"] = args
        captured["options"] = kwargs
        return Process()
    monkeypatch.setattr(asyncio, "create_subprocess_exec", spawn)

    async def scenario():
        response = await DockerWorkerTransport("qr-guard-worker-live").handle_async_request(
            httpx.Request("GET", "http://worker.test/internal/health"))
        assert response.json() == {"status": "ok"}
    asyncio.run(scenario())
    assert captured["args"] == ("docker", "exec", "-i", "qr-guard-worker-live", "node", "-e", DOCKER_HTTP_CLIENT)
    assert "shell" not in captured["options"]
    assert captured["stdin"] == {"method": "GET", "path": "/internal/health", "body": ""}
    assert not any("secret" in value for value in captured["options"]["env"].values())
    assert all(key not in captured["options"]["env"] for key in (
        "GOOGLE_SAFE_BROWSING_API_KEY", "SAFE_BROWSING_API_KEY", "UNRELATED_SERVER_TOKEN"))


@pytest.mark.parametrize("name", [";id", "--privileged", "x/y", "a b", "$(id)"])
def test_container_configuration_cannot_be_a_shell_or_docker_argument(name):
    with pytest.raises(ValueError):
        Settings(worker_container=name)
    with pytest.raises(ValueError):
        DockerWorkerTransport(name)


@pytest.mark.parametrize("target,allowed", [
    ("https://example.com/path?q=one", True), ("http://8.8.8.8/", True),
    ("http://127.0.0.1/", False), ("http://169.254.169.254/", False),
    ("http://[::1]/", False), ("https://example.com:444/", False),
    ("https://user:pass@example.com/", False), ("http://localhost/", False),
    ("https://x.local/", False), ("file:///tmp/input", False),
])
def test_public_target_checks_remain_narrow_before_dns(target, allowed):
    from app.worker import public_target
    assert public_target(target) is allowed


@pytest.mark.parametrize("blocked", [0, 1])
def test_public_jobs_are_wrapped_in_the_tunnel_and_blocked_requests_force_unknown(monkeypatch, blocked):
    import sys
    import types
    from app.worker import WorkerClient
    target = "https://example.com/path?lookup=exact"
    entered = []

    class Tunnel:
        def __init__(self, container_name, timeout_seconds):
            assert container_name == "qr-guard-worker-live"
            assert 0 < timeout_seconds <= 30
            self.blocked_count = blocked
        async def __aenter__(self):
            entered.append("enter")
            return self
        async def __aexit__(self, *args):
            entered.append("exit")
    monkeypatch.setitem(sys.modules, "app.egress_tunnel", types.SimpleNamespace(PublicEgressTunnel=Tunnel))
    handle, calls = jobs_fixture(target=target)

    async def scenario():
        client = WorkerClient(Settings(worker_container="qr-guard-worker-live", public_preview=True,
                                      worker_egress_verified=True), transport=httpx.MockTransport(handle))
        result, image = await client.analyze("public-job", target)
        assert entered == ["enter", "exit"]
        assert image == png_bytes()
        assert result.final_url == target
        assert result.inspection_complete is (blocked == 0)
        if blocked:
            assert any("차단" in item for item in result.limitations)
    asyncio.run(scenario())
    assert calls[0] == ("POST", "/internal/jobs")


def test_public_flag_alone_does_not_allow_private_or_remote_worker_transport(monkeypatch):
    from app.worker import WorkerClient, WorkerError
    async def scenario():
        for settings, target in [
            (Settings(worker_container="qr-guard-worker-live", public_preview=True, worker_egress_verified=True), "http://169.254.169.254/"),
            (Settings(worker_container="qr-guard-worker-live", public_preview=False, worker_egress_verified=True), "https://example.com/"),
            (Settings(worker_url="http://worker.test", public_preview=True, worker_egress_verified=True), "https://example.com/"),
        ]:
            def forbidden(request):
                pytest.fail("Blocked public target reached Worker")
            client = WorkerClient(settings, transport=httpx.MockTransport(forbidden))
            with pytest.raises(WorkerError, match="target_not_allowed"):
                await client.analyze("blocked-job", target)
    asyncio.run(scenario())
