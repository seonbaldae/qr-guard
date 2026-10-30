"""Real loopback HTTP smoke test. No fake Worker or target webpage requests."""

import os
from pathlib import Path
import socket
import subprocess
import sys
import time

import httpx


def test_uvicorn_real_http_roundtrip():
    root = Path(__file__).resolve().parents[2]
    environment = {key: value for key, value in os.environ.items() if not key.startswith("QR_GUARD_")}
    # Explicit empty canonical key disables both legacy environment and .env fallback.
    environment["GOOGLE_SAFE_BROWSING_API_KEY"] = ""
    environment.pop("SAFE_BROWSING_API_KEY", None)
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
        process = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "app.main:app", "--fd", str(listener.fileno()),
             "--workers", "1", "--no-access-log", "--log-level", "error"],
            cwd=root, env=environment, pass_fds=(listener.fileno(),),
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True,
        )
        try:
            with httpx.Client(base_url=f"http://127.0.0.1:{port}", trust_env=False, timeout=2) as client:
                deadline = time.monotonic() + 10
                while True:
                    try:
                        assert client.get("/api/health").status_code == 200
                        break
                    except httpx.TransportError:
                        assert process.poll() is None, "Uvicorn exited during startup"
                        assert time.monotonic() < deadline, "Uvicorn startup timed out"
                        time.sleep(0.02)
                for mode in ["static", "sandbox"]:
                    response = client.post("/api/scans", json={"url": "https://example.test/", "mode": mode})
                    assert response.status_code == 202
                    assert response.json()["status"] == "queued"
                    scan_id = response.json()["scanId"]
                    while True:
                        report = client.get(f"/api/scans/{scan_id}").json()
                        if report["status"] in {"completed", "failed"}:
                            break
                        assert time.monotonic() < deadline
                        time.sleep(0.01)
                    assert report["status"] == "completed"
                    assert report["verdict"]["level"] == "unknown"
                    expected = "not_requested" if mode == "static" else "blocked"
                    assert report["sandboxAnalysis"]["status"] == expected
                    assert client.get(f"/api/scans/{scan_id}/screenshot").status_code == 409
                assert client.post("/api/scans", json={"url": "javascript:alert(1)"}).status_code == 422
                assert client.get("/api/scans/missing").status_code == 404
                assert client.get("/docs").status_code == 200
                assert client.get("/openapi.json").status_code == 200
        finally:
            process.terminate()
            try:
                _, errors = process.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                _, errors = process.communicate(timeout=5)
            assert "Traceback" not in errors, errors
