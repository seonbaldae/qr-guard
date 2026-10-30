"""Run the real local API, isolated browser and plain-JS frontend together.

Requires .venv requirements, Node.js and Docker Desktop. No secrets enter Docker.
"""
import argparse
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parents[1]
NAME = "qr-guard-worker-live"
IMAGE = "qr-guard-worker:local"


def docker(*args, **kwargs):
    return subprocess.run(["docker", *args], cwd=ROOT, check=True, **kwargs)


def verify_container(public_preview=False):
    # Inspect only configuration needed for isolation; never print environment values.
    inspected = docker("inspect", NAME, capture_output=True, text=True)
    config = json.loads(inspected.stdout)[0]
    host = config["HostConfig"]
    assert config["State"]["Running"], "Worker is not running"
    assert host["NetworkMode"] == "none", "Worker must have no network"
    assert not host["PortBindings"], "Worker ports must not be published"
    assert host["ReadonlyRootfs"] and not host["Privileged"]
    assert config["Config"]["User"] == "pwuser"
    assert host["CapDrop"] == ["ALL"]
    assert host["CapAdd"] == ["CAP_SYS_CHROOT"]
    assert host["PidsLimit"] == 256 and host["Memory"] == 1024 ** 3
    assert host["NanoCpus"] == 10 ** 9
    assert any("no-new-privileges" in value for value in host["SecurityOpt"])
    profile = next(value.split("=", 1)[1] for value in host["SecurityOpt"] if value.startswith("seccomp="))
    assert json.loads(profile) == json.loads((ROOT / "worker/seccomp_profile.json").read_text())
    assert not config["Mounts"], "Do not mount host files or Docker socket into Worker"
    flags = dict(value.split("=", 1) for value in config["Config"].get("Env", []) if "=" in value)
    assert (flags.get("QR_GUARD_PUBLIC_PREVIEW") == "true") == public_preview, (
        "Existing Worker mode differs; stop it and recreate with the requested mode")
    expected = docker("image", "inspect", IMAGE, "--format", "{{.Id}}", capture_output=True, text=True)
    assert config["Image"] == expected.stdout.strip(), "Existing Worker uses an older image; recreate it"


def wait_ready(url, child):
    for _ in range(80):
        if child.poll() is not None:
            raise RuntimeError("Local server exited during startup")
        try:
            with urlopen(url, timeout=1) as response:
                if response.status == 200:
                    return
        except OSError:
            time.sleep(0.15)
    raise RuntimeError("Local server did not become ready")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--skip-build", action="store_true")
    parser.add_argument("--public-preview", action="store_true",
                        help="Enable bounded public HTTP(S) previews through the verified host tunnel")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--api-port", type=int, default=8000)
    args = parser.parse_args()
    if not all(1024 <= port <= 65535 for port in (args.port, args.api_port)):
        parser.error("Use unprivileged ports from 1024 to 65535")
    if args.port == args.api_port:
        parser.error("Frontend and API ports must differ")
    os.chdir(ROOT)
    docker("info", "--format", "{{.ServerVersion}}", stdout=subprocess.DEVNULL)
    if not args.skip_build:
        base = subprocess.run(["docker", "image", "inspect", "seonbaldae-browser"], capture_output=True)
        if base.returncode:
            docker("build", "-f", "worker/Dockerfile", "-t", "seonbaldae-browser", "worker")
        docker("build", "-f", "worker/Dockerfile.worker", "-t", IMAGE, "worker")
    existing = subprocess.run(["docker", "container", "inspect", NAME], capture_output=True)
    created = existing.returncode != 0
    children = []
    try:
        if created:
            docker("run", "-d", "--name", NAME, "--network", "none", "--read-only",
                   "--cap-drop", "ALL", "--cap-add", "SYS_CHROOT",
                   "--security-opt", "no-new-privileges",
                   "--security-opt", f"seccomp={ROOT / 'worker/seccomp_profile.json'}",
                   "--pids-limit", "256", "--memory", "1g", "--cpus", "1",
                   "--tmpfs", "/tmp:rw,nosuid,nodev,size=256m", "--shm-size", "128m",
                   "--init", "--env", f"QR_GUARD_PUBLIC_PREVIEW={str(args.public_preview).lower()}",
                   IMAGE, stdout=subprocess.DEVNULL)
        verify_container(args.public_preview)
        api_env = os.environ.copy()
        api_env.update({
            "QR_GUARD_WORKER_CONTAINER": NAME,
            "QR_GUARD_WORKER_URL": "",
            "QR_GUARD_DEMO_ORIGINS": "http://127.0.0.1:4000",
            "QR_GUARD_WORKER_EGRESS_VERIFIED": "true",
            "QR_GUARD_WORKER_CONCURRENCY": "1",
            "QR_GUARD_PUBLIC_PREVIEW": str(args.public_preview).lower(),
        })
        api = subprocess.Popen([sys.executable, "-m", "uvicorn", "app.main:app",
                                "--host", "127.0.0.1", "--port", str(args.api_port),
                                "--workers", "1", "--no-access-log"], env=api_env)
        children.append(api)
        wait_ready(f"http://127.0.0.1:{args.api_port}/api/health", api)
        frontend_env = {key: value for key, value in os.environ.items()
                        if key not in {"GOOGLE_SAFE_BROWSING_API_KEY", "SAFE_BROWSING_API_KEY"}}
        frontend_env.update(PORT=str(args.port), QR_GUARD_API=f"http://127.0.0.1:{args.api_port}")
        frontend = subprocess.Popen(["node", "scripts/dev-server.mjs"], env=frontend_env)
        children.append(frontend)
        wait_ready(f"http://127.0.0.1:{args.port}/api/health", frontend)
        print(f"Ready: http://127.0.0.1:{args.port}/", flush=True)
        print("Controlled browser target: http://127.0.0.1:4000/demo/normal", flush=True)
        print("Ctrl+C stops the local servers. Existing Worker containers are preserved.", flush=True)
        while all(child.poll() is None for child in children):
            time.sleep(0.5)
    finally:
        for child in reversed(children):
            if child.poll() is None:
                child.terminate()
        for child in children:
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()
        if created:
            docker("rm", "-f", NAME, stdout=subprocess.DEVNULL)


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    try:
        main()
    except KeyboardInterrupt:
        pass
