"""Run only owned QR Guard browser fixtures in the fixed review sandbox."""
import base64
import json
from pathlib import Path
import subprocess
import sys
import time

repo = Path(__file__).resolve().parents[2]
output = repo.parents[1] / ".worker-review" / "analysis-v03"
output.mkdir(parents=True, exist_ok=True)
name = "qr-guard-analysis-v03-check"
command = [
    "docker", "run", "--rm", "--name", name, "--network", "none", "--read-only",
    "--cap-drop", "ALL", "--cap-add", "SYS_CHROOT", "--security-opt", "no-new-privileges",
    "--security-opt", f"seccomp={repo / 'worker/seccomp_profile.json'}",
    "--pids-limit", "256", "--memory", "1g", "--cpus", "1",
    "--tmpfs", "/tmp:rw,nosuid,nodev,size=256m", "--shm-size", "128m", "--init",
    "--mount", f"type=bind,src={repo / 'worker/tests'},dst=/app/tests,readonly",
    "--env", "ANALYSIS_TEST_OUTPUT=/tmp/analysis-test-output", "--entrypoint", "node",
    "qr-guard-review-worker:analysis-v03", "--test", "--test-timeout=45000", "tests/browser-analysis.cjs",
]
process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
try:
    config = None
    for _ in range(40):
        probe = subprocess.run(["docker", "inspect", name], capture_output=True, text=True)
        if probe.returncode == 0:
            config = json.loads(probe.stdout)[0]
            break
        if process.poll() is not None:
            break
        time.sleep(0.05)
    assert config is not None, "review container was inspected before exit"
    host = config["HostConfig"]
    assert host["NetworkMode"] == "none"
    assert host["ReadonlyRootfs"] is True
    assert host["PidsLimit"] == 256
    assert host["Memory"] == 1024 * 1024 * 1024
    assert host["CapDrop"] == ["ALL"] and host["CapAdd"] == ["CAP_SYS_CHROOT"]
    assert any("no-new-privileges" in item for item in host["SecurityOpt"])
    seccomp = next(item.split("=", 1)[1] for item in host["SecurityOpt"] if item.startswith("seccomp="))
    assert json.loads(seccomp) == json.loads((repo / "worker/seccomp_profile.json").read_text())
    assert config["Config"]["User"] == "pwuser"
    text, _ = process.communicate(timeout=60)
finally:
    if process.poll() is None:
        subprocess.run(["docker", "stop", "-t", "2", name], capture_output=True)
        process.communicate(timeout=10)

clean = []
for line in text.splitlines():
    marker = "QR_GUARD_ARTIFACTS_JSON "
    if marker not in line:
        clean.append(line)
        continue
    artifacts = json.loads(line.split(marker, 1)[1])
    results = artifacts["results"]
    results["container"] = {
        "image": config["Config"]["Image"], "user": config["Config"]["User"],
        "networkMode": host["NetworkMode"], "readonlyRootfs": host["ReadonlyRootfs"],
        "capAdd": host["CapAdd"], "capDrop": host["CapDrop"],
        "noNewPrivileges": True, "seccompMatchesProject": True,
        "pidsLimit": host["PidsLimit"], "memoryBytes": host["Memory"],
    }
    (output / "browser-results.json").write_text(json.dumps(results, ensure_ascii=False, indent=2) + "\n")
    if "pngBase64" in artifacts:
        (output / "normal.png").write_bytes(base64.b64decode(artifacts["pngBase64"], validate=True))
    if "job" in artifacts:
        (output / "normal-job.json").write_text(json.dumps(artifacts["job"], ensure_ascii=False, indent=2) + "\n")
clean_text = "\n".join(clean) + "\n"
(output / "browser-test-output.txt").write_text(clean_text)
print(clean_text, end="")
print("Generated browser artifacts:", output)
sys.exit(process.returncode)
