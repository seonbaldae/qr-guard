"""Run the prebuilt Phishpedia model against one bounded Worker screenshot."""

import asyncio
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
from typing import Literal

from pydantic import ConfigDict, Field, StrictFloat, StrictInt, StrictStr, ValidationError

from app.config import Settings
from app.models import WireModel


class BrandDomainComparison(WireModel):
    status: Literal["match", "mismatch", "not_evaluated"]
    actual_host: StrictStr = Field(max_length=255)
    matched_reference_domain: StrictStr | None = Field(default=None, max_length=255)


class BrandAnalysis(WireModel):
    model_config = ConfigDict(
        alias_generator=WireModel.model_config["alias_generator"],
        populate_by_name=True,
        extra="ignore",
    )
    engine: Literal["phishpedia"]
    status: Literal["completed"]
    signal: Literal["brand_unidentified", "brand_domain_match", "brand_domain_inconsistency"]
    candidate_brand: StrictStr | None = Field(default=None, max_length=200)
    reference_domains: list[StrictStr] = Field(default_factory=list, max_length=100)
    raw_similarity: StrictFloat | None = None
    detected_logo_count: StrictInt = Field(ge=0, le=10_000)
    domain_comparison: BrandDomainComparison


class BrandEnvelope(WireModel):
    scan_id: StrictStr = Field(pattern=r"^[A-Za-z0-9_-]{1,64}$")
    final_url: StrictStr
    brand_analysis: BrandAnalysis


class PhishpediaError(Exception):
    pass


class PhishpediaAnalyzer:
    def __init__(self, settings: Settings):
        self.image = settings.phishpedia_image

    @property
    def enabled(self) -> bool:
        return self.image is not None

    async def analyze(self, scan_id: str, final_url: str, png: bytes) -> BrandAnalysis:
        if not self.image:
            raise PhishpediaError("phishpedia_not_configured")
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", scan_id):
            raise PhishpediaError("invalid_scan_id")
        return await asyncio.to_thread(self._run, scan_id, final_url, png)

    def _run(self, scan_id: str, final_url: str, png: bytes) -> BrandAnalysis:
        container = f"qr-guard-brand-{scan_id}"
        environment = {
            key: os.environ[key]
            for key in ("PATH", "HOME", "DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_CONFIG")
            if key in os.environ
        }
        try:
            with tempfile.TemporaryDirectory(prefix="qr-guard-brand-") as temporary:
                directory = Path(temporary) / scan_id
                directory.mkdir(mode=0o700)
                (directory / "shot.png").write_bytes(png)
                (directory / "info.txt").write_text(final_url, encoding="utf-8")
                command = [
                    "docker", "run", "--rm", "--name", container,
                    "--platform", "linux/amd64", "--network", "none", "--read-only",
                    "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                    "--pids-limit", "512", "--memory", "4g", "--cpus", "2",
                    "--tmpfs", "/tmp:rw,nosuid,nodev,size=512m",
                    "--mount", f"type=bind,source={directory},target=/input/{scan_id}",
                    self.image, "pixi", "run", "python", "-u", "analyze-brand.py",
                    "--input", f"/input/{scan_id}",
                ]
                completed = subprocess.run(
                    command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL, timeout=180, env=environment, check=False,
                )
                if completed.returncode:
                    raise PhishpediaError("phishpedia_failed")
                output = directory / "brand-analysis.json"
                if not output.is_file() or output.stat().st_size > 64 * 1024:
                    raise PhishpediaError("phishpedia_invalid_response")
                envelope = BrandEnvelope.model_validate_json(output.read_bytes())
                if envelope.scan_id != scan_id or envelope.final_url != final_url:
                    raise PhishpediaError("phishpedia_result_mismatch")
                return envelope.brand_analysis
        except (OSError, subprocess.SubprocessError, ValidationError, ValueError, json.JSONDecodeError) as exc:
            raise PhishpediaError("phishpedia_failed") from exc
        finally:
            try:
                subprocess.run(
                    ["docker", "rm", "-f", container], stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    timeout=10, env=environment, check=False,
                )
            except (OSError, subprocess.SubprocessError):
                pass
