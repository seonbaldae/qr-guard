"""Offline Phishpedia inference in a VM separate from the visiting browser.

Only a bounded PNG and its observed final URL enter the model VM. The prepared
snapshot contains the pinned code, weights and reference features; runtime
network access, package installation and model downloads are forbidden.
"""

from __future__ import annotations

import asyncio
import json
import re
from collections.abc import Callable
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, StrictFloat, StrictInt, StrictStr, ValidationError
from pydantic.alias_generators import to_camel

from app.cloud_worker import _decode_png, _managed_sandbox, _public_url

MAX_MODEL_RESULT_BYTES = 64 * 1024
MODEL_TIMEOUT_SECONDS = 150
MODEL_PROCESS_SECONDS = 120
PYTHON = "/opt/phishpedia/.venv/bin/python"
MODEL_ROOT = "/opt/phishpedia"
_SNAPSHOT = re.compile(r"^snap_[A-Za-z0-9_-]{1,128}$")
_SCAN_ID = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
MODEL_ENV = {
    "KMP_DUPLICATE_LIB_OK": "TRUE", "OMP_NUM_THREADS": "2", "MKL_NUM_THREADS": "2",
    "OPENBLAS_NUM_THREADS": "2", "NUMEXPR_NUM_THREADS": "2", "MAX_JOBS": "2",
    "CUDA_VISIBLE_DEVICES": "", "HF_HUB_OFFLINE": "1", "TRANSFORMERS_OFFLINE": "1",
    "PYTHONNOUSERSITE": "1", "PYTHONDONTWRITEBYTECODE": "1",
}


class CloudPhishpediaError(Exception):
    """A fixed code; SDK errors and model process output stay private."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


class _Model(BaseModel):
    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True, extra="forbid")


class BrandDomainComparison(_Model):
    status: Literal["match", "mismatch", "not_evaluated"]
    actual_host: StrictStr = Field(min_length=1, max_length=255)
    matched_reference_domain: StrictStr | None = Field(default=None, max_length=255)


class CloudBrandAnalysis(_Model):
    engine: Literal["phishpedia"]
    status: Literal["completed"]
    signal: Literal["brand_unidentified", "brand_domain_match", "brand_domain_inconsistency"]
    candidate_brand: StrictStr | None = Field(default=None, min_length=1, max_length=200)
    reference_domains: list[Annotated[StrictStr, Field(min_length=1, max_length=255)]] = Field(max_length=100)
    raw_similarity: Annotated[StrictFloat, Field(allow_inf_nan=False, ge=-1.001, le=1.001)] | None = None
    detected_logo_count: Annotated[StrictInt, Field(ge=0, le=10_000)]
    domain_comparison: BrandDomainComparison


class BrandEnvelope(_Model):
    scan_id: StrictStr = Field(pattern=_SCAN_ID.pattern)
    final_url: StrictStr = Field(min_length=1, max_length=2048)
    brand_analysis: CloudBrandAnalysis


def _reference_domain(value: str) -> str:
    try:
        if any(char.isspace() for char in value) or any(char in value for char in "/:@?#\\"):
            raise ValueError
        host = value.rstrip(".").encode("idna").decode("ascii").lower()
        labels = host.split(".")
        if len(host) > 253 or len(labels) < 2 or not all(_LABEL.fullmatch(label) for label in labels):
            raise ValueError
        return host
    except (ValueError, UnicodeError):
        raise CloudPhishpediaError("phishpedia_invalid_response") from None


def validate_brand_result(envelope: BrandEnvelope, scan_id: str, final_url: str) -> CloudBrandAnalysis:
    """Recompute domain consistency rather than accepting a remote verdict."""
    if envelope.scan_id != scan_id or envelope.final_url != final_url:
        raise CloudPhishpediaError("phishpedia_result_mismatch")
    _, actual_host, _ = _public_url(final_url)
    brand = envelope.brand_analysis
    comparison = brand.domain_comparison
    if comparison.actual_host != actual_host:
        raise CloudPhishpediaError("phishpedia_result_mismatch")
    if brand.signal == "brand_unidentified":
        if (brand.candidate_brand is not None or brand.reference_domains
                or comparison.status != "not_evaluated" or comparison.matched_reference_domain is not None):
            raise CloudPhishpediaError("phishpedia_invalid_response")
        return brand
    if (not brand.candidate_brand or not brand.candidate_brand.strip() or not brand.reference_domains
            or brand.raw_similarity is None or brand.detected_logo_count < 1):
        raise CloudPhishpediaError("phishpedia_invalid_response")
    domains = sorted({_reference_domain(value) for value in brand.reference_domains})
    matched = next((domain for domain in domains if actual_host == domain or actual_host.endswith("." + domain)), None)
    expected = "brand_domain_match" if matched else "brand_domain_inconsistency"
    if brand.signal != expected or comparison.status != ("match" if matched else "mismatch"):
        raise CloudPhishpediaError("phishpedia_invalid_response")
    reported_match = comparison.matched_reference_domain
    if matched is None and reported_match is not None:
        raise CloudPhishpediaError("phishpedia_invalid_response")
    if matched is not None and (reported_match is None or _reference_domain(reported_match) not in domains
                                or not (actual_host == _reference_domain(reported_match)
                                        or actual_host.endswith("." + _reference_domain(reported_match)))):
        raise CloudPhishpediaError("phishpedia_invalid_response")
    return brand.model_copy(update={"reference_domains": domains})


class CloudPhishpediaAnalyzer:
    def __init__(self, snapshot_id: str | None = None, *, factory: Callable[..., Any] | None = None):
        self.snapshot_id = snapshot_id or ""
        if self.snapshot_id and (not isinstance(self.snapshot_id, str) or not _SNAPSHOT.fullmatch(self.snapshot_id)):
            raise ValueError("Phishpedia requires a fixed snap_ runtime identifier")
        self.enabled = bool(self.snapshot_id)
        self._factory = factory

    async def analyze(self, scan_id: str, final_url: str, png: bytes) -> CloudBrandAnalysis:
        if not self.enabled:
            raise CloudPhishpediaError("phishpedia_not_configured")
        if not isinstance(scan_id, str) or not _SCAN_ID.fullmatch(scan_id):
            raise CloudPhishpediaError("phishpedia_invalid_input")
        try:
            _public_url(final_url)
            if not isinstance(png, bytes):
                raise ValueError
            png = _decode_png(png)
        except Exception:
            raise CloudPhishpediaError("phishpedia_invalid_input") from None
        directory = f"/tmp/{scan_id}"
        try:
            from vercel import sandbox
            from vercel.sandbox import NetworkPolicy, SandboxResources, SnapshotSource

            factory = self._factory or sandbox.create_sandbox
            async with asyncio.timeout(MODEL_TIMEOUT_SECONDS):
                async with _managed_sandbox(factory(
                    source=SnapshotSource(snapshot_id=self.snapshot_id), persistent=False,
                    execution_time_limit=180, resources=SandboxResources(vcpus=4, memory=8192),
                    network_policy=NetworkPolicy.deny_all(),
                ), delete_orphan_snapshots=False) as box:
                    await box.fs.mkdir(directory, recursive=False)
                    await box.fs.write_bytes(f"{directory}/shot.png", png, mode=0o600)
                    await box.fs.write_text(f"{directory}/info.txt", final_url, mode=0o600)
                    process = await box.run_process(
                        PYTHON, ["-u", f"{MODEL_ROOT}/analyze-brand.py", "--input", directory],
                        cwd=MODEL_ROOT, kill_after=MODEL_PROCESS_SECONDS,
                        capture_output=True, check=False, env=dict(MODEL_ENV),
                    )
                    if process.returncode != 0:
                        raise CloudPhishpediaError("phishpedia_failed")
                    async with box.fs.open(f"{directory}/brand-analysis.json", "rb") as stream:
                        raw = await stream.read(MAX_MODEL_RESULT_BYTES + 1)
                    if not isinstance(raw, bytes) or len(raw) > MAX_MODEL_RESULT_BYTES:
                        raise CloudPhishpediaError("phishpedia_invalid_response")
                    try:
                        envelope = BrandEnvelope.model_validate(json.loads(raw))
                    except (ValueError, ValidationError, RecursionError):
                        raise CloudPhishpediaError("phishpedia_invalid_response") from None
                    return validate_brand_result(envelope, scan_id, final_url)
        except CloudPhishpediaError:
            raise
        except TimeoutError:
            raise CloudPhishpediaError("phishpedia_timeout") from None
        except Exception:
            raise CloudPhishpediaError("phishpedia_unreachable") from None
