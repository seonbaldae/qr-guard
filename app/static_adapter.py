"""Adapter around B's existing synchronous analyzer and a local feed snapshot."""

from dataclasses import dataclass
from datetime import datetime, timezone
import os

from app.config import Settings
from app.models import Evidence, ProviderResult, Signal, StaticAnalysisResult
from app.precheck.analyzer import analyze
from app.precheck.payload import InvalidPayload, normalize


@dataclass(frozen=True)
class FeedSnapshot:
    urls: frozenset[str]
    modified_at: float | None

    @classmethod
    def load(cls, settings: Settings) -> "FeedSnapshot":
        try:
            if settings.feed_path is None:
                return cls(frozenset(), None)
            with settings.feed_path.open("rb") as stream:
                modified = os.fstat(stream.fileno()).st_mtime
                raw = stream.read(20 * 1024 * 1024 + 1)
            if len(raw) > 20 * 1024 * 1024:
                return cls(frozenset(), None)
            urls = frozenset(
                normalize(line) for line in raw.decode("utf-8").splitlines()
                if line.strip() and not line.lstrip().startswith("#")
            )
            return cls(urls, modified if urls else None)
        except (OSError, UnicodeError, InvalidPayload):
            return cls(frozenset(), None)

    def lookup(self, url: str, max_age: int) -> ProviderResult:
        now = datetime.now(timezone.utc)
        if self.modified_at is None:
            return ProviderResult(name="openphish", status="failed", matched=None, checked_at=None)
        stale = now.timestamp() - self.modified_at > max_age
        return ProviderResult(
            name="openphish", status="stale" if stale else "checked",
            matched=normalize(url) in self.urls, checked_at=now,
        )


def analyze_static(url: str, feed: FeedSnapshot, settings: Settings):
    result = analyze(url)
    static = StaticAnalysisResult.model_validate(result.model_dump(exclude={"evidence"}))
    evidence = [Evidence.model_validate(item.model_dump()) for item in result.evidence]
    provider = feed.lookup(url, settings.feed_max_age_seconds)
    static.providers = [provider]
    static.limitations = ["페이지 내용과 실제 정보 전송 여부는 검사하지 않았습니다."]
    if provider.status == "failed":
        static.limitations.append("사용 가능한 OpenPhish 피드가 없습니다.")
    elif provider.status == "stale":
        static.limitations.append("OpenPhish 피드가 오래되어 최신 위협을 반영하지 못할 수 있습니다.")
    if provider.matched:
        assert provider.checked_at is not None
        evidence.append(Evidence(
            id="ev-feed", kind="threat_feed_match", source="openphish",
            observed_at=provider.checked_at, summary="피싱 URL 목록과 정확히 일치했습니다.",
        ))
        static.signals.append(Signal(
            id="sig-feed", kind="threat_feed_match", severity="high", source="openphish",
            summary="피싱 URL 목록에 일치합니다.", evidence_ids=["ev-feed"],
        ))
    return static, evidence
