"""Explicit threat-check test doubles. They never invoke Google or read keys."""

from datetime import datetime, timezone

from app.precheck.payload import normalize
from app.precheck.safebrowsing import SafeBrowsingCheck
from app.precheck.schema import Evidence, ProviderResult, ProviderStatus, Signal


def google_result(matched=False, status: ProviderStatus = "checked"):
    now = datetime.now(timezone.utc).isoformat()
    provider = ProviderResult(
        name="google_safe_browsing", status=status,
        matched=matched if status == "checked" else None,
        checkedAt=now if status == "checked" else None,
    )
    if not matched or status != "checked":
        return SafeBrowsingCheck(provider)
    evidence = Evidence(
        id="ev-google", kind="known_threat_match", source="google_safe_browsing",
        observedAt=now, summary="Google에서 알려진 위협이 발견되었습니다.",
    )
    signal = Signal(
        id="sig-google", kind="known_threat_match", severity="high", source="google_safe_browsing",
        summary="Google에서 알려진 위협이 발견되었습니다.", evidenceIds=[evidence.id],
    )
    return SafeBrowsingCheck(provider, [signal], [evidence])


def fake_google(matched_urls=(), status: ProviderStatus = "checked"):
    matches = {normalize(url) for url in matched_urls}
    return lambda url: google_result(normalize(url) in matches, status)
