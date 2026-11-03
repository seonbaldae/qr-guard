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


def jobs_worker_from_result(handler):
    """Use existing bounded result fixtures through the actual jobs/PNG wire API."""
    import base64
    import json
    import httpx

    results = {}

    def transport(request):
        if request.method == "POST" and request.url.path == "/internal/jobs":
            response = handler(request)
            if response.status_code != 200:
                return response
            try:
                result = response.json()
                scan_id = json.loads(request.content)["scanId"]
            except (ValueError, KeyError):
                return response
            results[scan_id] = result
            return httpx.Response(202, json={"scanId": scan_id, "status": "queued"})
        scan_id = request.url.path.split("/")[3]
        result = results[scan_id]
        if request.url.path.endswith("/screenshot"):
            try:
                image = base64.b64decode(result["screenshotBase64"], validate=True)
            except (ValueError, KeyError):
                image = b"invalid PNG fixture"
            return httpx.Response(200, headers={"content-type": "image/png"}, content=image)
        return httpx.Response(200, json={
            "scanId": scan_id, "status": "completed", "finalUrl": result["finalUrl"],
            "httpStatus": result["httpStatus"], "screenshotStatus": "ready",
            "domAnalysis": {key: result[key] for key in (
                "pageTitle", "passwordFieldCount", "sensitiveFieldTypes", "forms",
            )},
            "networkAnalysis": {"requestHosts": result["requestHosts"], "requestCount": 1,
                                "blockedRequestCount": 0},
            "redirectAnalysis": {"finalUrl": result["finalUrl"], "redirected": result["redirected"],
                                 "redirectChain": []},
            "limitations": result["limitations"],
        })
    return transport
