"""API-to-B integration uses explicit fake Google results; no Google calls."""

import asyncio
from datetime import datetime, timezone

import httpx

from app.main import create_app
from app.precheck.safebrowsing import SafeBrowsingCheck
from app.precheck.schema import Evidence, ProviderResult, Signal


def google_result(matched=False, status="checked"):
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


def test_f1_preserves_google_result_and_skips_worker():
    seen = []

    def check(url):
        seen.append(url)
        return google_result(matched=True)

    async def scenario():
        application = create_app(threat_check=check)

        async def forbidden(*_args):
            raise AssertionError("Known threat must not reach Worker")

        application.state.scans.worker.analyze = forbidden
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=application), base_url="http://testserver",
        ) as client:
            created = await client.post("/api/scans", json={
                "url": "https://example.test/login?context=demo", "mode": "sandbox",
            })
            assert created.status_code == 202
            report = (await client.get(f"/api/scans/{created.json()['scanId']}")).json()
            assert report["staticAnalysis"]["providers"][0]["name"] == "google_safe_browsing"
            assert report["staticAnalysis"]["providers"][0]["matched"] is True
            assert report["verdict"]["level"] == "malicious"
            assert report["verdict"]["evidenceIds"] == ["ev-google"]
            assert all("피싱" not in reason for reason in report["verdict"]["reasons"])
            assert report["sandboxAnalysis"]["skipReason"] == "known_malicious"
            assert "openphish" not in str(report).lower()
            assert seen == ["https://example.test/login?context=demo"]
    asyncio.run(scenario())
