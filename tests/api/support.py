"""Explicit threat-check test doubles. They never invoke Google or read keys."""

from datetime import datetime, timezone
import base64
import json
import inspect
import httpx

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


def jobs_fixture_transport(handler):
    """Migrate the existing flat test DATA to v0.3 jobs fixtures (not a production fallback).

    The original handler still controls faults; each test now exercises POST acknowledgement,
    separate GET result and binary PNG. No brand inference is fabricated by this fixture.
    """
    jobs = {}
    async def wire(request):
        if request.method == 'POST':
            response = handler(request)
            if inspect.isawaitable(response):
                response = await response
            if response.status_code != 200:
                return response
            try:
                payload = json.loads(response.content)
            except (ValueError, httpx.ResponseNotRead):
                return response
            body = json.loads(request.content)
            scan_id = body['scanId']
            at = datetime.now(timezone.utc).isoformat()
            final = payload.get('finalUrl')
            jobs[scan_id] = (payload, {'scanId':scan_id,'status':'completed','acceptedAt':at,'capturedAt':at,
                'screenshotStatus':'ready','finalUrl':final,'httpStatus':payload.get('httpStatus'),
                'domAnalysis':{key:payload.get(key) for key in ['pageTitle','passwordFieldCount','sensitiveFieldTypes','forms']},
                'networkAnalysis':{'requestHosts':payload.get('requestHosts',[]),'requestCount':len(payload.get('requestHosts',[])),'blockedRequestCount':0},
                'redirectAnalysis':{'redirected':payload.get('redirected',False),'finalUrl':final,'redirectChain':[]},
                'limitations':payload.get('limitations',[]),'signals':[],'evidence':[],'errorCode':None})
            return httpx.Response(202,json={'scanId':scan_id,'status':'queued','acceptedAt':at})
        scan_id = request.url.path.split('/')[3]
        payload, job = jobs[scan_id]
        if request.url.path.endswith('/screenshot'):
            try:
                png = base64.b64decode(payload.get('screenshotBase64',''),validate=True)
            except ValueError:
                png = b'invalid'
            return httpx.Response(200,content=png,headers={'content-type':'image/png'})
        return httpx.Response(200,json=job)
    return httpx.MockTransport(wire)
