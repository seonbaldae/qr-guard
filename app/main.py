"""Run with: uvicorn app.main:app --host 127.0.0.1 --port 8000 --workers 1."""

import httpx

from fastapi import BackgroundTasks, FastAPI, HTTPException
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response

from app.config import Settings, configured_origin
from app.models import ScanAccepted, ScanReport, ScanRequest
from app.service import ScanCapacityError, ScanService
from app.static_adapter import ThreatCheck


def create_app(
    settings: Settings | None = None, *, worker_transport: httpx.AsyncBaseTransport | None = None,
    threat_check: ThreatCheck | None = None,
) -> FastAPI:
    application = FastAPI(title="QR Guard", version="0.2.0")
    settings = settings or Settings.from_env()
    application.add_middleware(
        CORSMiddleware, allow_origins=[configured_origin(value) for value in settings.cors_origins],
        allow_methods=["GET", "POST"], allow_headers=["Content-Type"], allow_credentials=False,
    )
    service = ScanService(settings, worker_transport, threat_check)
    application.state.scans = service

    @application.middleware("http")
    async def private_responses(request, call_next):
        response = await call_next(request)
        if request.url.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store"
            response.headers["X-Content-Type-Options"] = "nosniff"
        return response

    @application.exception_handler(RequestValidationError)
    async def validation_error(_request, exc: RequestValidationError):
        # FastAPI's default handler echoes rejected input, possibly including credentials.
        return JSONResponse(status_code=422, content={"detail": [
            {"loc": list(error["loc"]), "msg": "Invalid request value", "type": error["type"]}
            for error in exc.errors()
        ]})

    @application.get("/api/health")
    async def health():
        return {"status": "ok"}

    @application.post("/api/scans", response_model=ScanAccepted, status_code=202)
    async def create_scan(request: ScanRequest, tasks: BackgroundTasks):
        try:
            report = service.create(request)
        except ScanCapacityError:
            raise HTTPException(status_code=503, detail="Demo scan capacity reached") from None
        tasks.add_task(service.run, report.scan_id, request)
        return ScanAccepted(scan_id=report.scan_id, mode=request.mode)

    @application.get("/api/scans/{scan_id}", response_model=ScanReport)
    async def get_scan(scan_id: str):
        if scan_id not in service.reports:
            raise HTTPException(status_code=404, detail="Scan not found")
        return service.reports[scan_id]

    @application.get("/api/scans/{scan_id}/screenshot")
    async def get_screenshot(scan_id: str):
        report = service.reports.get(scan_id)
        if report is None:
            raise HTTPException(status_code=404, detail="Scan not found")
        image = service.screenshots.get(scan_id)
        if not report.sandbox_analysis.screenshot.available or image is None:
            raise HTTPException(status_code=409, detail="Screenshot unavailable")
        return Response(content=image, media_type="image/png", headers={
            "X-Content-Type-Options": "nosniff", "Cache-Control": "no-store",
            "Content-Security-Policy": "default-src 'none'; sandbox",
        })

    return application


app = create_app()
