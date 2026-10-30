"""Bound active Worker calls while retaining the public asynchronous scan API."""

import asyncio
import base64
from io import BytesIO

import httpx
from PIL import Image

from app.config import Settings
from app.main import create_app
from app.worker import WorkerResult


def test_worker_concurrency_is_bounded():
    async def scenario():
        application = create_app(Settings(max_worker_concurrency=1))
        image = BytesIO()
        Image.new("RGB", (1, 1)).save(image, format="PNG")
        result = WorkerResult.model_validate({
            "finalUrl": "https://demo.example.test/", "httpStatus": 200, "pageTitle": "Demo",
            "passwordFieldCount": 0, "sensitiveFieldTypes": [], "forms": [], "requestHosts": [],
            "redirected": False, "screenshotBase64": base64.b64encode(image.getvalue()).decode(),
            "limitations": [],
        })
        active = peak = calls = 0

        async def slow_worker(*_args):
            nonlocal active, peak, calls
            calls += 1
            active += 1
            peak = max(peak, active)
            try:
                await asyncio.sleep(0.02)
                return result, image.getvalue()
            finally:
                active -= 1

        application.state.scans.worker.analyze = slow_worker
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=application), base_url="http://testserver",
        ) as client:
            responses = await asyncio.gather(*[
                client.post("/api/scans", json={"url": "https://demo.example.test/", "mode": "sandbox"})
                for _ in range(3)
            ])
            assert all(response.status_code == 202 for response in responses)
            assert calls == 3
            assert peak == 1
            assert active == 0
    asyncio.run(scenario())
