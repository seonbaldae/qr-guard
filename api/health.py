"""Same-origin GET /api/health on Vercel."""
from app.public_api import create_public_app
from fastapi import FastAPI

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
app.mount("/", create_public_app())
