"""
app.py — FastAPI backend for CypherCraft: The Password Guardian.

Serves the frontend and provides API endpoints for:
    - Password strength analysis
    - Breach checking (HIBP k-anonymity)
    - Secure password generation

Security: Passwords are never logged, stored, or persisted.
"""

from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Optional

from utils.entropy import analyze_password
from utils.hash_utils import check_breach
from utils.generator import generate_password

import uvicorn

# ─── App Setup ────────────────────────────────────────────────
app = FastAPI(
    title="CypherCraft: The Password Guardian",
    description="Privacy-First Password Analyzer & Generator",
    version="1.0.0"
)

# CORS for local development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount static files and templates
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")


# ─── Request Models ───────────────────────────────────────────
class AnalyzeRequest(BaseModel):
    password: str = Field(..., min_length=1, max_length=256)


class BreachCheckRequest(BaseModel):
    password: str = Field(..., min_length=1, max_length=256)


class GenerateRequest(BaseModel):
    type: str = "standard"                      # standard | pin | passphrase
    length: Optional[int] = 16                  # for standard/pin
    word_count: Optional[int] = 4               # for passphrase
    uppercase: Optional[bool] = True
    lowercase: Optional[bool] = True
    numbers: Optional[bool] = True
    symbols: Optional[bool] = True
    exclude_ambiguous: Optional[bool] = False


# ─── Routes ───────────────────────────────────────────────────
@app.get("/")
async def serve_frontend(request: Request):
    """Serve the main HTML page."""
    return templates.TemplateResponse("index.html", {"request": request})


@app.post("/api/analyze")
async def api_analyze(req: AnalyzeRequest):
    """
    Analyze password strength.
    Returns entropy, crack time, strength label, and policy checks.
    Password is processed in memory only — never logged or stored.
    """
    result = analyze_password(req.password)
    return result


@app.post("/api/breach-check")
async def api_breach_check(req: BreachCheckRequest):
    """
    Check if password has been found in known data breaches.
    Uses HIBP k-anonymity model — only first 5 chars of SHA-1 hash
    are sent externally.
    """
    result = await check_breach(req.password)
    return result


@app.post("/api/generate")
async def api_generate(req: GenerateRequest):
    """
    Generate a cryptographically secure password.
    Options: standard, PIN, or passphrase.
    """
    options = req.model_dump()
    result = generate_password(options)
    return result


# ─── Entry Point ──────────────────────────────────────────────
if __name__ == "__main__":
    uvicorn.run("app:app", host="localhost", port=8001, reload=True)
