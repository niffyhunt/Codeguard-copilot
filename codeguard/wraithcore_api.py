"""FastAPI server for WraithCore inference.

Start: uvicorn codeguard.wraithcore_api:app --host 0.0.0.0 --port 8765
"""
import json
import logging
from typing import Optional

try:
    from fastapi import FastAPI, HTTPException
    from pydantic import BaseModel
    HAVE_FASTAPI = True
except ImportError:
    HAVE_FASTAPI = False
    FastAPI = type("FastAPI", (), {"__call__": lambda s: None})

from .wraithcore import get_wraithcore, WraithCore

logger = logging.getLogger(__name__)

if HAVE_FASTAPI:
    app = FastAPI(title="WraithCore", version="1.0.0", description="Security intelligence inference")
else:
    app = None


class HoneypotRequest(BaseModel):
    src_ip: str = "0.0.0.0"
    duration: int = 0
    commands: list = []
    downloads: list = []
    login_attempts: list = []


class PhishingRequest(BaseModel):
    content: str


class CVERequest(BaseModel):
    cve_id: str
    description: str
    patch_diff: Optional[str] = ""


class AnalyzeRequest(BaseModel):
    type: str  # "honeypot", "phishing", "cve"
    data: dict


if HAVE_FASTAPI:

    @app.get("/health")
    def health():
        wc = get_wraithcore()
        return {"status": "ok" if wc.is_ready() else "loading", "model": "wraithcore-7b"}

    @app.post("/wraithcore/analyze")
    def analyze(req: AnalyzeRequest):
        wc = get_wraithcore()
        if not wc.is_ready():
            raise HTTPException(status_code=503, detail="Model not loaded")

        if req.type == "honeypot":
            return wc.classify_attacker(req.data)
        elif req.type == "phishing":
            content = req.data.get("content", req.data.get("url", ""))
            return wc.detect_phishing(content)
        elif req.type == "cve":
            cve_id = req.data.get("cve_id", req.data.get("id", "CVE-XXXX"))
            desc = req.data.get("description", req.data.get("desc", ""))
            patch = req.data.get("patch_diff", "")
            return wc.score_cve(cve_id, desc, patch)
        else:
            raise HTTPException(status_code=400, detail=f"Unknown type: {req.type}")

    @app.post("/wraithcore/classify-attacker")
    def classify_attacker(req: HoneypotRequest):
        wc = get_wraithcore()
        if not wc.is_ready():
            raise HTTPException(status_code=503, detail="Model not loaded")
        return wc.classify_attacker(req.model_dump())

    @app.post("/wraithcore/detect-phishing")
    def detect_phishing(req: PhishingRequest):
        wc = get_wraithcore()
        if not wc.is_ready():
            raise HTTPException(status_code=503, detail="Model not loaded")
        return wc.detect_phishing(req.content)

    @app.post("/wraithcore/score-cve")
    def score_cve(req: CVERequest):
        wc = get_wraithcore()
        if not wc.is_ready():
            raise HTTPException(status_code=503, detail="Model not loaded")
        return wc.score_cve(req.cve_id, req.description, req.patch_diff)


def serve(host="0.0.0.0", port=8765):
    """Start the FastAPI server."""
    import uvicorn
    uvicorn.run("codeguard.wraithcore_api:app", host=host, port=port, reload=False)
