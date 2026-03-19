"""
api/main.py
Muhafiz Community Contribution API
FastAPI backend .
"""

import hashlib
import json
import logging
import sqlite3
from datetime import datetime
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from api.validator import validate_payload
from api.moderation import process_submission

logger = logging.getLogger(__name__)

DB_PATH = Path("api/muhafiz_api.db")

app = FastAPI(
    title="Muhafiz Community API",
    description="Crowdsourced device fingerprint contribution endpoint.",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST", "HEAD"],
    allow_headers=["*"],
)

class ContributionRequest(BaseModel):
    uuid:            str
    port:            int             = Field(..., ge=1, le=65535)
    banner_snippet:  str             = Field("", max_length=120)
    device_type:     str             = Field("unknown", max_length=50)
    manufacturer:    str             = Field("unknown", max_length=100)
    risk_score:      int             = Field(..., ge=1, le=10)
    shodan_match:    bool
    client_version:  str             = Field("unknown", max_length=20)
    contributed_at:  str

@app.post("/v1/contribute")
async def contribute(request: Request, payload: ContributionRequest):
    """
    Receive a sanitised contribution from a Muhafiz client.
    Validates, rate-limits, then passes to moderation pipeline.
    """
    ip_hash = hashlib.sha256(
        request.client.host.encode()
    ).hexdigest()

    # Rate limit check  10 per hour per IP
    if _is_rate_limited(ip_hash):
        raise HTTPException(status_code=429, detail="Rate limit exceeded. Try again later.")

    # Server-side validation
    valid, reason = validate_payload(payload.dict())
    if not valid:
        raise HTTPException(status_code=422, detail=reason)
    process_submission(payload.dict(), ip_hash)

    return {"status": "accepted", "uuid": payload.uuid}


@app.get("/v1/fingerprints.json")
async def get_fingerprints(request: Request):
    """
    Returns the latest merged fingerprint database.
    Supports ETag-based caching — returns 304 if unchanged.
    """
    fp_path = Path("analysis/fingerprints.json")
    if not fp_path.exists():
        raise HTTPException(status_code=404, detail="Fingerprint database not found.")

    data    = json.loads(fp_path.read_text())
    version = data.get("meta", {}).get("version", "0.0.0")
    etag    = f'"{version}"'

    if request.headers.get("If-None-Match") == etag:
        from fastapi.responses import Response
        return Response(status_code=304)

    from fastapi.responses import JSONResponse
    return JSONResponse(
        content=data,
        headers={"ETag": etag, "Cache-Control": "public, max-age=3600"},
    )


@app.get("/v1/stats")
async def get_stats():
    """Public community stats for the website dashboard."""
    with sqlite3.connect(DB_PATH) as conn:
        row = conn.execute("""
            SELECT total_submissions, total_merged,
                   total_rejected, total_signatures,
                   unique_devices_seen, last_updated
            FROM api_stats WHERE id = 1
        """).fetchone()

    if not row:
        return {
            "total_submissions":    0,
            "total_merged":         0,
            "total_rejected":       0,
            "total_signatures":     0,
            "unique_devices_seen":  0,
            "last_updated":         None,
        }

    return {
        "total_submissions":    row[0],
        "total_merged":         row[1],
        "total_rejected":       row[2],
        "total_signatures":     row[3],
        "unique_devices_seen":  row[4],
        "last_updated":         row[5],
    }

@app.get("/v1/status/{uuid}")
async def get_status(uuid: str):
    """Check the status of a submitted contribution by UUID."""
    with sqlite3.connect(DB_PATH) as conn:
        row = conn.execute(
            "SELECT status, submitted_at, updated_at FROM submissions WHERE uuid = ?",
            (uuid,)
        ).fetchone()

    if not row:
        raise HTTPException(status_code=404, detail="Submission not found.")

    return {
        "uuid":         uuid,
        "status":       row[0],
        "submitted_at": row[1],
        "updated_at":   row[2],
    }


#rate limiting helper function

def _is_rate_limited(ip_hash: str) -> bool:
    window = datetime.utcnow().strftime("%Y-%m-%d %H:00:00")
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS rate_limits (
                ip_hash       TEXT NOT NULL,
                window_start  TEXT NOT NULL,
                request_count INTEGER NOT NULL DEFAULT 1,
                PRIMARY KEY (ip_hash, window_start)
            )
        """)
        row = conn.execute(
            "SELECT request_count FROM rate_limits WHERE ip_hash = ? AND window_start = ?",
            (ip_hash, window)
        ).fetchone()

        if row is None:
            conn.execute(
                "INSERT INTO rate_limits (ip_hash, window_start) VALUES (?, ?)",
                (ip_hash, window)
            )
            conn.commit()
            return False

        if row[0] >= 10:
            return True

        conn.execute("""
            UPDATE rate_limits SET request_count = request_count + 1
            WHERE ip_hash = ? AND window_start = ?
        """, (ip_hash, window))
        conn.commit()
        return False