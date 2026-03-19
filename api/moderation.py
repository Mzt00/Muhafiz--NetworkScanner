"""
api/moderation.py
Three-tier moderation pipeline:
  Tier 1 — AUTO-MERGE:     port+banner seen >= 5 times with matching device_type
  Tier 2 — CONFIDENCE QUEUE: new/partial match, needs 3 submissions before auto-merge
  Tier 3 — MAINTAINER REVIEW: unknown banner, opens GitHub Issue via API
"""

import json
import logging
import os
import sqlite3
from datetime import datetime
from pathlib import Path

import requests

logger = logging.getLogger(__name__)

DB_PATH              = Path("api/muhafiz_api.db")
AUTO_MERGE_THRESHOLD = 5    # submissions needed for auto-merge
QUEUE_THRESHOLD      = 3    # submissions needed to escalate from queue to auto-merge
GITHUB_TOKEN         = os.getenv("GITHUB_TOKEN", "")
GITHUB_REPO          = os.getenv("GITHUB_REPO", "Mzt00/Muhafiz--NetworkScanner")


def process_submission(data: dict, ip_hash: str):
    """
    Main moderation entry point.
    Saves submission, checks confidence queue,
    and routes to the appropriate tier.
    """
    _save_submission(data, ip_hash)
    _update_stats("total_submissions")

    port       = data["port"]
    banner_key = data.get("banner_snippet", "").lower().strip()
    device_type = data.get("device_type", "unknown")
    manufacturer = data.get("manufacturer", "unknown")
    risk_score  = data.get("risk_score", 5)

    existing = _get_queue_entry(port, banner_key)

    if existing is None:
        
        count = _add_to_queue(port, banner_key, device_type, manufacturer, risk_score)
        logger.info(f"New queue entry: port {port} | '{banner_key[:40]}' (count: {count})")

    else:
        count = _increment_queue(port, banner_key, risk_score)
        logger.info(f"Queue entry updated: port {port} | count now {count}")

        # Tier 1 Auto-merge
        if count >= AUTO_MERGE_THRESHOLD and existing["status"] == "queued":
            _auto_merge(port, banner_key, device_type, manufacturer, risk_score)
            logger.info(f"AUTO-MERGE: port {port} | '{banner_key[:40]}'")

        # Tier 3 Maintainer review
        elif count >= QUEUE_THRESHOLD and existing["status"] == "queued":
            _open_github_issue(existing["id"], port, banner_key, device_type, manufacturer, risk_score, count)
            _update_queue_status(port, banner_key, "pending_review")
            logger.info(f"MAINTAINER REVIEW: opened issue for port {port}")



def _auto_merge(port, banner_key, device_type, manufacturer, risk_score):
    """Merge the signature directly into the fingerprints table."""
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            INSERT OR IGNORE INTO fingerprints
            (port, banner_contains, device_type, manufacturer,
             risk_base, source, merged_by)
            VALUES (?, ?, ?, ?, ?, 'community', 'auto')
        """, (port, json.dumps([banner_key]), device_type, manufacturer, risk_score))
        conn.commit()

    _update_queue_status(port, banner_key, "auto_merged")
    _update_stats("total_merged")
    _update_stats("total_signatures")
    _rebuild_fingerprints_json()


def _open_github_issue(queue_id, port, banner_key, device_type, manufacturer, risk_score, count):
    """
    Open a GitHub Issue via the GitHub API for maintainer review.
    Triggered when a submission hits the QUEUE_THRESHOLD.
    """
    if not GITHUB_TOKEN:
        logger.warning("GITHUB_TOKEN not set — cannot open issue.")
        return

    title = f"[Sig candidate] Port {port} — {device_type} ({manufacturer})"
    body  = f"""## New signature candidate

A submission has reached the maintainer review threshold.

| Field | Value |
|---|---|
| Port | `{port}` |
| Banner snippet | `{banner_key[:80]}` |
| Device type guess | `{device_type}` |
| Manufacturer guess | `{manufacturer}` |
| Risk score | `{risk_score}` |
| Submission count | `{count}` |

## Action required

If this looks correct, add it to `analysis/fingerprints.json` and label this issue `sig-candidate` to trigger an automatic release.

If it looks wrong or malicious, close this issue and label it `sig-rejected`.
"""

    try:
        response = requests.post(
            f"https://api.github.com/repos/{GITHUB_REPO}/issues",
            json={"title": title, "body": body, "labels": ["sig-candidate"]},
            headers={
                "Authorization": f"Bearer {GITHUB_TOKEN}",
                "Accept": "application/vnd.github+json",
            },
            timeout=10,
        )

        if response.status_code == 201:
            issue = response.json()
            _save_issue(queue_id, issue["number"], issue["html_url"])
            logger.info(f"GitHub issue #{issue['number']} opened: {issue['html_url']}")
        else:
            logger.warning(f"GitHub API returned {response.status_code}: {response.text}")

    except Exception as e:
        logger.warning(f"Failed to open GitHub issue: {e}")

def _rebuild_fingerprints_json():
    """
    Rebuild analysis/fingerprints.json from the merged
    fingerprints table after each auto-merge.
    """
    with sqlite3.connect(DB_PATH) as conn:
        rows = conn.execute("""
            SELECT port, banner_contains, device_type,
                   manufacturer, risk_base, notes
            FROM fingerprints
            ORDER BY port
        """).fetchall()

    signatures = []
    for row in rows:
        signatures.append({
            "port":            row[0],
            "banner_contains": json.loads(row[1]),
            "device_type":     row[2],
            "manufacturer":    row[3],
            "risk_base":       row[4],
            "notes":           row[5] or "",
        })

    data = {
        "meta": {
            "version":          _bump_version(),
            "total_signatures": len(signatures),
            "updated_at":       datetime.utcnow().isoformat() + "Z",
            "description":      "Muhafiz community device fingerprint database",
        },
        "signatures": signatures,
    }

    Path("analysis/fingerprints.json").write_text(json.dumps(data, indent=2))
    logger.info(f"fingerprints.json rebuilt — {len(signatures)} signatures")


def _save_submission(data: dict, ip_hash: str):
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            INSERT OR IGNORE INTO submissions
            (uuid, port, banner_snippet, device_type, manufacturer,
             risk_score, shodan_match, client_version, ip_hash)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            data["uuid"], data["port"], data.get("banner_snippet", ""),
            data.get("device_type", "unknown"), data.get("manufacturer", "unknown"),
            data.get("risk_score", 5), 1 if data.get("shodan_match") else 0,
            data.get("client_version", "unknown"), ip_hash,
        ))
        conn.commit()


def _get_queue_entry(port: int, banner_key: str):
    with sqlite3.connect(DB_PATH) as conn:
        row = conn.execute("""
            SELECT id, port, banner_key, device_type, manufacturer,
                   risk_score_avg, submission_count, status
            FROM confidence_queue
            WHERE port = ? AND banner_key = ?
        """, (port, banner_key)).fetchone()
    if not row:
        return None
    return {
        "id": row[0], "port": row[1], "banner_key": row[2],
        "device_type": row[3], "manufacturer": row[4],
        "risk_score_avg": row[5], "submission_count": row[6], "status": row[7],
    }


def _add_to_queue(port, banner_key, device_type, manufacturer, risk_score) -> int:
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            INSERT OR IGNORE INTO confidence_queue
            (port, banner_key, device_type, manufacturer, risk_score_avg, submission_count)
            VALUES (?, ?, ?, ?, ?, 1)
        """, (port, banner_key, device_type, manufacturer, risk_score))
        conn.commit()
    return 1


def _increment_queue(port, banner_key, risk_score) -> int:
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            UPDATE confidence_queue
            SET submission_count = submission_count + 1,
                risk_score_avg   = (risk_score_avg + ?) / 2,
                last_seen        = datetime('now')
            WHERE port = ? AND banner_key = ?
        """, (risk_score, port, banner_key))
        conn.commit()
        row = conn.execute(
            "SELECT submission_count FROM confidence_queue WHERE port = ? AND banner_key = ?",
            (port, banner_key)
        ).fetchone()
    return row[0] if row else 0


def _update_queue_status(port, banner_key, status):
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            UPDATE confidence_queue SET status = ?, updated_at = datetime('now')
            WHERE port = ? AND banner_key = ?
        """, (status, port, banner_key))
        conn.commit()


def _save_issue(queue_id, issue_number, issue_url):
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            INSERT OR IGNORE INTO github_issues
            (queue_id, issue_number, issue_url)
            VALUES (?, ?, ?)
        """, (queue_id, issue_number, issue_url))
        conn.commit()


def _update_stats(field: str):
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(f"""
            UPDATE api_stats SET {field} = {field} + 1,
            last_updated = datetime('now') WHERE id = 1
        """)
        conn.commit()


def _bump_version() -> str:
    fp = Path("analysis/fingerprints.json")
    try:
        data  = json.loads(fp.read_text())
        parts = data["meta"]["version"].split(".")
        parts[2] = str(int(parts[2]) + 1)
        return ".".join(parts)
    except Exception:
        return "0.1.0"