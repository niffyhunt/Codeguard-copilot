"""CodeGuard — Raven Intelligence Bridge (Python).
Optional enrichment of findings with attacker intelligence from WraithWall/Raven API."""
import os
import json
import logging
from urllib.request import Request, urlopen
from urllib.error import URLError

logger = logging.getLogger(__name__)

RAVEN_API_URL = os.getenv("RAVEN_API_URL", "https://wraithwall.online/api/raven")


def is_configured():
    return bool(os.getenv("RAVEN_API_KEY"))


def enrich_finding(finding_dict):
    """Enrich a single finding with Raven intelligence signals.
    Requires RAVEN_API_KEY and RAVEN_API_URL set as env vars."""
    api_key = os.getenv("RAVEN_API_KEY", "")
    if not api_key:
        return finding_dict

    try:
        finding_id = finding_dict.get("rule_id", "")
        req = Request(
            f"{RAVEN_API_URL}/intel/attacker/summary",
            headers={"X-Requested-With": "XMLHttpRequest", "X-API-Key": api_key},
        )
        with urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read())
            finding_dict["raven"] = {
                "attacker_aligned": data.get("attacker_aligned", 0) > 0,
                "deception_correlated": data.get("deception_correlated", 0) > 0,
                "source": "raven",
            }
    except Exception as e:
        logger.debug(f"Raven enrichment skipped: {e}")

    return finding_dict


def enrich_findings(findings):
    """Enrich multiple findings with Raven context if configured."""
    if not is_configured():
        return findings
    return [enrich_finding(f.to_dict()) for f in findings]


def get_raven_summary():
    """Fetch Raven intelligence summary for dashboard/doctor display."""
    api_key = os.getenv("RAVEN_API_KEY", "")
    if not api_key:
        return {"status": "not_configured"}
    try:
        req = Request(
            f"{RAVEN_API_URL}/intel/overview",
            headers={"X-Requested-With": "XMLHttpRequest", "X-API-Key": api_key},
        )
        with urlopen(req, timeout=5) as resp:
            return json.loads(resp.read())
    except Exception as e:
        return {"status": "unreachable", "error": str(e)[:100]}
