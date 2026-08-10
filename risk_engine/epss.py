"""EPSS scores via the FIRST.org batch API.

A scan yields few CVEs, so we ask for all of them in ONE request
(?cve=CVE-1,CVE-2,...) rather than downloading the 240k-row daily CSV. Returns
a {cve_id: epss_probability} map. FIRST's API is free, no key, sub-second.

If you ever need zero network at scan time, swap this for the daily CSV cache
(https://epss.empiricalsecurity.com/epss_scores-YYYY-MM-DD.csv.gz) behind the
same get_epss_scores() signature.
"""
from __future__ import annotations

import json
import logging
import urllib.parse
import urllib.request

log = logging.getLogger("risk_engine.epss")

EPSS_API = "https://api.first.org/data/v1/epss"


def get_epss_scores(cve_ids: list[str], timeout: float = 30) -> dict[str, float]:
    """Return {cve_id: epss_score} for the given CVEs (only real CVE IDs).

    Never raises: on failure returns {} and callers treat missing scores as 0.0.
    Non-CVE identifiers (e.g. nuclei template-ids like 'waf-detect') are filtered
    out before the request, since EPSS only knows CVEs.
    """
    cves = sorted({c.upper() for c in cve_ids if c and c.upper().startswith("CVE-")})
    if not cves:
        return {}
    try:
        query = urllib.parse.urlencode({"cve": ",".join(cves)})
        with urllib.request.urlopen(f"{EPSS_API}?{query}", timeout=timeout) as resp:  # noqa: S310
            payload = json.loads(resp.read().decode("utf-8"))
        scores = {
            row["cve"].upper(): float(row["epss"])
            for row in payload.get("data", [])
            if row.get("cve") and row.get("epss") is not None
        }
        log.info("EPSS: got %d/%d scores", len(scores), len(cves))
        return scores
    except Exception:
        log.exception("EPSS lookup failed; treating all scores as 0.0")
        return {}