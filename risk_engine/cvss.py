"""CVSS base scores via the NVD API, with an in-process cache.

NVD is rate-limited (roughly 5 requests / 30s without an API key, more with a
free key), so we cache per CVE and query one at a time. For the handful of CVEs
in a typical scan this is fine; if volume grows, add an NVD_API_KEY env var and
the higher rate limit, or batch by CPE.

Returns a {cve_id: cvss_base_score} map. Non-CVE ids are skipped.
"""
from __future__ import annotations

import json
import logging
import os
import time
import urllib.request

log = logging.getLogger("risk_engine.cvss")

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY = os.environ.get("NVD_API_KEY")  # optional; raises the rate limit

_cache: dict[str, float | None] = {}


def _extract_base_score(cve_item: dict) -> float | None:
    """Pull a CVSS base score from an NVD CVE record, preferring v3.x over v2."""
    metrics = cve_item.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key)
        if entries:
            try:
                return float(entries[0]["cvssData"]["baseScore"])
            except (KeyError, IndexError, ValueError, TypeError):
                continue
    return None


def _fetch_one(cve_id: str, timeout: float) -> float | None:
    req = urllib.request.Request(f"{NVD_API}?cveId={cve_id}")
    if NVD_API_KEY:
        req.add_header("apiKey", NVD_API_KEY)
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
        payload = json.loads(resp.read().decode("utf-8"))
    vulns = payload.get("vulnerabilities", [])
    if not vulns:
        return None
    return _extract_base_score(vulns[0].get("cve", {}))


def get_cvss_scores(cve_ids: list[str], timeout: float = 30) -> dict[str, float]:
    """Return {cve_id: cvss_base_score} for real CVEs. Never raises.

    Missing/unknown CVEs simply don't appear in the result; callers default to
    0.0. Results are cached in-process so repeated CVEs cost one request total.
    """
    cves = sorted({c.upper() for c in cve_ids if c and c.upper().startswith("CVE-")})
    out: dict[str, float] = {}
    for cve in cves:
        if cve not in _cache:
            try:
                _cache[cve] = _fetch_one(cve, timeout)
            except Exception:
                log.exception("NVD lookup failed for %s; treating CVSS as unknown", cve)
                _cache[cve] = None
            # be polite to NVD's rate limit when we actually hit the network
            time.sleep(0.6 if NVD_API_KEY else 6.0)
        if _cache[cve] is not None:
            out[cve] = _cache[cve]
    return out