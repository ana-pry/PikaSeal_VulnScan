"""CISA KEV catalog -> a membership set of actively-exploited CVE IDs.

KEV is a single small catalog (~1,600 entries), so we download it once and check
membership locally rather than hitting a per-CVE API (there isn't one). Source is
CISA's JSON feed; the cisagov/kev-data GitHub mirror is an equally valid source
if you'd rather pin it in the container build.

Design: load once, reuse. get_kev_set() caches in-process so scoring a batch of
findings does a single fetch, not one per finding.
"""
from __future__ import annotations

import json
import logging
import urllib.request

log = logging.getLogger("risk_engine.kev")

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

_cache: set[str] | None = None


def _fetch(url: str, timeout: float) -> str:
    with urllib.request.urlopen(url, timeout=timeout) as resp:  # noqa: S310 (trusted gov URL)
        return resp.read().decode("utf-8")


def load_kev_set(url: str = KEV_URL, timeout: float = 30) -> set[str]:
    """Fetch the KEV catalog and return the set of CVE IDs in it.

    Never raises: on any failure returns an empty set (so scoring degrades to
    'nothing is KEV-flagged' rather than crashing the cycle).
    """
    try:
        raw = _fetch(url, timeout)
        data = json.loads(raw)
        cves = {
            v["cveID"].upper()
            for v in data.get("vulnerabilities", [])
            if v.get("cveID")
        }
        log.info("KEV catalog loaded: %d CVEs", len(cves))
        return cves
    except Exception:
        log.exception("KEV load failed; treating catalog as empty")
        return set()


def get_kev_set(refresh: bool = False) -> set[str]:
    """Cached accessor. First call fetches; later calls reuse until refresh=True."""
    global _cache
    if _cache is None or refresh:
        _cache = load_kev_set()
    return _cache