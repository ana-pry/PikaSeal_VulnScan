"""Risk Prioritization Engine.

Contract (frozen):
    score_findings(raw_findings: list[dict]) -> list[dict]
        Input : raw finding dicts from run_nuclei()
                {"cve_id", "severity", "description"}
        Output: same list, enriched with cvss_score, epss_score, kev_flag,
                risk_score, severity -- ready to insert into the findings table.

Model: a weighted composite of CVSS (base severity), EPSS (probability of
exploitation in the next 30 days), and KEV (confirmed active exploitation).
KEV acts as both a factor and a hard floor, since active exploitation outweighs
theoretical scores. The output `severity` is always mapped into the
findings.severity CHECK set -- ('low','medium','high','critical') -- regardless
of what nuclei emitted (this is the fix for the raw-nuclei-severity flag).

Enrichment is CVE-keyed. nuclei findings without a real CVE (misconfigs,
tech-detection -> cve_id is a template-id like 'waf-detect') can't be looked up,
so they're scored from what we have (no CVSS/EPSS/KEV) rather than dropped.
"""
from __future__ import annotations

from .cvss import get_cvss_scores
from .epss import get_epss_scores
from .kev import get_kev_set

# Composite weights (tunable). Must sum to 1.0.
W_CVSS = 0.5
W_EPSS = 0.3
W_KEV = 0.2

KEV_FLOOR = 90.0  # a KEV finding is never scored below this


def _band(risk_score: float) -> str:
    """Map a 0-100 risk score to the findings.severity CHECK set."""
    if risk_score >= 90:
        return "critical"
    if risk_score >= 70:
        return "high"
    if risk_score >= 40:
        return "medium"
    return "low"


def compute_risk(cvss: float, epss: float, kev: bool) -> float:
    """Weighted composite in 0-100, with a KEV hard floor. Pure + unit-testable."""
    score = 100.0 * (
        W_CVSS * (cvss / 10.0)   # cvss is 0-10
        + W_EPSS * epss          # epss is already 0-1
        + W_KEV * (1.0 if kev else 0.0)
    )
    if kev:
        score = max(score, KEV_FLOOR)
    return round(score, 2)


def score_findings(raw_findings: list[dict]) -> list[dict]:
    """Enrich raw nuclei findings with CVSS/EPSS/KEV and a composite risk score.

    Batches the three lookups once for all findings (not per-finding), then scores
    each. Returns a new list; input dicts are not mutated.
    """
    if not raw_findings:
        return []

    cve_ids = [f.get("cve_id", "") for f in raw_findings]
    cvss_map = get_cvss_scores(cve_ids)
    epss_map = get_epss_scores(cve_ids)
    kev_set = get_kev_set()

    enriched: list[dict] = []
    for f in raw_findings:
        cve = (f.get("cve_id") or "").upper()
        cvss = cvss_map.get(cve, 0.0)
        epss = epss_map.get(cve, 0.0)
        kev = cve in kev_set
        risk = compute_risk(cvss, epss, kev)

        enriched.append({
            **f,                       # keep cve_id, description, original severity fields
            "cvss_score": cvss,
            "epss_score": epss,
            "kev_flag": kev,
            "risk_score": risk,
            "severity": _band(risk),   # overrides raw nuclei severity -> CHECK-safe
        })
    return enriched