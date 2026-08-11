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

import logging

from .cvss import get_cvss_scores
from .epss import get_epss_scores
from .kev import get_kev_set

log = logging.getLogger("risk_engine.scoring")

# --- scoring parameters (config-driven, with defaults) ----------------------
# risk_score is on a 0-10 scale (matching CVSS and the config's risk_thresholds).
# All params live under config.yaml's `risk_thresholds` section: the critical/
# high/medium band cutoffs, plus nested `weights` and `kev_floor`. A missing or
# broken config falls back to these defaults, so scoring never depends on the
# file being present. Loaded once at import.

_DEFAULT_WEIGHTS = {"cvss": 0.5, "epss": 0.3, "kev": 0.2}
_DEFAULT_KEV_FLOOR = 9.0
_DEFAULT_BANDS = {"critical": 9.0, "high": 7.0, "medium": 4.0}


def _load_scoring_config(path: str = "config.yaml") -> dict:
    """Read the `risk_thresholds` section from config.yaml. Missing/broken -> {}."""
    try:
        import yaml
        with open(path) as f:
            return (yaml.safe_load(f) or {}).get("risk_thresholds", {}) or {}
    except FileNotFoundError:
        return {}
    except Exception:
        log.exception("could not parse %s; using default scoring params", path)
        return {}


_cfg = _load_scoring_config()
# band cutoffs are the top-level critical/high/medium keys in risk_thresholds
_bands = {**_DEFAULT_BANDS, **{k: _cfg[k] for k in ("critical", "high", "medium") if k in _cfg}}
_weights = {**_DEFAULT_WEIGHTS, **(_cfg.get("weights") or {})}

# Composite weights (should sum to 1.0).
W_CVSS = float(_weights["cvss"])
W_EPSS = float(_weights["epss"])
W_KEV = float(_weights["kev"])
KEV_FLOOR = float(_cfg.get("kev_floor", _DEFAULT_KEV_FLOOR))  # KEV never scores below this
# risk_score thresholds for each severity band (0-10 scale).
BAND_CRITICAL = float(_bands["critical"])
BAND_HIGH = float(_bands["high"])
BAND_MEDIUM = float(_bands["medium"])


def _band(risk_score: float) -> str:
    """Map a 0-10 risk score to the findings.severity CHECK set."""
    if risk_score >= BAND_CRITICAL:
        return "critical"
    if risk_score >= BAND_HIGH:
        return "high"
    if risk_score >= BAND_MEDIUM:
        return "medium"
    return "low"


def compute_risk(cvss: float, epss: float, kev: bool) -> float:
    """Weighted composite on a 0-10 scale, with a KEV hard floor. Pure + testable."""
    composite = (
        W_CVSS * (cvss / 10.0)   # cvss 0-10 -> 0-1
        + W_EPSS * epss          # epss already 0-1
        + W_KEV * (1.0 if kev else 0.0)
    )                            # composite is 0-1
    score = 10.0 * composite     # scale to 0-10
    if kev:
        score = max(score, KEV_FLOOR)
    return round(score, 2)


# Score for non-CVE findings, derived from nuclei's own template severity. This
# is the industry-standard fallback: when there's no CVE to look up CVSS/EPSS/KEV
# for (misconfigs, weak TLS, tech-detect), trust the scanner's severity rating.
# Values are chosen so _band() maps each back to the matching severity band.
_SEVERITY_SCORE = {
    "critical": 9.0,
    "high": 7.0,
    "medium": 5.0,
    "low": 3.0,
    "info": 1.0,
    "unknown": 0.0,
}


def _is_real_cve(cve_id: str) -> bool:
    return bool(cve_id) and cve_id.upper().startswith("CVE-")


def _score_non_cve(nuclei_severity: str | None) -> float:
    """Map a nuclei template severity to a 0-10 risk score."""
    sev = (nuclei_severity or "unknown").lower()
    return _SEVERITY_SCORE.get(sev, 0.0)


def score_findings(raw_findings: list[dict]) -> list[dict]:
    """Enrich raw nuclei findings with CVSS/EPSS/KEV and a composite risk score.

    Two paths:
      - Real CVE (cve_id like CVE-YYYY-N): CVSS+EPSS+KEV composite.
      - No CVE (misconfig, weak TLS, tech-detect -> cve_id is a template-id):
        fall back to nuclei's own template severity, since there's nothing to
        look up. This keeps a weak-cipher-suites finding ranked above a cosmetic
        missing-header one, instead of flooring everything to 0.

    Batches the CVE lookups once for all findings. Returns a new list; input
    dicts are not mutated.
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
        if _is_real_cve(cve):
            cvss = cvss_map.get(cve, 0.0)
            epss = epss_map.get(cve, 0.0)
            kev = cve in kev_set
            risk = compute_risk(cvss, epss, kev)
        else:
            # No CVE -> score from nuclei's own severity rating.
            cvss, epss, kev = 0.0, 0.0, False
            risk = _score_non_cve(f.get("severity"))

        enriched.append({
            **f,                       # keep cve_id, description, original severity fields
            "cvss_score": cvss,
            "epss_score": epss,
            "kev_flag": kev,
            "risk_score": risk,
            "severity": _band(risk),   # overrides raw nuclei severity -> CHECK-safe
        })
    return enriched