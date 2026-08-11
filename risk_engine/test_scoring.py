"""Offline tests for the scoring model.

    PYTHONPATH=. python risk_engine/test_scoring.py
    # or: python -m pytest risk_engine/test_scoring.py -v

The pure compute_risk() / _band() logic is tested directly (no network). The
score_findings() end-to-end test monkeypatches the three data-source lookups so
it runs fully offline and deterministically -- the same decoupling used in the
scanner's test suite. Swap in real fixtures once you've done a live run.
"""
from __future__ import annotations

from risk_engine import scoring
from risk_engine.scoring import _band, compute_risk, score_findings

# --- pure scoring logic -----------------------------------------------------

def test_band_boundaries():
    assert _band(9.5) == "critical"
    assert _band(9.0) == "critical"
    assert _band(8.9) == "high"
    assert _band(7.0) == "high"
    assert _band(4.0) == "medium"
    assert _band(3.9) == "low"
    assert _band(0) == "low"


def test_compute_risk_kev_floor():
    # A low-CVSS, low-EPSS finding that IS in KEV must still land critical,
    # because active exploitation overrides theoretical scores.
    assert compute_risk(cvss=2.0, epss=0.01, kev=True) >= 9.0
    assert _band(compute_risk(2.0, 0.01, True)) == "critical"


def test_compute_risk_ordering():
    # More CVSS / EPSS / KEV should never decrease the score.
    low = compute_risk(3.0, 0.05, False)
    mid = compute_risk(7.0, 0.05, False)
    hi = compute_risk(7.0, 0.80, False)
    assert low < mid < hi


def test_compute_risk_all_zero():
    assert compute_risk(0.0, 0.0, False) == 0.0


# --- score_findings end-to-end (lookups stubbed -> fully offline) -----------

def test_score_findings_offline(monkeypatch):
    # Stub the three network lookups with fixed data.
    monkeypatch.setattr(scoring, "get_cvss_scores",
                        lambda ids: {"CVE-2021-44228": 10.0})
    monkeypatch.setattr(scoring, "get_epss_scores",
                        lambda ids: {"CVE-2021-44228": 0.97})
    monkeypatch.setattr(scoring, "get_kev_set",
                        lambda: {"CVE-2021-44228"})

    raw = [
        {"cve_id": "CVE-2021-44228", "severity": "critical", "description": "Log4Shell"},
        {"cve_id": "waf-detect",     "severity": "info",     "description": "WAF detected"},
    ]
    out = score_findings(raw)

    # CVE finding: fully enriched, KEV-flagged, critical.
    log4j = out[0]
    assert log4j["cvss_score"] == 10.0
    assert log4j["epss_score"] == 0.97
    assert log4j["kev_flag"] is True
    assert log4j["severity"] == "critical"
    assert log4j["description"] == "Log4Shell"   # original fields preserved

    # non-CVE 'info' finding: no CVE lookup, scored from nuclei severity (info->low).
    waf = out[1]
    assert waf["cvss_score"] == 0.0
    assert waf["epss_score"] == 0.0
    assert waf["kev_flag"] is False
    assert waf["severity"] == "low"

    # every output severity is inside the schema CHECK set.
    allowed = {"low", "medium", "high", "critical"}
    assert all(f["severity"] in allowed for f in out)
    # every output row has the full enriched shape.
    required = {"cve_id", "description", "cvss_score", "epss_score",
                "kev_flag", "risk_score", "severity"}
    assert all(required <= set(f) for f in out)


def test_non_cve_findings_ranked_by_nuclei_severity(monkeypatch):
    # No network needed: none of these are real CVEs, so no lookups fire.
    monkeypatch.setattr(scoring, "get_cvss_scores", lambda ids: {})
    monkeypatch.setattr(scoring, "get_epss_scores", lambda ids: {})
    monkeypatch.setattr(scoring, "get_kev_set", lambda: set())

    raw = [
        {"cve_id": "weak-cipher-suites",  "severity": "medium", "description": "Weak TLS ciphers"},
        {"cve_id": "http-missing-headers", "severity": "info",   "description": "Missing headers"},
        {"cve_id": "some-high-misconfig",  "severity": "high",   "description": "Serious misconfig"},
    ]
    out = {f["cve_id"]: f for f in score_findings(raw)}

    # A weak-TLS medium finding must NOT rank the same as a cosmetic info one.
    assert out["weak-cipher-suites"]["severity"] == "medium"
    assert out["http-missing-headers"]["severity"] == "low"
    assert out["some-high-misconfig"]["severity"] == "high"
    # and the scores order correctly
    assert (out["some-high-misconfig"]["risk_score"]
            > out["weak-cipher-suites"]["risk_score"]
            > out["http-missing-headers"]["risk_score"])


def test_score_findings_empty():
    assert score_findings([]) == []


# --- minimal runner so it works without pytest ------------------------------

class _MP:
    """Tiny monkeypatch stand-in so this file runs with plain python too."""
    def __init__(self): self._undo = []
    def setattr(self, obj, name, val):
        self._undo.append((obj, name, getattr(obj, name)))
        setattr(obj, name, val)
    def undo(self):
        for obj, name, val in reversed(self._undo):
            setattr(obj, name, val)


if __name__ == "__main__":
    import inspect
    passed = 0
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        if "monkeypatch" in inspect.signature(fn).parameters:
            mp = _MP()
            try:
                fn(mp)
            finally:
                mp.undo()
        else:
            fn()
        print(f"ok  {fn.__name__}")
        passed += 1
    print(f"\n{passed}/{len(fns)} passed")