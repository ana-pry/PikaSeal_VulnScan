"""Offline tests for remediation.explain(). No network, no DB."""
from __future__ import annotations

from risk_engine.remediation import explain, get_guidance

REQUIRED_KEYS = {"title", "what", "how", "references"}


def test_specific_template_match():
    out = explain({"finding_type": "misconfig", "cve_id": "weak-cipher-suites"})
    assert "cipher" in out["title"].lower()
    assert out["how"]                       # non-empty fix guidance
    assert REQUIRED_KEYS <= set(out)


def test_real_cve_gets_nvd_link():
    out = explain({"finding_type": "cve", "cve_id": "CVE-2021-44228",
                   "description": "Log4Shell RCE"})
    assert "CVE-2021-44228" in out["title"]
    assert any("nvd.nist.gov" in r for r in out["references"])
    # Description is shown on its own line by the UI, so it must NOT be folded
    # into `what` (doing so rendered the same text twice on the dashboard).
    assert "Log4Shell RCE" not in out["what"]
    assert out["what"]                      # still non-empty plain-language "why"


def test_type_fallback_when_template_unknown():
    # A template-id we haven't mapped -> falls back to finding_type guidance.
    out = explain({"finding_type": "weak_tls", "cve_id": "some-unmapped-tls-check"})
    assert "TLS" in out["title"] or "tls" in out["title"].lower()
    assert REQUIRED_KEYS <= set(out)


def test_open_port_service_specific():
    # A known service gets tailored, service-aware guidance (not the generic one).
    out = explain({"finding_type": "open_port", "cve_id": None,
                   "port": 23, "service": "telnet"})
    assert "telnet" in out["title"].lower()
    assert "SSH" in out["how"]               # telnet -> use SSH
    assert REQUIRED_KEYS <= set(out)


def test_open_port_unknown_service_falls_back():
    # An unmapped service still returns the generic open-port guidance.
    out = explain({"finding_type": "open_port", "cve_id": None,
                   "port": 8080, "service": "http-proxy"})
    assert out["what"] and out["how"]
    assert REQUIRED_KEYS <= set(out)


def test_cve_kev_flag_escalates():
    # A known-exploited CVE reads as urgent and keeps its NVD link.
    kev = explain({"finding_type": "cve", "cve_id": "CVE-2021-44228", "kev_flag": 1})
    plain = explain({"finding_type": "cve", "cve_id": "CVE-2021-44228", "kev_flag": 0})
    assert "exploit" in kev["what"].lower()
    assert kev["what"] != plain["what"]
    assert any("nvd.nist.gov" in r for r in kev["references"])


def test_get_guidance_projects_to_why_fix():
    # The dashboard wrapper mirrors explain()'s what/how.
    finding = {"finding_type": "open_port", "service": "telnet"}
    g = get_guidance(finding)
    full = explain(finding)
    assert set(g) == {"why", "fix"}
    assert g["why"] == full["what"] and g["fix"] == full["how"]


def test_generic_fallback_never_empty():
    # Totally unknown shape still returns usable guidance.
    out = explain({})
    assert REQUIRED_KEYS <= set(out)
    assert out["what"] and out["how"]


def test_all_entries_have_required_keys():
    from risk_engine.remediation import _TEMPLATE_GUIDANCE, _TYPE_GUIDANCE, _GENERIC
    for entry in (*_TEMPLATE_GUIDANCE.values(), *_TYPE_GUIDANCE.values(), _GENERIC):
        assert REQUIRED_KEYS <= set(entry), f"entry missing keys: {entry}"


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"ok  {fn.__name__}")
    print(f"\n{len(fns)}/{len(fns)} passed")