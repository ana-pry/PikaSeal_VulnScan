"""Offline tests for remediation.explain(). No network, no DB."""
from __future__ import annotations

from risk_engine.remediation import explain

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
    assert "Log4Shell RCE" in out["what"]   # description folded in


def test_type_fallback_when_template_unknown():
    # A template-id we haven't mapped -> falls back to finding_type guidance.
    out = explain({"finding_type": "weak_tls", "cve_id": "some-unmapped-tls-check"})
    assert "TLS" in out["title"] or "tls" in out["title"].lower()
    assert REQUIRED_KEYS <= set(out)


def test_open_port_guidance():
    out = explain({"finding_type": "open_port", "cve_id": None,
                   "port": 22, "service": "ssh"})
    assert "port" in out["title"].lower()
    assert REQUIRED_KEYS <= set(out)


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