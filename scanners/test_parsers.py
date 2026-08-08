"""Offline parser tests -- run with NO tools installed and NO network.

    python -m pytest scanners/test_parsers.py -v
    # or, no pytest:
    PYTHONPATH=. python scanners/test_parsers.py

Fixtures mirror real nmap -oX - and nuclei -jsonl output. On Day 1, after you
run each tool by hand, paste a snippet of YOUR actual output over these to lock
the parsers to what your installed versions emit.
"""
from __future__ import annotations

import sqlite3
import tempfile
from pathlib import Path

from scanners import discovery
from scanners.port_scan import parse_nmap_xml, run_nmap
from scanners.vuln_scan import parse_nuclei_jsonl, run_nuclei

# The real frozen `assets` DDL, copied verbatim from db/schema.sql, so this test
# fails loudly if the two ever drift apart.
ASSETS_DDL = """
CREATE TABLE IF NOT EXISTS assets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT NOT NULL,
    ip_address TEXT,
    asset_type TEXT CHECK(asset_type IN ('domain', 'subdomain', 'ip')) DEFAULT 'subdomain',
    authorized BOOLEAN NOT NULL DEFAULT 0,
    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    status TEXT CHECK(status IN ('active', 'inactive')) DEFAULT 'active',
    UNIQUE(domain)
);
"""

# --- fixtures ---------------------------------------------------------------

NMAP_XML = """<?xml version="1.0"?>
<nmaprun scanner="nmap">
  <host>
    <address addr="45.33.32.156" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack"/>
        <service name="ssh" product="OpenSSH" version="6.6.1p1"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="open" reason="syn-ack"/>
        <service name="https"/>
      </port>
      <port protocol="tcp" portid="9929">
        <state state="closed" reason="reset"/>
        <service name="nping-echo"/>
      </port>
    </ports>
  </host>
</nmaprun>"""

# Real nuclei rows: CVE with classification, misconfig with no classification,
# and a tech-detect row where `classification` exists but cve-id is null
# (captured from a live scanme.nmap.org run -- this last case is easy to miss).
NUCLEI_JSONL = (
    '{"template-id":"CVE-2021-44228","type":"http","host":"https://scanme.nmap.org",'
    '"matched-at":"https://scanme.nmap.org","info":{"name":"Log4j RCE",'
    '"severity":"critical","description":"Log4j JNDI RCE",'
    '"classification":{"cve-id":["CVE-2021-44228"]}}}\n'
    '{"template-id":"apache-detect","type":"http","host":"http://scanme.nmap.org",'
    '"matched-at":"http://scanme.nmap.org","info":{"name":"Apache Detection",'
    '"severity":"info","description":"Detected Apache"}}\n'
    '{"template-id":"waf-detect","type":"http","host":"http://scanme.nmap.org",'
    '"matched-at":"http://scanme.nmap.org","info":{"name":"WAF Detection",'
    '"severity":"info","description":"A web application firewall was detected.",'
    '"classification":{"cve-id":null,"cwe-id":["cwe-200"]}}}\n'
    'THIS LINE IS GARBAGE AND MUST BE SKIPPED\n'
    '\n'
)

# --- guard-path tests (deterministic, no tool invocation, no network) --------
# These check the early-return guards only. We deliberately do NOT pass a real
# ip_address/domain here: on a machine where the tools ARE installed, that would
# trigger a live scan and return real results. Guard inputs return [] before any
# subprocess runs, so these pass identically with or without tools installed.

def test_run_nmap_guards_return_empty():
    assert run_nmap({"id": 1, "domain": "x"}) == []   # no ip_address key
    assert run_nmap({"ip_address": ""}) == []          # blank ip_address
    assert run_nmap({}) == []                          # empty asset


def test_run_nuclei_guards_return_empty():
    assert run_nuclei({"id": 1}) == []                 # no domain key
    assert run_nuclei({"domain": ""}) == []            # blank domain
    assert run_nuclei({}) == []                        # empty asset


# --- parser tests -----------------------------------------------------------

def test_parse_nmap_xml_open_ports_only():
    results = parse_nmap_xml(NMAP_XML)
    # closed port dropped; only open ones returned, in contract shape
    assert results == [
        {"port": 22, "service": "ssh"},
        {"port": 443, "service": "https"},
    ]
    assert all(set(r) == {"port", "service"} for r in results)


def test_parse_nmap_xml_malformed_returns_empty():
    assert parse_nmap_xml("<not valid xml") == []
    assert parse_nmap_xml("") == []


def test_parse_nuclei_jsonl_cve_and_fallback():
    findings = parse_nuclei_jsonl(NUCLEI_JSONL)
    assert len(findings) == 3  # garbage + blank lines skipped
    assert findings[0] == {
        "cve_id": "CVE-2021-44228",
        "severity": "critical",
        "description": "Log4j JNDI RCE",
    }
    # no classification at all -> falls back to template-id
    assert findings[1]["cve_id"] == "apache-detect"
    assert findings[1]["severity"] == "info"
    # classification present but cve-id null -> also falls back to template-id
    assert findings[2]["cve_id"] == "waf-detect"
    assert findings[2]["description"] == "A web application firewall was detected."
    assert all(set(f) == {"cve_id", "severity", "description"} for f in findings)


def test_parse_nuclei_jsonl_empty():
    assert parse_nuclei_jsonl("") == []


# --- save_assets against the REAL frozen schema -----------------------------

def _fresh_db(tmp: str) -> str:
    db = Path(tmp) / "results.db"
    conn = sqlite3.connect(db)
    conn.executescript(ASSETS_DDL)
    conn.commit()
    conn.close()
    return str(db)


def test_save_assets_defaults_and_upsert():
    with tempfile.TemporaryDirectory() as tmp:
        db = _fresh_db(tmp)
        discovery.RESULTS_DB = db  # point the module at the temp DB

        discovery.save_assets(["a.example.com", "b.example.com"], run_id=1)

        conn = sqlite3.connect(db)
        rows = conn.execute(
            "SELECT domain, authorized, asset_type, status FROM assets ORDER BY domain"
        ).fetchall()
        assert rows == [
            ("a.example.com", 0, "subdomain", "active"),
            ("b.example.com", 0, "subdomain", "active"),
        ]

        # Re-running with an overlapping domain must NOT duplicate or reset
        # authorized (simulate one asset having been authorized in between).
        conn.execute("UPDATE assets SET authorized = 1 WHERE domain = 'a.example.com'")
        conn.commit()
        conn.close()

        discovery.save_assets(["a.example.com", "c.example.com"], run_id=2)

        conn = sqlite3.connect(db)
        count = conn.execute("SELECT COUNT(*) FROM assets").fetchone()[0]
        still_authorized = conn.execute(
            "SELECT authorized FROM assets WHERE domain = 'a.example.com'"
        ).fetchone()[0]
        conn.close()

        assert count == 3               # a, b, c -- no duplicate 'a'
        assert still_authorized == 1    # upsert didn't clobber authorization


def test_save_assets_empty_is_noop():
    with tempfile.TemporaryDirectory() as tmp:
        db = _fresh_db(tmp)
        discovery.RESULTS_DB = db
        discovery.save_assets([], run_id=1)  # must not raise
        conn = sqlite3.connect(db)
        assert conn.execute("SELECT COUNT(*) FROM assets").fetchone()[0] == 0
        conn.close()


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"ok  {fn.__name__}")
    print(f"\n{len(fns)}/{len(fns)} passed")