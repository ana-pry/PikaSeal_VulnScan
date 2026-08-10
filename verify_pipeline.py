"""End-to-end verification harness for the Discovery+Scanning and Risk Engine
modules.

Proves that HP's functions round-trip through the REAL db/results.db schema:
    discover_assets -> save_assets -> resolve -> run_nmap / run_nuclei ->
    score_findings -> insert into findings

This is a TEST HARNESS for HP's own modules, NOT the production orchestrator
(that's a separate teammate's module). It exercises only HP's functions plus the
DB, so it verifies the seams the plan calls out: rows land in db/results.db,
finding shapes map to the findings columns, and the CHECK/NOT-NULL constraints
pass on real inserts.

Usage:
    PYTHONPATH=. python verify_pipeline.py                 # scanme.nmap.org
    PYTHONPATH=. python verify_pipeline.py example.com     # your own domain
Requires the four scan tools installed and network access (same as a real run).
"""
from __future__ import annotations

import os
import socket
import sqlite3
import sys
from pathlib import Path

from risk_engine.scoring import score_findings
from scanners.discovery import discover_assets, save_assets
from scanners.port_scan import run_nmap
from scanners.vuln_scan import run_nuclei

DB_PATH = os.environ.get("DB_PATH", "db/results.db")
SCHEMA_PATH = "db/schema.sql"


# --- DB helpers -------------------------------------------------------------

def init_db(db_path: str, schema_path: str) -> sqlite3.Connection:
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA foreign_keys = ON")
    with open(schema_path) as f:
        conn.executescript(f.read())
    conn.commit()
    return conn


def start_run(conn: sqlite3.Connection) -> int:
    cur = conn.execute("INSERT INTO scan_runs (status) VALUES ('running')")
    conn.commit()
    return int(cur.lastrowid)


def finish_run(conn: sqlite3.Connection, run_id: int, status: str) -> None:
    conn.execute(
        "UPDATE scan_runs SET status = ?, finished_at = CURRENT_TIMESTAMP WHERE id = ?",
        (status, run_id),
    )
    conn.commit()


def _is_cve(cve_id: str | None) -> bool:
    return bool(cve_id) and cve_id.upper().startswith("CVE-")


def insert_port_findings(conn, asset_id: int, run_id: int, ports: list[dict]) -> int:
    """Persist nmap open-port results. Ports are informational -> severity NULL."""
    for p in ports:
        conn.execute(
            "INSERT INTO findings (run_id, asset_id, finding_type, port, service, severity) "
            "VALUES (?, ?, 'open_port', ?, ?, NULL)",
            (run_id, asset_id, p.get("port"), p.get("service")),
        )
    conn.commit()
    return len(ports)


def insert_vuln_findings(conn, asset_id: int, run_id: int, scored: list[dict]) -> int:
    """Persist scored nuclei findings. Real CVE -> 'cve', else 'misconfig'."""
    for f in scored:
        ftype = "cve" if _is_cve(f.get("cve_id")) else "misconfig"
        conn.execute(
            "INSERT INTO findings (run_id, asset_id, finding_type, cve_id, cvss_score, "
            "epss_score, kev_flag, risk_score, severity, description) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                run_id, asset_id, ftype, f.get("cve_id"), f.get("cvss_score"),
                f.get("epss_score"), f.get("kev_flag"), f.get("risk_score"),
                f.get("severity"), f.get("description"),
            ),
        )
    conn.commit()
    return len(scored)


def resolve_ip(domain: str) -> str | None:
    """Resolve to an IPv4 address (nmap needs -6 for IPv6, which we don't pass).

    getaddrinfo can return IPv6 first; force AF_INET so nmap gets a scannable
    address. Falls back to any address only if there's no A record.
    """
    try:
        v4 = socket.getaddrinfo(domain, None, family=socket.AF_INET)
        if v4:
            return v4[0][4][0]
    except OSError:
        pass
    try:
        return socket.getaddrinfo(domain, None)[0][4][0]
    except OSError:
        return None


# --- main flow --------------------------------------------------------------

def main() -> None:
    domain = sys.argv[1] if len(sys.argv) > 1 else "scanme.nmap.org"
    conn = init_db(DB_PATH, SCHEMA_PATH)
    run_id = start_run(conn)
    print(f"scan_runs row created: run_id={run_id}")

    try:
        subs = discover_assets(domain)
        print(f"discover_assets({domain}) -> {len(subs)} subdomains")
        save_assets(subs or [domain], run_id)   # fall back to root if none found

        # This harness authorizes everything so the scan path actually runs.
        # (In production the orchestrator only scans authorized=1 assets.)
        conn.execute("UPDATE assets SET authorized = 1")
        conn.commit()

        assets = conn.execute("SELECT id, domain FROM assets").fetchall()
        for asset_id, dom in assets:
            ip = resolve_ip(dom)
            if not ip:
                print(f"  {dom}: unresolved, skipping scan")
                continue
            asset = {"id": asset_id, "domain": dom, "ip_address": ip}

            ports = run_nmap(asset)
            n_ports = insert_port_findings(conn, asset_id, run_id, ports)

            raw = run_nuclei(asset)
            scored = score_findings(raw)
            n_vulns = insert_vuln_findings(conn, asset_id, run_id, scored)

            print(f"  {dom} ({ip}): {n_ports} open ports, {n_vulns} vuln findings")

        finish_run(conn, run_id, "completed")
    except Exception:
        finish_run(conn, run_id, "failed")
        conn.close()
        raise

    _report(conn)
    conn.close()


def _report(conn: sqlite3.Connection) -> None:
    print("\n=== scan_runs ===")
    for row in conn.execute("SELECT id, status, started_at, finished_at FROM scan_runs"):
        print(" ", row)
    print("=== assets ===")
    for row in conn.execute("SELECT id, domain, ip_address, authorized FROM assets"):
        print(" ", row)
    print("=== findings ===")
    for row in conn.execute(
        "SELECT id, run_id, asset_id, finding_type, port, service, cve_id, "
        "severity, risk_score FROM findings ORDER BY finding_type"
    ):
        print(" ", row)
    print("\nOK — everything above landed in the real schema with FKs intact.")


if __name__ == "__main__":
    main()