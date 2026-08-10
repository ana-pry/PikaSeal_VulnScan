"""
orchestrator.py

Owns the top-level scan cycle: discover -> resolve -> scan -> score -> persist -> alert.
Integrates real teammate functions per CONTRACTS.md (frozen signatures).
"""

import logging
import os
import re
import socket
import sqlite3
from datetime import datetime, timezone

import yaml
from dotenv import load_dotenv

from scanners.discovery import discover_assets, save_assets
from scanners.port_scan import run_nmap
from scanners.vuln_scan import run_nuclei
from risk_engine.scoring import score_findings
from notifier.webhooks import send_alerts

load_dotenv()
logger = logging.getLogger(__name__)

CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d+$", re.IGNORECASE)


def _load_config(config_path: str = "config.yaml") -> dict:
    try:
        with open(config_path, "r") as f:
            return yaml.safe_load(f) or {}
    except (FileNotFoundError, yaml.YAMLError) as e:
        logger.error(f"Failed to load config: {e}")
        return {}


def _get_db_connection() -> sqlite3.Connection:
    db_path = os.environ.get("DB_PATH", "db/results.db")
    return sqlite3.connect(db_path)


def _start_scan_run(conn: sqlite3.Connection) -> int:
    cur = conn.execute(
        "INSERT INTO scan_runs (started_at, status) VALUES (?, ?)",
        (datetime.now(timezone.utc).isoformat(), "running"),
    )
    conn.commit()
    return cur.lastrowid


def _finish_scan_run(conn: sqlite3.Connection, run_id: int, status: str) -> None:
    conn.execute(
        "UPDATE scan_runs SET finished_at = ?, status = ? WHERE id = ?",
        (datetime.now(timezone.utc).isoformat(), status, run_id),
    )
    conn.commit()


def _resolve_ip(domain: str) -> str | None:
    try:
        return socket.getaddrinfo(domain, None)[0][4][0]
    except socket.gaierror as e:
        logger.warning(f"Could not resolve {domain}: {e}")
        return None


def _get_authorized_assets(conn: sqlite3.Connection) -> list[dict]:
    """
    Only authorized=1 assets are scanned. New assets from discover_assets
    default to authorized=0 and require explicit authorization before
    run_nmap/run_nuclei ever touch them.
    """
    rows = conn.execute(
        "SELECT id, domain, ip_address FROM assets WHERE authorized = 1"
    ).fetchall()

    assets = []
    for asset_id, domain, ip_address in rows:
        if not ip_address:
            ip_address = _resolve_ip(domain)
            if ip_address:
                conn.execute(
                    "UPDATE assets SET ip_address = ? WHERE id = ?",
                    (ip_address, asset_id),
                )
        if ip_address:
            assets.append({"id": asset_id, "domain": domain, "ip_address": ip_address})
        else:
            logger.warning(f"Skipping asset id={asset_id} ({domain}) - could not resolve IP.")

    conn.commit()
    return assets


def _insert_port_finding(conn: sqlite3.Connection, run_id: int, asset_id: int, port_result: dict) -> None:
    conn.execute(
        """INSERT INTO findings (run_id, asset_id, finding_type, port, service, status)
           VALUES (?, ?, 'open_port', ?, ?, 'open')""",
        (run_id, asset_id, port_result.get("port"), port_result.get("service")),
    )


def _insert_vuln_finding(conn: sqlite3.Connection, run_id: int, finding: dict) -> None:
    cve_id = finding.get("cve_id")
    finding_type = "cve" if cve_id and CVE_PATTERN.match(cve_id) else "misconfig"

    conn.execute(
        """INSERT INTO findings
           (run_id, asset_id, finding_type, cve_id, cvss_score, epss_score,
            kev_flag, risk_score, severity, description, status)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'open')""",
        (
            run_id,
            finding.get("asset_id"),
            finding_type,
            cve_id,
            finding.get("cvss_score"),
            finding.get("epss_score"),
            finding.get("kev_flag"),
            finding.get("risk_score"),
            finding.get("severity"),
            finding.get("description"),
        ),
    )


def run_scan_cycle() -> None:
    config = _load_config()
    domains = config.get("targets", {}).get("domains", [])

    conn = _get_db_connection()
    run_id = _start_scan_run(conn)
    logger.info(f"=== Starting scan cycle (run_id={run_id}) ===")

    try:
        # 1. Discovery
        all_subdomains: list[str] = []
        for domain in domains:
            subdomains = discover_assets(domain)
            all_subdomains.extend(subdomains)

        save_assets(all_subdomains, run_id)

        # 2. Load authorized assets to actually scan (with resolved IPs)
        assets = _get_authorized_assets(conn)
        if not assets:
            logger.warning("No authorized assets to scan - nothing will be scanned this cycle.")

        # 3. Port scan + vuln scan per asset
        all_raw_vuln_findings: list[dict] = []
        for asset in assets:
            port_results = run_nmap(asset)
            for port_result in port_results:
                _insert_port_finding(conn, run_id, asset["id"], port_result)
            conn.commit()

            vuln_results = run_nuclei(asset)
            for finding in vuln_results:
                finding["asset_id"] = asset["id"]
                finding["target"] = asset["domain"]  # needed by notifier._format_message
                all_raw_vuln_findings.append(finding)

        # 4. Score all vuln findings together.
        # score_findings may return fresh dicts that drop unknown keys, so we
        # re-attach asset_id + target index-wise. Safe either way: if scoring
        # preserves them, we overwrite with the same values.
        scored_findings = score_findings(all_raw_vuln_findings) if all_raw_vuln_findings else []
        for raw, scored in zip(all_raw_vuln_findings, scored_findings):
            scored["asset_id"] = raw["asset_id"]
            scored["target"] = raw["target"]

        for finding in scored_findings:
            _insert_vuln_finding(conn, run_id, finding)
        conn.commit()

        # 5. Alert (webhooks.py already filters by min_severity_to_alert internally)
        send_alerts(scored_findings)

        _finish_scan_run(conn, run_id, "completed")
        logger.info(f"=== Scan cycle complete (run_id={run_id}) ===")

    except Exception as e:
        logger.exception(f"Scan cycle failed unexpectedly: {e}")
        _finish_scan_run(conn, run_id, "failed")

    finally:
        conn.close()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    run_scan_cycle()
    