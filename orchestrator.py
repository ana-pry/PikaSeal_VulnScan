"""
orchestrator.py

Owns the top-level scan cycle. Day 1: stub calls only, so the flow exists
and the scheduler (Day 2) has something real to trigger. Day 3: stub calls
get swapped for the real teammate functions once those PRs land.
"""

import logging

logger = logging.getLogger(__name__)

# --- Day 1 stub imports -----------------------------------------------
# On Day 3, replace these stub functions with real imports, e.g.:
#   from scanners.discovery import discover_assets
#   from scanners.nmap_runner import run_nmap
#   from scanners.nuclei_runner import run_nuclei
#   from risk_engine.scoring import score_findings
from notifier.webhooks import send_alerts  # real as of Day 1


def discover_assets() -> list[dict]:
    """STUB — replace with real import on Day 3."""
    print("[STUB] discover_assets() called")
    return [{"ip": "10.0.0.5"}, {"ip": "10.0.0.12"}]


def run_nmap(asset: dict) -> dict:
    """STUB — replace with real import on Day 3."""
    print(f"[STUB] run_nmap({asset}) called")
    return {"asset": asset, "ports": [22, 80]}


def run_nuclei(asset: dict, nmap_result: dict) -> list[dict]:
    """STUB — replace with real import on Day 3."""
    print(f"[STUB] run_nuclei({asset}, {nmap_result}) called")
    return [{"target": asset.get("ip"), "severity": "medium", "description": "stub finding"}]


def score_findings(raw_findings: list[dict]) -> list[dict]:
    """STUB — replace with real import on Day 3."""
    print(f"[STUB] score_findings({raw_findings}) called")
    return raw_findings


def save_assets(assets: list[dict]) -> None:
    """STUB — persistence is the orchestrator's job per CONTRACTS.md."""
    print(f"[STUB] save_assets({assets}) called")


def run_scan_cycle() -> None:
    """
    Runs one full scan cycle: discover -> scan -> score -> persist -> alert.
    This is the function the scheduler calls on an interval.
    """
    logger.info("=== Starting scan cycle ===")

    try:
        assets = discover_assets()
        save_assets(assets)

        raw_findings = []
        for asset in assets:
            nmap_result = run_nmap(asset)
            nuclei_findings = run_nuclei(asset, nmap_result)
            raw_findings.extend(nuclei_findings)

        scored_findings = score_findings(raw_findings)

        send_alerts(scored_findings)

        logger.info("=== Scan cycle complete ===")

    except Exception as e:
        logger.exception(f"Scan cycle failed unexpectedly: {e}")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    run_scan_cycle()
    