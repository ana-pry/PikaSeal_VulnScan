"""Vuln scanning: run_nuclei(asset) -> [{"cve_id", "severity", "description"}].

Contract (frozen):
    run_nuclei(asset: dict) -> list[dict]
        asset: {"id": int, "domain": str, "ip_address": str}
        returns: [{"cve_id": "CVE-2023-1234", "severity": "high",
                   "description": "..."}]
        empty list on no results / timeout; NEVER raises.

Output feeds risk_engine.score_findings(), which enriches each dict with
cvss/epss/kev/risk_score. Enrichment is CVE-keyed, so cve_id matters:
we take info.classification.cve-id when present, else fall back to the
template-id as the identifier so nothing is silently unattributable.

parse_nuclei_jsonl() is separate from the subprocess call for offline testing.
"""
from __future__ import annotations

import json
import logging
import tempfile
from pathlib import Path

from .runner import run_tool

log = logging.getLogger("scanners.vuln_scan")


def _extract_cve(obj: dict, info: dict) -> str:
    classification = info.get("classification") or {}
    cve = classification.get("cve-id")
    if isinstance(cve, list) and cve:
        return str(cve[0]).upper()
    if isinstance(cve, str) and cve:
        return cve.upper()
    # Fall back to template-id so risk_engine still has a stable key.
    return obj.get("template-id", obj.get("templateID", ""))


def parse_nuclei_jsonl(text: str) -> list[dict]:
    """Parse nuclei JSONL into contract dicts. Bad lines are skipped, not fatal."""
    findings: list[dict] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(obj, dict):
            continue
        info = obj.get("info") or {}
        findings.append({
            "cve_id": _extract_cve(obj, info),
            "severity": (info.get("severity") or "unknown").lower(),
            "description": info.get("description") or info.get("name") or "",
        })
    return findings


def run_nuclei(asset: dict, timeout: float = 900) -> list[dict]:
    """Run nuclei against asset["domain"] as an https URL. Returns findings.

    Never raises. Returns [] on missing domain, tool failure, or timeout.
    FLAG: older nuclei used `-json`; current uses `-jsonl`. Confirm on Day 1.
    """
    try:
        domain = (asset or {}).get("domain")
        if not domain:
            log.warning("run_nuclei called with no domain: %r", asset)
            return []
        url = domain if domain.startswith(("http://", "https://")) else f"https://{domain}"

        with tempfile.TemporaryDirectory() as tmp:
            targets = Path(tmp) / "targets.txt"
            targets.write_text(url + "\n")
            res = run_tool(
                ["nuclei", "-l", str(targets), "-jsonl", "-silent"],
                timeout=timeout,
            )

        findings = parse_nuclei_jsonl(res.stdout)
        if not findings and not res.ok:
            log.warning("nuclei(%s) failed: %s", url, res.reason)
        return findings
    except Exception:  # defensive: contract says never raises
        log.exception("run_nuclei crashed for asset=%r", asset)
        return []
