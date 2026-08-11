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
    """Run nuclei against asset["domain"]. Returns findings.

    Scans BOTH https:// and http:// for a bare domain, because HTTP-only hosts
    (legacy boxes, internal tools, many small-business services) would otherwise
    be skipped when we assume https. nuclei ignores whichever scheme doesn't
    respond. If the domain already carries a scheme, we use it as-is.

    Never raises. Returns [] on missing domain, tool failure, or timeout.
    """
    try:
        domain = (asset or {}).get("domain")
        if not domain:
            log.warning("run_nuclei called with no domain: %r", asset)
            return []
        if domain.startswith(("http://", "https://")):
            urls = [domain]
        else:
            urls = [f"https://{domain}", f"http://{domain}"]

        with tempfile.TemporaryDirectory() as tmp:
            targets = Path(tmp) / "targets.txt"
            targets.write_text("\n".join(urls) + "\n")
            res = run_tool(
                # DEMO ONLY: the "-tags","tech","-severity",... args make nuclei
                # emit info-level tech-detection findings so you can SEE the
                # pipeline produce rows. Remove them for production so nuclei
                # runs its full vulnerability template set.
                ["nuclei", "-l", str(targets), "-jsonl", "-silent"],
                timeout=timeout,
            )

        findings = parse_nuclei_jsonl(res.stdout)
        if not findings and not res.ok:
            log.warning("nuclei(%s) failed: %s", domain, res.reason)
        return findings
    except Exception:  # defensive: contract says never raises
        log.exception("run_nuclei crashed for asset=%r", asset)
        return []