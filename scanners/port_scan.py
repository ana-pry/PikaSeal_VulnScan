"""Port scanning: run_nmap(asset) -> [{"port": int, "service": str}, ...].

Contract (frozen):
    run_nmap(asset: dict) -> list[dict]
        asset: {"id": int, "domain": str, "ip_address": str}
        returns: [{"port": 443, "service": "https"}, ...]
        empty list on no results / timeout; NEVER raises.

parse_nmap_xml() is kept separate from the subprocess call so it's unit-testable
offline against fixture XML with no nmap installed.
"""
from __future__ import annotations

import logging
import xml.etree.ElementTree as ET

from .runner import run_tool

log = logging.getLogger("scanners.port_scan")


def parse_nmap_xml(xml_text: str) -> list[dict]:
    """Parse nmap XML (from `-oX -`) into [{"port", "service"}] for OPEN ports.

    Malformed XML -> [] (handles the malformed-XML edge case without crashing).
    """
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        log.warning("nmap returned unparseable XML")
        return []

    results: list[dict] = []
    for host_el in root.findall("host"):
        ports_el = host_el.find("ports")
        if ports_el is None:
            continue
        for port_el in ports_el.findall("port"):
            state_el = port_el.find("state")
            if state_el is None or state_el.get("state") != "open":
                continue
            try:
                port = int(port_el.get("portid", "0"))
            except ValueError:
                continue
            svc_el = port_el.find("service")
            service = svc_el.get("name", "") if svc_el is not None else ""
            results.append({"port": port, "service": service})
    return results


def run_nmap(asset: dict, ports: str | None = "1-1000", timeout: float = 600) -> list[dict]:
    """Scan asset["ip_address"] with nmap. Returns open ports/services.

    Never raises. Returns [] on missing IP, tool failure, or timeout.
    (ports/timeout are internal knobs, not part of the contract.)
    """
    try:
        target = (asset or {}).get("ip_address")
        if not target:
            log.warning("run_nmap called with no ip_address: %r", asset)
            return []

        cmd = ["nmap", "-oX", "-", "-Pn", "-sV"]
        if ports:
            cmd += ["-p", ports]
        cmd.append(target)

        res = run_tool(cmd, timeout=timeout)
        # nmap can exit non-zero yet still emit valid partial XML, so always try
        # to parse whatever came back before giving up.
        services = parse_nmap_xml(res.stdout)
        if not services and not res.ok:
            log.warning("nmap(%s) failed: %s", target, res.reason)
        return services
    except Exception:  # defensive: contract says never raises
        log.exception("run_nmap crashed for asset=%r", asset)
        return []
