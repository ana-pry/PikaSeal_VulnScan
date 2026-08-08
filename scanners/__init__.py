"""Discovery + Scanning module. Public API matches CONTRACTS.md."""
from .discovery import discover_assets, save_assets
from .port_scan import parse_nmap_xml, run_nmap
from .vuln_scan import parse_nuclei_jsonl, run_nuclei

__all__ = [
    "discover_assets",
    "save_assets",
    "run_nmap",
    "run_nuclei",
    "parse_nmap_xml",
    "parse_nuclei_jsonl",
]
