"""Plain-language guidance for findings, aimed at a non-security reader.

get_guidance(finding: dict) -> {"why": str, "fix": str}

finding needs: finding_type, service (may be None), cve_id (may be None),
kev_flag (may be None/0/1). Extra keys are ignored, so a sqlite3.Row
converted with dict() works as-is.

Guidance is rule-based off finding_type/service, not looked up per-CVE, so it
stays accurate even for vulnerabilities the scanner has never seen before.
"""
from __future__ import annotations

_SERVICE_TIPS: dict[str, tuple[str, str]] = {
    "telnet": (
        "Telnet sends everything, including passwords, in plain text over the network.",
        "Turn off Telnet and use SSH instead.",
    ),
    "ftp": (
        "FTP transmits files and login credentials without encryption.",
        "Switch to SFTP or FTPS, or close this port if it isn't needed.",
    ),
    "rdp": (
        "Remote Desktop exposed to the internet is one of the most common ways attackers get in.",
        "Put RDP behind a VPN, or restrict it to specific trusted IP addresses.",
    ),
    "ms-wbt-server": (
        "Remote Desktop exposed to the internet is one of the most common ways attackers get in.",
        "Put RDP behind a VPN, or restrict it to specific trusted IP addresses.",
    ),
    "mysql": (
        "This database port is reachable from the public internet, not just your own network.",
        "Restrict this port to your internal network and require strong authentication.",
    ),
    "postgresql": (
        "This database port is reachable from the public internet, not just your own network.",
        "Restrict this port to your internal network and require strong authentication.",
    ),
    "ssh": (
        "SSH is generally safe, but leaving it open to the whole internet invites automated login attempts.",
        "Use key-based login instead of passwords, and consider restricting access to known IP addresses.",
    ),
    "microsoft-ds": (
        "File-sharing services like SMB are a frequent target for ransomware.",
        "Block this port from the internet and only allow it on your internal network.",
    ),
    "netbios-ssn": (
        "File-sharing services like SMB are a frequent target for ransomware.",
        "Block this port from the internet and only allow it on your internal network.",
    ),
}

_DEFAULT_PORT_TIP = (
    "This service is reachable from the public internet, which gives an attacker one more thing to try.",
    "Close the port if it isn't needed, or restrict it to trusted IP addresses with a firewall.",
)


def _port_tip(service: str | None) -> tuple[str, str]:
    return _SERVICE_TIPS.get((service or "").lower(), _DEFAULT_PORT_TIP)


def get_guidance(finding: dict) -> dict:
    ftype = finding.get("finding_type")

    if ftype == "open_port":
        why, fix = _port_tip(finding.get("service"))

    elif ftype == "cve":
        cve = finding.get("cve_id") or "This vulnerability"
        if finding.get("kev_flag"):
            why = f"{cve} is a publicly documented flaw that attackers are actively exploiting right now."
            fix = "Patch or update the affected software immediately, this is a confirmed active threat, not just a theoretical risk."
        else:
            why = f"{cve} is a publicly known flaw in the software running here."
            fix = "Update the affected software to the version that fixes this CVE."

    elif ftype == "weak_tls":
        why = "Outdated encryption settings make it easier for someone to intercept or tamper with traffic to this site."
        fix = "Disable old protocols like TLS 1.0 and 1.1 and weak cipher suites, and require TLS 1.2 or newer."

    elif ftype == "misconfig":
        why = "A configuration issue was found that could expose more than intended."
        fix = "Review the description below and correct the setting following your platform's hardening guide."

    else:
        why = "This finding may expose information or access that should be restricted."
        fix = "Review the details below with your IT provider to determine the right fix."

    return {"why": why, "fix": fix}
