"""Plain-language explanations and fix guidance for findings.

Turns a raw finding (from the findings table) into non-expert-friendly text:
what the problem is, why it matters, and how to fix it. This is the feature
that makes the tool usable by someone who isn't a security expert -- every other
scanner assumes you already know what "weak-cipher-suites" means.

Design:
  - explain(finding) is the rich entry point. Given a finding dict/row with
    finding_type, cve_id (a template-id for non-CVEs), service, kev_flag,
    severity and description, it returns {"title", "what", "how", "references"}.
  - get_guidance(finding) is a thin projection of explain() down to
    {"why", "fix"} -- the shape the dashboard templates render. It exists so the
    dashboard has a single import for guidance and the two modules can't drift.
  - Guidance is chosen most-specific-first and stays *dynamic* in three ways:
      1. open_port findings are keyed by the detected service (telnet -> "use
         SSH", RDP -> "put behind a VPN"), not one generic "a port is open".
      2. CVE findings escalate their wording when kev_flag is set -- a flaw that
         is being actively exploited reads as urgent, not theoretical. This is
         the same real-world-exploitation signal the risk engine scores on.
      3. Real CVEs get a live NVD link built from the CVE id, so we point at the
         authoritative source instead of hand-writing per-CVE text.
  - Nothing ever returns empty: unknown templates fall back to finding_type,
    then to a safe generic message.

No network, no DB, no dependencies -- pure lookup, so the dashboard can call it
per finding at render time.
"""
from __future__ import annotations

# Per-service guidance for open_port findings, keyed by the nmap-reported service
# name. Values are (what, how). This is what makes open-port guidance dynamic:
# the bulk of findings are open ports, and "telnet -> use SSH" is far more useful
# than "a service is reachable".
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
    "A service on your system is reachable from the internet. Open ports aren't bad by "
    "themselves, but each one is a door an attacker can try.",
    "Confirm this service needs to be public. If not, close the port at your firewall or "
    "restrict it to trusted addresses. Keep the service software up to date.",
)

# Per-template guidance for the common findings this scanner actually produces.
# Keyed by nuclei template-id (stored in the finding's cve_id field for non-CVEs).
_TEMPLATE_GUIDANCE: dict[str, dict] = {
    "weak-cipher-suites": {
        "title": "Weak encryption ciphers enabled",
        "what": "Your server accepts outdated encryption methods that modern attackers can break. It's like using a lock that's known to be pickable.",
        "how": "On your web server, disable weak ciphers and allow only strong, modern ones (AES-GCM, ChaCha20). Most hosting providers have a one-click 'modern TLS' setting; if you manage the server, update the cipher list in your Apache/Nginx TLS config.",
        "references": ["https://ssl-config.mozilla.org/"],
    },
    "deprecated-tls": {
        "title": "Outdated TLS version supported",
        "what": "Your site still allows old versions of the encryption protocol (TLS 1.0/1.1) that are no longer considered safe.",
        "how": "Disable TLS 1.0 and 1.1 and require TLS 1.2 or higher. Your host or server config has a 'minimum TLS version' setting for this.",
        "references": ["https://ssl-config.mozilla.org/"],
    },
    "tls-version": {
        "title": "TLS version information",
        "what": "This reports which encryption protocol versions your server supports. It's informational, but old versions being present is worth checking.",
        "how": "Confirm only TLS 1.2 and 1.3 are enabled; disable anything older.",
        "references": ["https://ssl-config.mozilla.org/"],
    },
    "http-missing-security-headers": {
        "title": "Missing security headers",
        "what": "Your site isn't sending certain optional 'instructions' to browsers that help protect visitors from common attacks (like clickjacking or content injection).",
        "how": "Add security headers to your web server config: Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, and Strict-Transport-Security. Many are a few lines in your Apache/Nginx config or a plugin if you use a CMS.",
        "references": ["https://owasp.org/www-project-secure-headers/"],
    },
    "missing-cookie-samesite-strict": {
        "title": "Cookies missing SameSite protection",
        "what": "Cookies on your site don't specify a 'SameSite' rule, which helps stop other websites from misusing your users' logged-in sessions.",
        "how": "Set the SameSite attribute (Lax or Strict) on your cookies. If you use a framework or CMS, this is usually a configuration option.",
        "references": ["https://owasp.org/www-community/SameSite"],
    },
    "missing-sri": {
        "title": "Missing Subresource Integrity",
        "what": "Your site loads scripts/styles from other places without verifying they haven't been tampered with. If one of those sources is compromised, malicious code could run on your site.",
        "how": "Add an 'integrity' attribute (a checksum) to external <script> and <link> tags. Most CDN providers give you the exact tag to copy.",
        "references": ["https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity"],
    },
    "wildcard-tls": {
        "title": "Wildcard TLS certificate in use",
        "what": "Your certificate covers all subdomains at once (*.example.com). Convenient, but if it's ever stolen it exposes every subdomain.",
        "how": "This is often acceptable. If you handle sensitive systems, consider per-subdomain certificates for those instead. No urgent action if your key is well protected.",
        "references": [],
    },
}

# Broad fallback guidance by finding_type, used when there's no specific template
# entry. Keeps every finding explainable even for templates we haven't mapped.
_TYPE_GUIDANCE: dict[str, dict] = {
    "open_port": {
        "title": "Open network port",
        "what": _DEFAULT_PORT_TIP[0],
        "how": _DEFAULT_PORT_TIP[1],
        "references": [],
    },
    "weak_tls": {
        "title": "TLS/SSL configuration weakness",
        "what": "There's an issue with how your site handles encryption. Weak encryption settings can let attackers intercept or read traffic that should be private.",
        "how": "Update your server's TLS settings to modern, secure defaults. Mozilla's SSL Configuration Generator produces a safe config for your server type.",
        "references": ["https://ssl-config.mozilla.org/"],
    },
    "misconfig": {
        "title": "Security misconfiguration",
        "what": "A setting on your system isn't configured securely. On its own it may be minor, but misconfigurations are a common way attackers gain a foothold.",
        "how": "Review the finding details below and adjust the relevant setting. If it references a specific product, check that product's security/hardening guide.",
        "references": ["https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"],
    },
    "cve": {
        "title": "Known vulnerability (CVE)",
        "what": "Software on your system has a publicly known security flaw. Because it's public, attackers know about it too.",
        "how": "Update the affected software to a patched version -- this is the single most effective fix. Check the vendor's advisory (linked below) for the specific version to upgrade to.",
        "references": [],
    },
}

_GENERIC = {
    "title": "Security finding",
    "what": "The scanner flagged something worth reviewing on this asset.",
    "how": "Review the finding details and consult the referenced product's documentation for hardening guidance.",
    "references": [],
}


def _looks_like_cve(cve_id: str | None) -> bool:
    return bool(cve_id) and cve_id.upper().startswith("CVE-")


def _explain_open_port(finding: dict) -> dict:
    """Service-aware guidance for an open_port finding."""
    service = (finding.get("service") or "").lower()
    what, how = _SERVICE_TIPS.get(service, _DEFAULT_PORT_TIP)
    title = f"Exposed {finding['service']} service" if finding.get("service") else "Open network port"
    return {"title": title, "what": what, "how": how, "references": []}


def _explain_cve(finding: dict) -> dict:
    """CVE guidance, escalated when the flaw is a known-exploited (KEV) one."""
    base = dict(_TYPE_GUIDANCE["cve"])
    cve_id = finding.get("cve_id")
    label = cve_id.upper() if _looks_like_cve(cve_id) else "This vulnerability"

    if finding.get("kev_flag"):
        base["title"] = f"Actively exploited vulnerability: {label}"
        base["what"] = (
            f"{label} is a publicly documented flaw that attackers are actively exploiting "
            "right now -- this is a confirmed active threat, not just a theoretical risk."
        )
        base["how"] = "Patch or update the affected software immediately. Treat this as urgent."
    else:
        base["title"] = f"Known vulnerability: {label}" if _looks_like_cve(cve_id) else base["title"]
        base["what"] = f"{label} is a publicly known flaw in the software running here. Because it's public, attackers know about it too."
        base["how"] = "Update the affected software to the version that fixes this CVE -- this is the single most effective fix."

    if _looks_like_cve(cve_id):
        base["references"] = [f"https://nvd.nist.gov/vuln/detail/{cve_id.upper()}"]
    # Note: the finding's raw `description` is intentionally NOT folded into
    # `what` here. The dashboard renders `description` on its own line, so
    # appending it produced the same text twice ("Why it matters" echoing the
    # description). Keeping `what` as clean plain-language leaves the technical
    # detail to the separate description line, consistent with non-CVE findings.
    return base


def explain(finding: dict) -> dict:
    """Return rich non-expert guidance for a finding.

    finding: a dict/row with at least finding_type. cve_id holds a template-id
    for non-CVE findings; service, kev_flag and description are used when present.

    Returns: {"title", "what", "how", "references"} -- never empty.
    """
    finding_type = (finding.get("finding_type") or "").lower()
    cve_id = finding.get("cve_id")

    # 1. Real CVE (or any cve-typed finding): KEV-aware, with NVD link.
    if finding_type == "cve":
        return _explain_cve(finding)

    # 2. Open port: service-aware guidance.
    if finding_type == "open_port":
        return _explain_open_port(finding)

    # 3. Most specific: exact template-id match.
    if cve_id and cve_id in _TEMPLATE_GUIDANCE:
        return dict(_TEMPLATE_GUIDANCE[cve_id])

    # 4. Broad fallback by finding_type.
    if finding_type in _TYPE_GUIDANCE:
        return dict(_TYPE_GUIDANCE[finding_type])

    # 5. Safe generic fallback -- always returns something.
    return dict(_GENERIC)


def get_guidance(finding: dict) -> dict:
    """Projection of explain() to the {"why", "fix"} shape the dashboard renders.

    Kept as the dashboard's single import so guidance logic lives in one place
    and the dashboard copy can be retired.
    """
    g = explain(finding)
    return {"why": g["what"], "fix": g["how"]}
