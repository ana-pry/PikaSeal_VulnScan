"""Plain-language explanations and fix guidance for findings.

Turns a raw finding (from the findings table) into non-expert-friendly text:
what the problem is, why it matters, and how to fix it. This is the feature
that makes the tool usable by someone who isn't a security expert -- every other
scanner assumes you already know what "weak-cipher-suites" means.

Design:
  - explain(finding) is the single entry point. Given a finding dict/row with
    finding_type, cve_id (a template-id for non-CVEs), severity, and description,
    it returns {"title", "what", "how", "references"}.
  - Guidance is looked up most-specific-first: exact template-id, then the broad
    finding_type, then a safe generic fallback. Nothing ever returns empty.
  - Real CVEs get a generic "apply the vendor patch" message plus a live NVD
    link built from the CVE id -- we don't hand-write per-CVE text (there are
    too many), we point to the authoritative source.

No network, no DB, no dependencies -- pure lookup, so the dashboard can call it
per finding at render time.
"""
from __future__ import annotations

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
        "what": "A service on your system is reachable from the internet. Open ports aren't bad by themselves, but each one is a door an attacker can try.",
        "how": "Confirm this service needs to be public. If not, close the port at your firewall or restrict it to trusted addresses. Keep the service software up to date.",
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


def explain(finding: dict) -> dict:
    """Return non-expert guidance for a finding.

    finding: a dict/row with at least finding_type and cve_id (which holds a
    template-id for non-CVE findings). description is used as extra detail.

    Returns: {"title", "what", "how", "references"} -- never empty.
    """
    finding_type = (finding.get("finding_type") or "").lower()
    cve_id = finding.get("cve_id")

    # 1. Real CVE: authoritative NVD link + generic patch guidance.
    if finding_type == "cve" and _looks_like_cve(cve_id):
        base = dict(_TYPE_GUIDANCE["cve"])
        cid = cve_id.upper()
        base["title"] = f"Known vulnerability: {cid}"
        base["references"] = [f"https://nvd.nist.gov/vuln/detail/{cid}"]
        if finding.get("description"):
            base["what"] = f"{base['what']} Details: {finding['description']}"
        return base

    # 2. Most specific: exact template-id match.
    if cve_id and cve_id in _TEMPLATE_GUIDANCE:
        return dict(_TEMPLATE_GUIDANCE[cve_id])

    # 3. Broad fallback by finding_type.
    if finding_type in _TYPE_GUIDANCE:
        return dict(_TYPE_GUIDANCE[finding_type])

    # 4. Safe generic fallback -- always returns something.
    return dict(_GENERIC)