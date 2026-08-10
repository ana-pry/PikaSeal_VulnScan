from risk_engine.scoring import score_findings

tests = [
    # High/critical profiles (KEV + high EPSS)
    {"cve_id": "CVE-2021-44228", "severity": "critical", "description": "Log4Shell (KEV, high EPSS)"},
    {"cve_id": "CVE-2014-0160",  "severity": "high",     "description": "Heartbleed (KEV, mid CVSS)"},
    {"cve_id": "CVE-2023-38545", "severity": "high",     "description": "curl SOCKS5 (high CVSS, no KEV)"},
    {"cve_id": "CVE-2019-11043", "severity": "critical", "description": "PHP-FPM RCE (KEV)"},
    # Lower-profile — should exercise medium / low bands
    {"cve_id": "CVE-2012-1823",  "severity": "high",     "description": "old PHP-CGI (high CVSS, very old)"},
    {"cve_id": "CVE-2016-2183",  "severity": "medium",   "description": "SWEET32 (medium CVSS, low EPSS)"},
    {"cve_id": "CVE-2011-3389",  "severity": "medium",   "description": "BEAST TLS (low EPSS, no KEV)"},
]

for f in score_findings(tests):
    print(
        f"{f['cve_id']:18} "
        f"cvss={f['cvss_score']:<4} "
        f"epss={round(f['epss_score'], 5):<9} "
        f"kev={str(f['kev_flag']):5} "
        f"-> risk={f['risk_score']} ({f['severity']})"
    )