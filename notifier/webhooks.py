"""
notifier/webhooks.py

Sends alerts for scan findings to a webhook endpoint (Slack/Discord/generic).
No dependencies on other modules — safe to build and test standalone.
"""

import logging
import os
import requests
import yaml
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)

SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def _load_notifications_config(config_path: str = "config.yaml") -> dict:
    try:
        with open(config_path, "r") as f:
            config = yaml.safe_load(f) or {}
        return config.get("notifications", {})
    except (FileNotFoundError, yaml.YAMLError) as e:
        logger.error(f"Failed to load config: {e}")
        return {}


def _should_alert(severity: str, min_severity: str) -> bool:
    return SEVERITY_ORDER.get(severity.lower(), 0) >= SEVERITY_ORDER.get(min_severity.lower(), 0)


def _format_message(findings: list[dict]) -> dict:
    if not findings:
        return {"text": "Scan complete — no findings to report."}
    lines = [f"🔔 {len(findings)} finding(s) from latest scan cycle:"]
    for f in findings:
        target = f.get("target", "unknown")
        severity = f.get("severity", "unknown")
        desc = f.get("description", "")
        lines.append(f"- [{severity.upper()}] {target}: {desc}")
    return {"text": "\n".join(lines)}


def send_alerts(findings: list[dict], config_path: str = "config.yaml") -> bool:
    """Never raises — catches, logs, returns False on failure (CONTRACTS.md rule)."""
    if not findings:
        logger.info("No findings — nothing to send.")
        return True

    config = _load_notifications_config(config_path)
    min_severity = config.get("min_severity_to_alert", "high")

    alertable = [f for f in findings if _should_alert(f.get("severity", "low"), min_severity)]
    if not alertable:
        logger.info(f"No findings met min_severity_to_alert={min_severity}.")
        return True

    webhook_url = os.environ.get("SLACK_WEBHOOK_URL")
    if not webhook_url:
        logger.error("SLACK_WEBHOOK_URL not set in environment.")
        return False

    payload = _format_message(alertable)
    try:
        response = requests.post(webhook_url, json=payload, timeout=10)
        response.raise_for_status()
        logger.info(f"Alert sent ({len(alertable)} finding(s)).")
        return True
    except requests.exceptions.RequestException as e:
        logger.error(f"Failed to send alert: {e}")
        return False


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    sample_findings = [
        {"target": "10.0.0.5", "severity": "high", "description": "Open RDP port with weak auth"},
    ]
    send_alerts(sample_findings)
    