"""
scheduler.py

Wires APScheduler to call orchestrator.run_scan_cycle() on an interval
read from config.yaml (schedule.interval_hours). Works against the
Day 1 stubbed orchestrator — no changes needed here when the real
functions land on Day 3, since it only calls run_scan_cycle(), not
the functions inside it.
"""

import logging
import yaml
from apscheduler.schedulers.blocking import BlockingScheduler

from orchestrator import run_scan_cycle

logger = logging.getLogger(__name__)


def load_scheduler_config(config_path: str = "config.yaml") -> dict:
    try:
        with open(config_path, "r") as f:
            config = yaml.safe_load(f) or {}
        return config.get("schedule", {})
    except (FileNotFoundError, yaml.YAMLError) as e:
        logger.error(f"Failed to load schedule config, using defaults: {e}")
        return {}


def start():
    config = load_scheduler_config()
    interval_hours = config.get("interval_hours", 1)

    scheduler = BlockingScheduler()
    scheduler.add_job(
        run_scan_cycle,
        "interval",
        hours=interval_hours,
        id="scan_cycle",
        next_run_time=None,  # fires immediately on start, then every interval_hours
    )

    logger.info(f"Scheduler starting — run_scan_cycle every {interval_hours} hour(s).")
    try:
        scheduler.start()
    except (KeyboardInterrupt, SystemExit):
        logger.info("Scheduler stopped.")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    start()
    