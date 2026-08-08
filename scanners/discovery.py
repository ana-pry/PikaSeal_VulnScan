"""Discovery: subfinder + amass -> flat list of subdomain strings.

Contract (frozen):
    discover_assets(domain: str) -> list[str]
    save_assets(subdomains: list[str], run_id: int) -> None

discover_assets is a scan wrapper: it never raises, returns [] on failure.
save_assets is the one persistence function in this role -- it writes to the
assets table. New domains default to authorized = 0.
"""
from __future__ import annotations

import logging
import os
import sqlite3
import tempfile
from pathlib import Path

from .runner import run_tool

log = logging.getLogger("scanners.discovery")

# Where results.db lives. Overridable via env so it matches the .env config the
# rest of the team uses; falls back to the repo-relative default.
RESULTS_DB = os.environ.get("RESULTS_DB", "db/results.db")


def _clean_hosts(text: str, domain: str) -> set[str]:
    """Keep non-empty lines that look like subdomains of `domain`."""
    hosts: set[str] = set()
    for line in text.splitlines():
        h = line.strip().lower().rstrip(".")
        if not h or " " in h:
            continue
        if h == domain or h.endswith("." + domain):
            hosts.add(h)
    return hosts


def _run_subfinder(domain: str, timeout: float) -> set[str]:
    res = run_tool(["subfinder", "-d", domain, "-silent"], timeout=timeout)
    if not res.ok and not res.stdout:
        log.warning("subfinder(%s) failed: %s", domain, res.reason)
        return set()
    return _clean_hosts(res.stdout, domain)


def _run_amass(domain: str, timeout: float) -> set[str]:
    """Passive amass enum, then read subdomains back out (amass v5 model).

    amass v5 removed `-o`: `enum` writes to a graph DB, and you retrieve results
    with the separate `subs` subcommand. We isolate the DB in a temp `-dir` so
    runs don't collide, then `amass subs -show` prints the names to stdout.

    This is best-effort: if amass is a different major version (v4 apt packages
    still exist) or the subcommand shape differs, it degrades to an empty set
    with a logged warning, and discovery falls back to subfinder alone.
    """
    with tempfile.TemporaryDirectory() as tmp:
        enum = run_tool(
            ["amass", "enum", "-passive", "-d", domain, "-dir", tmp, "-nocolor"],
            timeout=timeout,
        )
        # Read the enumerated names back out of the graph DB in the same dir.
        show = run_tool(
            ["amass", "subs", "-d", domain, "-dir", tmp, "-show", "-nocolor"],
            timeout=60,
        )
        text = show.stdout

    hosts = _clean_hosts(text, domain)
    if not hosts and not (enum.ok and show.ok):
        reason = show.reason or enum.reason or "no results"
        log.warning("amass(%s) failed: %s", domain, reason)
    return hosts


def discover_assets(domain: str, timeout: float = 300) -> list[str]:
    """Run subfinder + amass against `domain`, return a deduped subdomain list.

    Never raises. On total failure returns []. (timeout is an internal knob,
    not part of the contract -- callers can ignore it.)
    """
    try:
        found = _run_subfinder(domain, timeout) | _run_amass(domain, timeout)
        return sorted(found)
    except Exception:  # defensive: contract says wrappers never raise
        log.exception("discover_assets(%s) crashed", domain)
        return []


def _connect(db_path: str) -> sqlite3.Connection:
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    return sqlite3.connect(db_path)


def save_assets(subdomains: list[str], run_id: int) -> None:
    """Insert/update rows in the assets table; new domains default authorized=0.

    Reconciled against the frozen schema:
      - `assets` is keyed UNIQUE(domain); that's the upsert target.
      - authorized/asset_type/status/first_seen/last_seen all have schema
        defaults, so a bare `INSERT (domain)` gives new rows authorized=0 and
        asset_type='subdomain' automatically.
      - There is NO run_id column on `assets` (run<->asset association lives on
        `findings`). So `run_id` here is contextual only: we log it and use the
        re-discovery to bump last_seen. If the team expected assets to record a
        run_id, that's a contract/schema mismatch worth raising -- but the
        stated behavior ("insert/update, default authorized=0") is fully met.
    """
    if not subdomains:
        return
    conn = _connect(RESULTS_DB)
    try:
        # New rows inherit schema defaults (authorized=0, asset_type='subdomain',
        # status='active', first_seen/last_seen=now). Re-seeing a domain just
        # refreshes last_seen -- we never clobber a manually-authorized asset
        # back to 0, and we leave first_seen untouched.
        conn.executemany(
            """
            INSERT INTO assets (domain)
            VALUES (?)
            ON CONFLICT(domain) DO UPDATE SET last_seen = CURRENT_TIMESTAMP
            """,
            [(d,) for d in subdomains],
        )
        conn.commit()
        log.info("save_assets: upserted %d assets (run_id=%s)", len(subdomains), run_id)
    except Exception:
        log.exception("save_assets failed for run_id=%s", run_id)
        raise
    finally:
        conn.close()