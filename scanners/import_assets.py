"""Import an SMB/non-profit's own assets from a CSV file into the assets table.

This is the "bring your own assets" path: instead of (or alongside) automated
discovery, a non-expert can hand the tool a spreadsheet of the domains/IPs they
own, exported as CSV from Excel/Google Sheets. It complements
`discovery.save_assets` -- same table, same UNIQUE(domain) upsert, same
`authorized=0` default -- but accepts the richer, messier input a human types.

Design notes:
  - The core function accepts a file path OR a file-like object (e.g. a Flask
    upload stream), so the dashboard can call it directly on an uploaded file
    without writing a temp file first.
  - It is pure/offline: no network, no scan tools. Only SQLite writes.
  - It NEVER trusts the input format -- every row is normalized and validated,
    and bad rows are skipped and reported rather than aborting the whole import.
    A non-expert's CSV will have https:// prefixes, trailing slashes, ports,
    blank lines, and stray headers; we clean all of that.

Authorization seam (IMPORTANT -- team decision pending):
    New rows are written at `authorized=0`, exactly like discovery. Out of the
    box an imported asset is therefore recorded but NOT scanned until it is
    authorized. The `authorize` parameter is a dormant seam for the yet-to-be-
    decided authorization model (see the TODO in orchestrator._get_authorized_
    assets); it defaults to False so behavior is identical to today. Do not wire
    it to True in the dashboard until the team settles the authorization model.

Contract (new -- additive, not part of the frozen CONTRACTS.md):
    import_assets_from_csv(source, *, db_path=None, authorize=False) -> ImportSummary
"""
from __future__ import annotations

import csv
import ipaddress
import logging
import os
import re
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path
from typing import IO, Iterable, Union

log = logging.getLogger("scanners.import_assets")

# Same env-var contract as every other module (see CLAUDE.md): DB_PATH wins,
# repo-relative default otherwise.
RESULTS_DB = os.environ.get("DB_PATH", "db/results.db")

# Header aliases a human might reasonably type. Mapped to our canonical columns.
_DOMAIN_ALIASES = {"domain", "host", "hostname", "asset", "name", "url", "website"}
_IP_ALIASES = {"ip", "ip_address", "ipaddress", "address"}
_TYPE_ALIASES = {"type", "asset_type"}

_VALID_TYPES = {"domain", "subdomain", "ip"}

# A permissive-but-sane hostname check: dot-separated labels of letters/digits/
# hyphens (not leading/trailing hyphen), TLD at least two letters. Good enough
# to reject obvious junk without a full public-suffix list.
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)"
    r"(?:\.(?!-)[a-z0-9-]{1,63}(?<!-))*"
    r"\.[a-z]{2,}$"
)


@dataclass
class SkippedRow:
    """One input row we could not import, with a human-readable reason."""

    line: int
    value: str
    reason: str


@dataclass
class ImportSummary:
    """Result of an import, shaped for a dashboard onboarding screen to render."""

    imported: int = 0  # new assets inserted
    updated: int = 0  # existing assets re-seen (last_seen / ip refreshed)
    skipped: list[SkippedRow] = field(default_factory=list)

    @property
    def total_rows(self) -> int:
        return self.imported + self.updated + len(self.skipped)

    def as_dict(self) -> dict:
        """JSON-friendly view for a template / API response."""
        return {
            "imported": self.imported,
            "updated": self.updated,
            "skipped": [
                {"line": s.line, "value": s.value, "reason": s.reason}
                for s in self.skipped
            ],
            "total_rows": self.total_rows,
        }


# --- normalization ----------------------------------------------------------


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _normalize_host(raw: str) -> tuple[str | None, str]:
    """Turn a messy user-typed value into a bare hostname/IP.

    Returns (host, "") on success or (None, reason) if the value is unusable.
    Strips scheme, credentials, path/query, and an explicit port; lowercases;
    drops a trailing dot. Validates the result as an IPv4/IPv6 address or a
    plausible domain name.
    """
    h = raw.strip().lower()
    if not h:
        return None, "empty value"

    # Strip a URL scheme (http://, https://, etc.) and anything before it.
    if "://" in h:
        h = h.split("://", 1)[1]
    # Strip user:pass@ credentials.
    if "@" in h:
        h = h.rsplit("@", 1)[1]
    # Strip path / query / fragment -- keep only the authority.
    h = re.split(r"[/?#]", h, maxsplit=1)[0]

    if not h:
        return None, "no host in value"

    # Bracketed IPv6 literal, optionally with a port: [::1]:443
    if h.startswith("["):
        h = h[1:].split("]", 1)[0]
    # host:port -- only strip when it's a single colon (so we don't mangle a
    # bare IPv6 address, which has several).
    elif h.count(":") == 1:
        host_part, _, port_part = h.partition(":")
        if port_part.isdigit():
            h = host_part

    h = h.rstrip(".")
    if not h:
        return None, "no host in value"

    if _is_ip(h):
        return h, ""
    if _DOMAIN_RE.match(h):
        return h, ""
    return None, f"not a valid domain or IP: {raw.strip()!r}"


def _detect_type(host: str) -> str:
    """Classify a normalized host into the schema's asset_type CHECK set.

    Heuristic (documented, not perfect): an IP -> 'ip'; a two-label name like
    example.com -> 'domain'; anything with more labels -> 'subdomain'. This
    over-labels multi-part registrable domains (e.g. example.co.uk) as
    'subdomain', which only affects the display label, never what gets scanned.
    """
    if _is_ip(host):
        return "ip"
    return "domain" if host.count(".") == 1 else "subdomain"


# --- CSV parsing ------------------------------------------------------------


def _read_text(source: Union[str, Path, IO]) -> str:
    """Accept a path, or a text/binary file-like object, and return its text."""
    if isinstance(source, (str, Path)):
        return Path(source).read_text(encoding="utf-8-sig")
    data = source.read()
    if isinstance(data, bytes):
        # utf-8-sig also transparently strips a UTF-8 BOM Excel loves to add.
        return data.decode("utf-8-sig")
    return data


def _column_map(header: list[str]) -> dict[str, int] | None:
    """If `header` names a domain-ish column, return {canonical: index}.

    Returns None when the first row is not a header (i.e. it already looks like
    data), so single-column, header-less CSVs still work.
    """
    lowered = [c.strip().lower() for c in header]
    mapping: dict[str, int] = {}
    for idx, name in enumerate(lowered):
        if name in _DOMAIN_ALIASES and "domain" not in mapping:
            mapping["domain"] = idx
        elif name in _IP_ALIASES and "ip_address" not in mapping:
            mapping["ip_address"] = idx
        elif name in _TYPE_ALIASES and "asset_type" not in mapping:
            mapping["asset_type"] = idx
    return mapping if "domain" in mapping else None


@dataclass
class _ParsedRow:
    domain: str
    ip_address: str | None
    asset_type: str


def _parse_rows(text: str) -> tuple[list[_ParsedRow], list[SkippedRow]]:
    """Parse CSV text into clean rows + a list of skipped rows with reasons."""
    parsed: list[_ParsedRow] = []
    skipped: list[SkippedRow] = []
    seen: set[str] = set()  # in-file dedupe on normalized domain

    reader = csv.reader(text.splitlines())
    col_map: dict[str, int] | None = None
    header_checked = False

    for line_no, row in enumerate(reader, start=1):
        # Drop fully blank lines and #-comments (first cell starts with #).
        if not row or all(not cell.strip() for cell in row):
            continue
        if row[0].lstrip().startswith("#"):
            continue

        # The first non-blank row may be a header; detect it once.
        if not header_checked:
            header_checked = True
            col_map = _column_map(row)
            if col_map is not None:
                continue  # consumed as header

        def cell(key: str) -> str | None:
            if col_map is None:
                return row[0] if key == "domain" else None
            idx = col_map.get(key)
            if idx is None or idx >= len(row):
                return None
            val = row[idx].strip()
            return val or None

        raw_domain = cell("domain") or ""
        host, reason = _normalize_host(raw_domain)
        if host is None:
            skipped.append(SkippedRow(line_no, raw_domain, reason))
            continue
        if host in seen:
            skipped.append(SkippedRow(line_no, host, "duplicate in file"))
            continue
        seen.add(host)

        # Optional ip_address column -- validate if present, else leave for the
        # orchestrator to resolve later.
        ip_val = cell("ip_address")
        ip_address = ip_val if (ip_val and _is_ip(ip_val)) else None

        # Optional asset_type column -- honor it only if it's in the CHECK set,
        # otherwise auto-detect from the host shape.
        type_val = (cell("asset_type") or "").lower()
        asset_type = type_val if type_val in _VALID_TYPES else _detect_type(host)

        parsed.append(_ParsedRow(host, ip_address, asset_type))

    return parsed, skipped


# --- persistence ------------------------------------------------------------


def _connect(db_path: str) -> sqlite3.Connection:
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    return sqlite3.connect(db_path)


def import_assets_from_csv(
    source: Union[str, Path, IO],
    *,
    db_path: str | None = None,
    authorize: bool = False,
) -> ImportSummary:
    """Import assets from a CSV file/stream into the assets table.

    Args:
        source: a filesystem path, or a file-like object (text or bytes) such
            as a Flask upload stream (`request.files['file']`).
        db_path: override the target DB; defaults to $DB_PATH / db/results.db.
        authorize: dormant seam for the pending authorization-model decision.
            Leave False (the default) to match current behavior -- imported
            rows are written at authorized=0 and are NOT scanned until
            authorized by whatever model the team lands on.

    Returns:
        An ImportSummary: counts of newly imported vs. re-seen assets, plus a
        per-row list of anything skipped (with the reason), suitable for
        showing a user during onboarding.

    Never raises on bad rows -- those are skipped and reported. It will raise on
    a genuinely unreadable source (missing file, undecodable bytes) so the
    caller can surface a clear error.
    """
    text = _read_text(source)
    parsed, skipped = _parse_rows(text)
    summary = ImportSummary(skipped=skipped)

    if not parsed:
        log.info("import_assets_from_csv: no importable rows (%d skipped)", len(skipped))
        return summary

    target_db = db_path or RESULTS_DB
    conn = _connect(target_db)
    try:
        existing = {
            r[0] for r in conn.execute("SELECT domain FROM assets").fetchall()
        }
        authorized_value = 1 if authorize else 0

        for pr in parsed:
            if pr.domain in existing:
                # Re-seeing a known asset: refresh last_seen and fill in an IP if
                # we now have one. Never clobber a manually-set authorization or
                # an existing IP with NULL.
                conn.execute(
                    """
                    UPDATE assets
                       SET last_seen = CURRENT_TIMESTAMP,
                           ip_address = COALESCE(?, ip_address)
                     WHERE domain = ?
                    """,
                    (pr.ip_address, pr.domain),
                )
                summary.updated += 1
            else:
                conn.execute(
                    """
                    INSERT INTO assets (domain, ip_address, asset_type, authorized)
                    VALUES (?, ?, ?, ?)
                    """,
                    (pr.domain, pr.ip_address, pr.asset_type, authorized_value),
                )
                summary.imported += 1

        conn.commit()
    finally:
        conn.close()

    log.info(
        "import_assets_from_csv: %d imported, %d updated, %d skipped (authorize=%s)",
        summary.imported,
        summary.updated,
        len(summary.skipped),
        authorize,
    )
    return summary


# --- CLI (for standalone use / testing before the dashboard wires this in) ---


def _main(argv: Iterable[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(
        description="Import your organization's assets from a CSV file.",
    )
    parser.add_argument("csv_file", help="path to a CSV of assets (see assets.example.csv)")
    parser.add_argument(
        "--db",
        default=None,
        help="target SQLite DB (default: $DB_PATH or db/results.db)",
    )
    parser.add_argument(
        "--authorize",
        action="store_true",
        help="mark imported assets authorized=1 (GATED on the pending team "
        "authorization-model decision -- do not use in production yet)",
    )
    args = parser.parse_args(list(argv) if argv is not None else None)

    summary = import_assets_from_csv(
        args.csv_file, db_path=args.db, authorize=args.authorize
    )
    print(f"Imported: {summary.imported}")
    print(f"Updated:  {summary.updated}")
    print(f"Skipped:  {len(summary.skipped)}")
    for s in summary.skipped:
        print(f"  line {s.line}: {s.value!r} -- {s.reason}")
    return 0


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    raise SystemExit(_main())
