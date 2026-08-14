"""Offline tests for CSV asset import -- NO network, NO scan tools.

    python -m pytest scanners/test_import_assets.py -v
    # or, no pytest:
    PYTHONPATH=. python scanners/test_import_assets.py

DB writes are exercised against the REAL frozen `assets` schema in a temp DB, so
this fails loudly if the import ever drifts from db/schema.sql.
"""
from __future__ import annotations

import io
import sqlite3
import tempfile
from pathlib import Path

from scanners.import_assets import (
    _detect_type,
    _normalize_host,
    import_assets_from_csv,
)

# The real frozen `assets` DDL, copied verbatim from db/schema.sql.
ASSETS_DDL = """
CREATE TABLE IF NOT EXISTS assets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT NOT NULL,
    ip_address TEXT,
    asset_type TEXT CHECK(asset_type IN ('domain', 'subdomain', 'ip')) DEFAULT 'subdomain',
    authorized BOOLEAN NOT NULL DEFAULT 0,
    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    status TEXT CHECK(status IN ('active', 'inactive')) DEFAULT 'active',
    UNIQUE(domain)
);
"""


def _fresh_db(tmp: str) -> str:
    db = Path(tmp) / "results.db"
    conn = sqlite3.connect(db)
    conn.executescript(ASSETS_DDL)
    conn.commit()
    conn.close()
    return str(db)


# --- normalization units ----------------------------------------------------


def test_normalize_strips_scheme_port_path_and_case():
    assert _normalize_host("HTTPS://Example.com/login?x=1")[0] == "example.com"
    assert _normalize_host("http://shop.example.com:8443/")[0] == "shop.example.com"
    assert _normalize_host("  example.com.  ")[0] == "example.com"
    assert _normalize_host("user:pass@example.com")[0] == "example.com"


def test_normalize_accepts_ip_rejects_junk():
    assert _normalize_host("203.0.113.10")[0] == "203.0.113.10"
    assert _normalize_host("not a domain")[0] is None
    assert _normalize_host("")[0] is None
    assert _normalize_host("http://")[0] is None


def test_detect_type():
    assert _detect_type("example.com") == "domain"
    assert _detect_type("shop.example.com") == "subdomain"
    assert _detect_type("203.0.113.10") == "ip"


# --- import against the real schema -----------------------------------------


def test_import_headered_csv_defaults_authorized_zero():
    csv_text = (
        "domain,ip_address,asset_type\n"
        "Example.com,,\n"
        "https://shop.example.com/,,\n"
        "203.0.113.10,203.0.113.10,ip\n"
    )
    with tempfile.TemporaryDirectory() as tmp:
        db = _fresh_db(tmp)
        summary = import_assets_from_csv(io.StringIO(csv_text), db_path=db)

        assert summary.imported == 3
        assert summary.updated == 0
        assert summary.skipped == []

        conn = sqlite3.connect(db)
        rows = conn.execute(
            "SELECT domain, ip_address, asset_type, authorized FROM assets ORDER BY domain"
        ).fetchall()
        conn.close()

        assert rows == [
            ("203.0.113.10", "203.0.113.10", "ip", 0),
            ("example.com", None, "domain", 0),
            ("shop.example.com", None, "subdomain", 0),
        ]


def test_import_headerless_single_column():
    csv_text = "example.com\nwww.example.com\n"
    with tempfile.TemporaryDirectory() as tmp:
        db = _fresh_db(tmp)
        summary = import_assets_from_csv(io.StringIO(csv_text), db_path=db)
        assert summary.imported == 2
        conn = sqlite3.connect(db)
        domains = {r[0] for r in conn.execute("SELECT domain FROM assets").fetchall()}
        conn.close()
        assert domains == {"example.com", "www.example.com"}


def test_skips_blanks_comments_and_dupes():
    csv_text = (
        "domain\n"
        "# this is a comment\n"
        "\n"
        "example.com\n"
        "EXAMPLE.com\n"  # duplicate after normalization
        "not a valid host\n"
    )
    with tempfile.TemporaryDirectory() as tmp:
        db = _fresh_db(tmp)
        summary = import_assets_from_csv(io.StringIO(csv_text), db_path=db)
        assert summary.imported == 1
        reasons = {s.reason for s in summary.skipped}
        assert any("duplicate" in r for r in reasons)
        assert any("not a valid" in r for r in reasons)


def test_reimport_updates_not_duplicates_and_preserves_auth():
    csv_text = "domain\nexample.com\n"
    with tempfile.TemporaryDirectory() as tmp:
        db = _fresh_db(tmp)
        import_assets_from_csv(io.StringIO(csv_text), db_path=db)

        # Simulate the asset having been authorized out-of-band.
        conn = sqlite3.connect(db)
        conn.execute("UPDATE assets SET authorized = 1 WHERE domain = 'example.com'")
        conn.commit()
        conn.close()

        # Re-import the same asset, now also carrying an IP.
        summary = import_assets_from_csv(
            io.StringIO("domain,ip_address\nexample.com,203.0.113.5\n"), db_path=db
        )
        assert summary.imported == 0
        assert summary.updated == 1

        conn = sqlite3.connect(db)
        count = conn.execute("SELECT COUNT(*) FROM assets").fetchone()[0]
        authorized, ip = conn.execute(
            "SELECT authorized, ip_address FROM assets WHERE domain = 'example.com'"
        ).fetchone()
        conn.close()

        assert count == 1  # no duplicate row
        assert authorized == 1  # re-import did not clobber authorization
        assert ip == "203.0.113.5"  # IP got filled in


def test_authorize_flag_sets_authorized_one():
    with tempfile.TemporaryDirectory() as tmp:
        db = _fresh_db(tmp)
        import_assets_from_csv(
            io.StringIO("domain\nexample.com\n"), db_path=db, authorize=True
        )
        conn = sqlite3.connect(db)
        authorized = conn.execute(
            "SELECT authorized FROM assets WHERE domain = 'example.com'"
        ).fetchone()[0]
        conn.close()
        assert authorized == 1


def test_bytes_stream_with_bom():
    # Excel exports UTF-8 with a BOM; the reader must transparently handle it.
    raw = "﻿domain\nexample.com\n".encode("utf-8")
    with tempfile.TemporaryDirectory() as tmp:
        db = _fresh_db(tmp)
        summary = import_assets_from_csv(io.BytesIO(raw), db_path=db)
        assert summary.imported == 1
        conn = sqlite3.connect(db)
        domain = conn.execute("SELECT domain FROM assets").fetchone()[0]
        conn.close()
        assert domain == "example.com"


def test_empty_csv_is_noop():
    with tempfile.TemporaryDirectory() as tmp:
        db = _fresh_db(tmp)
        summary = import_assets_from_csv(io.StringIO("domain\n"), db_path=db)
        assert summary.imported == 0 and summary.updated == 0


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"ok  {fn.__name__}")
    print(f"\n{len(fns)}/{len(fns)} passed")
