import sqlite3
from pathlib import Path
from flask import Flask, render_template, request

app = Flask(__name__)

DB_PATH = Path(__file__).resolve().parent.parent / "db" / "results.db"
SCHEMA_PATH = Path(__file__).resolve().parent.parent / "db" / "schema.sql"


def ensure_db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    try:
        conn.executescript(SCHEMA_PATH.read_text())
        conn.commit()
    finally:
        conn.close()


ensure_db()


def get_db():
    """Open a read-write SQLite connection so the dashboard works locally."""
    conn = sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES)
    conn.row_factory = sqlite3.Row
    return conn


@app.route("/")
def overview():
    conn = get_db()
    try:
        asset_count = conn.execute("SELECT COUNT(*) FROM assets").fetchone()[0]
        authorized_count = conn.execute(
            "SELECT COUNT(*) FROM assets WHERE authorized = 1"
        ).fetchone()[0]

        finding_count = conn.execute(
            "SELECT COUNT(*) FROM findings WHERE status = 'open'"
        ).fetchone()[0]

        severity_breakdown = conn.execute("""
            SELECT severity, COUNT(*) AS n
            FROM findings
            WHERE status = 'open'
            GROUP BY severity
            ORDER BY
                CASE severity
                    WHEN 'critical' THEN 1
                    WHEN 'high' THEN 2
                    WHEN 'medium' THEN 3
                    WHEN 'low' THEN 4
                    ELSE 5
                END
        """).fetchall()

        kev_count = conn.execute(
            "SELECT COUNT(*) FROM findings WHERE kev_flag = 1 AND status = 'open'"
        ).fetchone()[0]

        recent_scans = conn.execute("""
            SELECT id, started_at, finished_at, status, notes
            FROM scan_runs
            ORDER BY started_at DESC
            LIMIT 5
        """).fetchall()
    finally:
        conn.close()

    return render_template(
        "index.html",
        asset_count=asset_count,
        authorized_count=authorized_count,
        finding_count=finding_count,
        severity_breakdown=severity_breakdown,
        kev_count=kev_count,
        recent_scans=recent_scans,
    )


@app.route("/findings")
def findings():
    sort = request.args.get("sort", "risk_score")
    allowed = {
        "risk_score": "f.risk_score DESC NULLS LAST",
        "severity": """
            CASE f.severity
                WHEN 'critical' THEN 1
                WHEN 'high' THEN 2
                WHEN 'medium' THEN 3
                WHEN 'low' THEN 4
                ELSE 5
            END, f.risk_score DESC
        """,
        "discovered": "f.discovered_at DESC",
    }
    order_by = allowed.get(sort, allowed["risk_score"])

    conn = get_db()
    try:
        rows = conn.execute(f"""
            SELECT
                f.id, f.finding_type, f.port, f.service,
                f.cve_id, f.cvss_score, f.kev_flag,
                f.risk_score, f.severity, f.description,
                f.status, f.discovered_at,
                a.domain, a.ip_address
            FROM findings f
            LEFT JOIN assets a ON a.id = f.asset_id
            WHERE f.status = 'open'
            ORDER BY {order_by}
        """).fetchall()
    finally:
        conn.close()

    return render_template("findings.html", findings=rows, sort=sort)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)