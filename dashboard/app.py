import re
import sqlite3
from pathlib import Path
from flask import Flask, redirect, render_template, request, url_for

from remediation import get_guidance

app = Flask(__name__)

# Bare hostname only (no scheme/path/port) -- e.g. "shop.example.com".
_DOMAIN_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)(\.[a-z0-9-]{1,63})+$")


def _clean_domain(raw: str) -> str | None:
    """Normalize user input down to a bare domain, or None if it isn't one."""
    value = (raw or "").strip().lower()
    value = re.sub(r"^https?://", "", value)
    value = value.split("/")[0].split(":")[0]
    return value if _DOMAIN_RE.match(value) else None

DB_PATH = Path(__file__).resolve().parent.parent / "db" / "results.db"
SCHEMA_PATH = Path(__file__).resolve().parent.parent / "db" / "schema.sql"

SEVERITY_ORDER_SQL = """
    CASE severity
        WHEN 'critical' THEN 1
        WHEN 'high' THEN 2
        WHEN 'medium' THEN 3
        WHEN 'low' THEN 4
        ELSE 5
    END
"""

# Health score: start at 100 and subtract a per-finding penalty by severity,
# floored at 0. Weights are deliberately steep on critical/high so a handful
# of serious findings move the score a lot more than a pile of low ones.
_SEVERITY_PENALTY = {"critical": 20, "high": 10, "medium": 4, "low": 1}
_GRADE_BANDS = [
    (90, "A", "Strong health"),
    (75, "B", "Good health"),
    (60, "C", "Fair health"),
    (40, "D", "Weak health"),
    (0, "F", "Critical health"),
]


def _health_score(severity_counts: dict) -> dict:
    penalty = sum(_SEVERITY_PENALTY.get(sev, 0) * n for sev, n in severity_counts.items())
    score = max(0, 100 - penalty)
    for floor, grade, label in _GRADE_BANDS:
        if score >= floor:
            return {"score": score, "grade": grade, "label": label}
    return {"score": score, "grade": "F", "label": "Critical health"}


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

        severity_breakdown = conn.execute(f"""
            SELECT severity, COUNT(*) AS n
            FROM findings
            WHERE status = 'open'
            GROUP BY severity
            ORDER BY {SEVERITY_ORDER_SQL}
        """).fetchall()
        severity_counts = {row["severity"]: row["n"] for row in severity_breakdown}
        health = _health_score(severity_counts)

        kev_count = conn.execute(
            "SELECT COUNT(*) FROM findings WHERE kev_flag = 1 AND status = 'open'"
        ).fetchone()[0]

        top_finding_row = conn.execute("""
            SELECT
                f.id, f.finding_type, f.port, f.service,
                f.cve_id, f.cvss_score, f.kev_flag,
                f.risk_score, f.severity, f.description,
                a.domain, a.ip_address
            FROM findings f
            LEFT JOIN assets a ON a.id = f.asset_id
            WHERE f.status = 'open'
            ORDER BY f.risk_score DESC
            LIMIT 1
        """).fetchone()
        top_finding = None
        if top_finding_row is not None:
            top_finding = dict(top_finding_row)
            top_finding["guidance"] = get_guidance(top_finding)

        top_issues = conn.execute("""
            SELECT f.id, f.finding_type, f.risk_score, f.severity, f.cve_id, a.domain
            FROM findings f
            LEFT JOIN assets a ON a.id = f.asset_id
            WHERE f.status = 'open'
            ORDER BY f.risk_score DESC
            LIMIT 3
        """).fetchall()

        recent_scans_rows = conn.execute("""
            SELECT id, started_at, finished_at, status, notes
            FROM scan_runs
            ORDER BY started_at DESC
            LIMIT 5
        """).fetchall()

        run_ids = [row["id"] for row in recent_scans_rows]
        finding_counts_by_run = {}
        if run_ids:
            placeholders = ",".join("?" * len(run_ids))
            count_rows = conn.execute(
                f"SELECT run_id, COUNT(*) AS n FROM findings WHERE run_id IN ({placeholders}) GROUP BY run_id",
                run_ids,
            ).fetchall()
            finding_counts_by_run = {row["run_id"]: row["n"] for row in count_rows}

        recent_scans = []
        for row in recent_scans_rows:
            scan = dict(row)
            scan["finding_count"] = finding_counts_by_run.get(row["id"], 0)
            recent_scans.append(scan)
    finally:
        conn.close()

    return render_template(
        "index.html",
        asset_count=asset_count,
        authorized_count=authorized_count,
        finding_count=finding_count,
        severity_breakdown=severity_breakdown,
        health=health,
        kev_count=kev_count,
        top_finding=top_finding,
        top_issues=top_issues,
        recent_scans=recent_scans,
        target_error=request.args.get("target_error"),
    )


@app.route("/findings")
def findings():
    sort = request.args.get("sort", "risk_score")
    severity_filter = request.args.get("severity")
    asset_id = request.args.get("asset_id", type=int)
    highlight = request.args.get("highlight", type=int)

    allowed = {
        "risk_score": "f.risk_score DESC",
        "severity": f"{SEVERITY_ORDER_SQL.replace('severity', 'f.severity')}, f.risk_score DESC",
        "discovered": "f.discovered_at DESC",
    }
    order_by = allowed.get(sort, allowed["risk_score"])

    where = ["f.status = 'open'"]
    params: list = []
    if severity_filter in {"critical", "high", "medium", "low"}:
        where.append("f.severity = ?")
        params.append(severity_filter)
    if asset_id is not None:
        where.append("f.asset_id = ?")
        params.append(asset_id)

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
            WHERE {' AND '.join(where)}
            ORDER BY {order_by}
        """, params).fetchall()
    finally:
        conn.close()

    findings_list = []
    for row in rows:
        item = dict(row)
        item["guidance"] = get_guidance(item)
        findings_list.append(item)

    return render_template(
        "findings.html",
        findings=findings_list,
        sort=sort,
        severity_filter=severity_filter,
        asset_id=asset_id,
        highlight=highlight,
    )


@app.route("/assets")
def assets():
    conn = get_db()
    try:
        rows = conn.execute("""
            SELECT
                a.id, a.domain, a.ip_address, a.asset_type, a.authorized,
                a.status, a.first_seen, a.last_seen,
                SUM(CASE WHEN f.status = 'open' THEN 1 ELSE 0 END) AS open_findings,
                SUM(CASE WHEN f.status = 'open' AND f.severity = 'critical' THEN 1 ELSE 0 END) AS critical_findings
            FROM assets a
            LEFT JOIN findings f ON f.asset_id = a.id
            GROUP BY a.id
            ORDER BY critical_findings DESC, open_findings DESC, a.domain ASC
        """).fetchall()
    finally:
        conn.close()

    return render_template("assets.html", assets=rows, added=request.args.get("added"))


@app.route("/assets/add", methods=["POST"])
def add_asset():
    domain = _clean_domain(request.form.get("domain", ""))
    if not domain:
        return redirect(url_for("overview", target_error="Enter a domain like yourbusiness.com"))

    conn = get_db()
    try:
        conn.execute(
            "INSERT OR IGNORE INTO assets (domain, asset_type) VALUES (?, 'domain')",
            (domain,),
        )
        conn.commit()
    finally:
        conn.close()

    return redirect(url_for("assets", added=domain))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
