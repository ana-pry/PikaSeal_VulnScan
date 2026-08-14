"""TTPR dashboard — Flask app.

Serves the operator-facing views (overview, findings, assets) plus the asset
management actions that used to require the CLI: adding a single target, and
importing an organization's own assets from a CSV, and marking assets in/out of
scope (authorized).

DB + module wiring:
  - DB_PATH is resolved once and pushed into the environment so the CSV importer
    (which reads $DB_PATH) targets the same database as this dashboard.
  - The repo root is added to sys.path so `scanners` imports cleanly when the app
    is launched directly (python dashboard/app.py).
"""
import os
import re
import sqlite3
import sys
import threading
from pathlib import Path

from flask import Flask, flash, redirect, render_template, request, url_for

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

DEFAULT_DB = REPO_ROOT / "db" / "results.db"
DB_PATH = Path(os.environ.get("DB_PATH", DEFAULT_DB))
# Make every module (notably the CSV importer) agree on the DB the dashboard
# is looking at.
os.environ["DB_PATH"] = str(DB_PATH)
SCHEMA_PATH = REPO_ROOT / "db" / "schema.sql"

from scanners.import_assets import import_assets_from_csv  # noqa: E402
from risk_engine.remediation import get_guidance  # noqa: E402
from orchestrator import run_scan_cycle  # noqa: E402

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET", "ttpr-dev-secret-change-me")

# A scan cycle takes minutes (nmap + nuclei), far longer than a request can
# block, so /scans/run launches run_scan_cycle() on a daemon thread and returns
# immediately. This in-process guard stops a second run from being launched
# while one is in flight; the scan_runs table (status='running') is the durable
# record the page reads, so progress still shows even after a restart.
_scan_lock = threading.Lock()
_scan_running = False


def _run_scan_async():
    global _scan_running
    try:
        run_scan_cycle()
    except Exception:
        app.logger.exception("Background scan cycle crashed")
    finally:
        with _scan_lock:
            _scan_running = False


def _scan_in_progress() -> bool:
    with _scan_lock:
        return _scan_running

# Bare hostname only (no scheme/path/port) -- e.g. "shop.example.com".
_DOMAIN_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)(\.[a-z0-9-]{1,63})+$")


def _clean_domain(raw: str) -> str | None:
    """Normalize user input down to a bare domain, or None if it isn't one."""
    value = (raw or "").strip().lower()
    value = re.sub(r"^https?://", "", value)
    value = value.split("/")[0].split(":")[0]
    return value if _DOMAIN_RE.match(value) else None


SEVERITY_ORDER_SQL = """
    CASE severity
        WHEN 'critical' THEN 1
        WHEN 'high' THEN 2
        WHEN 'medium' THEN 3
        WHEN 'low' THEN 4
        ELSE 5
    END
"""

# Every re-scan re-inserts the same open findings (there is no cross-run dedup
# upstream), so a host scanned twice shows each issue twice. Until that's fixed
# at the source, the "current open findings" views collapse to the most recent
# row per distinct issue. GROUP BY groups NULLs together (unlike a UNIQUE
# constraint), so open_port rows (cve_id NULL) and cve rows (service/port NULL)
# both dedupe correctly. Display-layer only: the DB still stores every run's rows.
LATEST_OPEN_FINDING_IDS = """
    SELECT MAX(id) FROM findings
    WHERE status = 'open'
    GROUP BY asset_id, finding_type, cve_id, service, port
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


@app.context_processor
def inject_last_scan():
    """Sidebar footer: date + finding count of the most recent scan run."""
    conn = get_db()
    try:
        row = conn.execute("""
            SELECT s.started_at,
                   (SELECT COUNT(*) FROM findings f WHERE f.run_id = s.id) AS n
            FROM scan_runs s
            ORDER BY s.started_at DESC
            LIMIT 1
        """).fetchone()
    except sqlite3.Error:
        row = None
    finally:
        conn.close()
    if not row or not row["started_at"]:
        return {"last_scan_note": None}
    stamp = str(row["started_at"]).split(".")[0]
    return {"last_scan_note": f"{stamp} · {row['n']} findings"}


# Plain-language answers for non-experts; rendered on the FAQ page.
_FAQ = [
    {"q": "What does PikaSeal actually do?",
     "a": "It looks at your organization the way an outsider on the internet would. It finds your "
          "public-facing websites, subdomains and servers, checks them for common weaknesses, and "
          "explains in plain English what to fix first. You don't need a security team to use it."},
    {"q": "Do I need to install anything on my website or servers?",
     "a": "No. PikaSeal is an external scanner, so it works entirely from the outside using your domain "
          "name. There's no agent, plugin or code to add to your site."},
    {"q": "Is it safe to run? Will a scan break my website?",
     "a": "Scans are read-only. They observe what's already exposed to the internet and never change, "
          "delete or log into anything. Normal scans put no meaningful load on a typical small-business site."},
    {"q": "Why do I have to \"authorize\" an asset before scanning it?",
     "a": "You should only scan things you own or run. Marking an asset as authorized is your confirmation "
          "that you're allowed to test it. Anything left \"Not authorized\" is tracked but never actively probed."},
    {"q": "I'm not technical. Will I understand the results?",
     "a": "That's the point of the tool. Every finding has a \"Why it matters\" and a \"How to fix it\" written "
          "for a non-security reader, and the Overview always tells you the single most important thing to fix first."},
    {"q": "What do the severity labels and the health score mean?",
     "a": "Severity (Critical, High, Medium, Low) is how serious an issue is. The health score is a simple "
          "0-100 grade of your overall exposure — higher is better. Together they tell you where to spend limited time."},
    {"q": "How often should I scan?",
     "a": "New weaknesses appear over time, so a regular schedule — for example weekly — keeps you ahead of them. "
          "You can also run a scan any time after making a change to your site."},
    {"q": "Is my scan data shared with anyone?",
     "a": "Your assets and findings stay in your own dashboard. PikaSeal is meant to give a small business or "
          "non-profit the same visibility a larger company would have, without sending your data around."},
    {"q": "This found an issue — what do I do next?",
     "a": "Open the finding, read the fix steps, and pass them to whoever manages that site (your web host, IT "
          "contractor, or volunteer). Most low-severity items, like outdated encryption settings, are quick "
          "configuration changes."},
]


@app.route("/")
def overview():
    conn = get_db()
    try:
        asset_count = conn.execute("SELECT COUNT(*) FROM assets").fetchone()[0]
        authorized_count = conn.execute(
            "SELECT COUNT(*) FROM assets WHERE authorized = 1"
        ).fetchone()[0]

        finding_count = conn.execute(
            f"SELECT COUNT(*) FROM findings "
            f"WHERE status = 'open' AND id IN ({LATEST_OPEN_FINDING_IDS})"
        ).fetchone()[0]

        severity_breakdown = conn.execute(f"""
            SELECT severity, COUNT(*) AS n
            FROM findings
            WHERE status = 'open' AND id IN ({LATEST_OPEN_FINDING_IDS})
            GROUP BY severity
            ORDER BY {SEVERITY_ORDER_SQL}
        """).fetchall()
        severity_counts = {row["severity"]: row["n"] for row in severity_breakdown}
        health = _health_score(severity_counts)

        kev_count = conn.execute(
            f"SELECT COUNT(*) FROM findings "
            f"WHERE kev_flag = 1 AND status = 'open' AND id IN ({LATEST_OPEN_FINDING_IDS})"
        ).fetchone()[0]

        top_finding_row = conn.execute(f"""
            SELECT
                f.id, f.finding_type, f.port, f.service,
                f.cve_id, f.cvss_score, f.kev_flag,
                f.risk_score, f.severity, f.description,
                a.domain, a.ip_address
            FROM findings f
            LEFT JOIN assets a ON a.id = f.asset_id
            WHERE f.status = 'open' AND f.id IN ({LATEST_OPEN_FINDING_IDS})
            ORDER BY f.risk_score DESC
            LIMIT 1
        """).fetchone()
        top_finding = None
        if top_finding_row is not None:
            top_finding = dict(top_finding_row)
            top_finding["guidance"] = get_guidance(top_finding)

        top_issues = conn.execute(f"""
            SELECT f.id, f.finding_type, f.risk_score, f.severity, f.cve_id, a.domain
            FROM findings f
            LEFT JOIN assets a ON a.id = f.asset_id
            WHERE f.status = 'open' AND f.id IN ({LATEST_OPEN_FINDING_IDS})
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

    where = ["f.status = 'open'", f"f.id IN ({LATEST_OPEN_FINDING_IDS})"]
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
        rows = conn.execute(f"""
            SELECT
                a.id, a.domain, a.ip_address, a.asset_type, a.authorized,
                a.status, a.first_seen, a.last_seen,
                SUM(CASE WHEN f.status = 'open' AND f.id IN ({LATEST_OPEN_FINDING_IDS}) THEN 1 ELSE 0 END) AS open_findings,
                SUM(CASE WHEN f.status = 'open' AND f.id IN ({LATEST_OPEN_FINDING_IDS}) AND f.severity = 'critical' THEN 1 ELSE 0 END) AS critical_findings
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


@app.route("/assets/import", methods=["POST"])
def import_assets():
    upload = request.files.get("file")
    if upload is None or not upload.filename:
        flash("Choose a CSV file to import.", "error")
        return redirect(url_for("assets"))

    authorize = request.form.get("authorize") == "on"
    try:
        summary = import_assets_from_csv(
            upload.stream, db_path=str(DB_PATH), authorize=authorize
        )
    except Exception as exc:  # unreadable file / bad encoding
        app.logger.exception("CSV import failed")
        flash(f"Could not read that file: {exc}", "error")
        return redirect(url_for("assets"))

    scope_note = " and added to scope" if authorize else ""
    flash(
        f"Imported {summary.imported} new "
        f"{'asset' if summary.imported == 1 else 'assets'}"
        f"{scope_note}, updated {summary.updated}.",
        "ok",
    )
    if summary.skipped:
        preview = "; ".join(
            f"line {s.line}: {s.reason}" for s in summary.skipped[:5]
        )
        more = "" if len(summary.skipped) <= 5 else f" (+{len(summary.skipped) - 5} more)"
        flash(f"Skipped {len(summary.skipped)}: {preview}{more}", "warn")
    return redirect(url_for("assets"))


@app.route("/assets/<int:asset_id>/authorize", methods=["POST"])
def set_authorization(asset_id: int):
    to = 1 if request.form.get("to") == "1" else 0
    conn = get_db()
    try:
        row = conn.execute(
            "SELECT domain FROM assets WHERE id = ?", (asset_id,)
        ).fetchone()
        if row is None:
            flash("That asset no longer exists.", "error")
            return redirect(url_for("assets"))
        conn.execute(
            "UPDATE assets SET authorized = ? WHERE id = ?", (to, asset_id)
        )
        conn.commit()
    finally:
        conn.close()

    verb = "added to scope" if to else "removed from scope"
    flash(f"{row['domain']} {verb}.", "ok")
    return redirect(url_for("assets"))


@app.route("/scans")
def scans():
    conn = get_db()
    try:
        authorized_count = conn.execute(
            "SELECT COUNT(*) FROM assets WHERE authorized = 1"
        ).fetchone()[0]

        rows = conn.execute("""
            SELECT id, started_at, finished_at, status, notes
            FROM scan_runs
            ORDER BY started_at DESC
            LIMIT 25
        """).fetchall()

        run_ids = [row["id"] for row in rows]
        counts: dict = {}
        if run_ids:
            placeholders = ",".join("?" * len(run_ids))
            for c in conn.execute(
                f"SELECT run_id, COUNT(*) AS n FROM findings "
                f"WHERE run_id IN ({placeholders}) GROUP BY run_id",
                run_ids,
            ):
                counts[c["run_id"]] = c["n"]
    finally:
        conn.close()

    scan_runs = []
    for row in rows:
        scan = dict(row)
        scan["finding_count"] = counts.get(row["id"], 0)
        scan_runs.append(scan)

    # Treat a run as in-progress if our thread flag is set OR a row is still
    # marked 'running' in the DB (covers a scan started before an app restart).
    db_running = any(row["status"] == "running" for row in rows)
    return render_template(
        "scans.html",
        scan_runs=scan_runs,
        authorized_count=authorized_count,
        scan_running=_scan_in_progress() or db_running,
    )


@app.route("/scans/run", methods=["POST"])
def run_scan():
    if _scan_in_progress():
        flash("A scan is already running — give it a moment to finish.", "warn")
        return redirect(url_for("scans"))

    conn = get_db()
    try:
        authorized_count = conn.execute(
            "SELECT COUNT(*) FROM assets WHERE authorized = 1"
        ).fetchone()[0]
    finally:
        conn.close()

    if authorized_count == 0:
        flash(
            "No assets are authorized for scanning yet. Add one to scope on the "
            "Assets page first — you should only scan things you own or run.",
            "warn",
        )
        return redirect(url_for("scans"))

    global _scan_running
    with _scan_lock:
        _scan_running = True
    threading.Thread(target=_run_scan_async, daemon=True).start()

    plural = "s" if authorized_count != 1 else ""
    flash(
        f"Scan started against {authorized_count} authorized asset{plural}. "
        "This can take a few minutes; results appear here as it finishes.",
        "ok",
    )
    return redirect(url_for("scans"))


@app.route("/faq")
def faq():
    return render_template("faq.html", faq=_FAQ)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
