from fastapi import FastAPI, BackgroundTasks, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger
import atexit
import sqlite3
import json
import uuid
import os
import sys
from datetime import datetime

PLAN_LIMITS = {
    "free":    2,   # 2 scans/month
    "starter": 10,  # 10 scans/month — ₹999/month
    "pro":     50,  # 50 scans/month — ₹2,999/month
    "agency":  999, # Unlimited — ₹4,999/month
}
# Add project root to path
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

app = FastAPI(
    title="HawkEye API",
    description="AI-Assisted Bug Hunting Framework API",
    version="1.0.0",
)

# Allow React frontend to call this API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    print(f"Unhandled server error: {exc}")
    return JSONResponse(
        status_code=500,
        content={"detail": f"Internal Server Error: {str(exc)}"},
    )

# ─────────────────────────────────────────
# DATABASE SETUP
# ─────────────────────────────────────────

DB_PATH = os.path.join(ROOT, "hawkeye.db")


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()

    # Original scans table
    conn.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id           TEXT PRIMARY KEY,
            target       TEXT NOT NULL,
            modules      TEXT NOT NULL,
            status       TEXT DEFAULT 'pending',
            risk_level   TEXT DEFAULT '',
            total        INTEGER DEFAULT 0,
            critical     INTEGER DEFAULT 0,
            high         INTEGER DEFAULT 0,
            medium       INTEGER DEFAULT 0,
            low          INTEGER DEFAULT 0,
            info         INTEGER DEFAULT 0,
            findings     TEXT DEFAULT '[]',
            report_html  TEXT DEFAULT '',
            report_json  TEXT DEFAULT '',
            created_at   TEXT NOT NULL,
            completed_at TEXT DEFAULT ''
        )
    """)

    # Monitored targets for differential scanning
    conn.execute("""
        CREATE TABLE IF NOT EXISTS targets (
            id           TEXT PRIMARY KEY,
            domain       TEXT UNIQUE NOT NULL,
            modules      TEXT DEFAULT 'headers',
            frequency    TEXT DEFAULT 'weekly',
            last_scan_id TEXT DEFAULT '',
            ai_enabled   BOOLEAN DEFAULT 0,
            fast_mode    BOOLEAN DEFAULT 1,
            created_at   TEXT NOT NULL,
            next_scan_at TEXT DEFAULT ''
        )
    """)

    # Diff reports
    conn.execute("""
        CREATE TABLE IF NOT EXISTS diff_reports (
            id           TEXT PRIMARY KEY,
            target_id    TEXT NOT NULL,
            old_scan_id  TEXT NOT NULL,
            new_scan_id  TEXT NOT NULL,
            new_count    INTEGER DEFAULT 0,
            fixed_count  INTEGER DEFAULT 0,
            worsened_count INTEGER DEFAULT 0,
            diff_json    TEXT DEFAULT '{}',
            created_at   TEXT NOT NULL
        )
    """)

    conn.commit()
    conn.close()


init_db()


# ─────────────────────────────────────────
# MODELS
# ─────────────────────────────────────────
class TargetRequest(BaseModel):
    domain:    str
    modules:   str  = "headers,web"
    frequency: str  = "weekly"
    ai:        bool = False
    fast:      bool = True

class ScanRequest(BaseModel):
    target:       str
    headers:      bool = False
    network:      bool = False
    web:          bool = False
    api:          bool = False
    ai:           bool = False
    fast:         bool = False
    stealth:      bool = False
    proxy:        str  = ""
    subdomains:   bool = False
    max_subs:     int  = 500
    login_url:    str  = ""
    username:     str  = ""
    password:     str  = ""
    token:        str  = ""
    token_header: str  = "Authorization"
    logic:        bool = False
    login_url2:   str  = ""
    username2:    str  = ""
    password2:    str  = ""
    headless:     bool = False
    recon:        bool = False
    rl_mode:  str = ""
    rl_steps: int = 10


# ─────────────────────────────────────────
# BACKGROUND SCAN TASK
# ─────────────────────────────────────────

def run_scan(scan_id: str, request: ScanRequest):
    """Execute scan job asynchronously."""
    conn = get_db()
    conn.execute("UPDATE scans SET status='running' WHERE id=?", (scan_id,))
    conn.commit()
    conn.close()

    all_findings = []
    target = request.target
    if not target.startswith("http://") and not target.startswith("https://"):
        target_url = f"http://{target}"
    else:
        target_url = target

    # Auth session setup if login url or token provided
    auth_session = None
    if request.login_url or request.token:
        try:
            from modules.auth_handler import create_authenticated_session
            auth_session, auth_result = create_authenticated_session(
                login_url    = request.login_url,
                username     = request.username,
                password     = request.password,
                token        = request.token,
                token_header = request.token_header,
                proxy        = request.proxy,
            )
            if not auth_result.get("success"):
                auth_session = None
        except Exception as e:
            print(f"Auth session error: {e}")
            auth_session = None

    try:
        # Subdomains
        if request.subdomains:
            try:
                from modules.subdomain_enum import discover_subdomains
                bare_domain = target_url.replace("https://", "").replace("http://", "").split("/")[0]
                result = discover_subdomains(bare_domain, active=True, passive=True)
                for sub_info in result.get("alive_subdomains", [])[:request.max_subs]:
                    sub_url = sub_info["final_url"]
                    sub_findings = []
                    if request.headers:
                        from modules.header_checker import scan_headers
                        sub_findings.extend(scan_headers(sub_url))
                    if request.network:
                        from modules.network_scanner import scan_network
                        sub_findings.extend(scan_network(sub_info["subdomain"], fast=True))
                    if request.web:
                        from modules.web_scanner import scan_web
                        sub_findings.extend(scan_web(sub_url, stealth=request.stealth, proxy=request.proxy))
                    if request.api:
                        from modules.api_tester import scan_api
                        sub_findings.extend(scan_api(sub_url, fast=True))
                    for f in sub_findings:
                        f["subdomain"] = sub_info["subdomain"]
                    all_findings.extend(sub_findings)
            except Exception as e:
                print(f"Subdomain enum error: {e}")

        # Headers
        if request.headers:
            try:
                from modules.header_checker import scan_headers
                all_findings.extend(scan_headers(target_url))
            except Exception as e:
                print(f"Header checker error: {e}")
                # ── RL MODE ──
        if request.rl_mode:
            from rl.inference import rl_guided_scan
            result = rl_guided_scan(
                target    = request.target,
                mode      = request.rl_mode,
                max_steps = request.rl_steps,
                proxy     = request.proxy,
                stealth   = request.stealth,
                verbose   = False,
            )
            if not result.get("error"):
                for f in result["findings"]:
                    f["rl_sequence"] = result["scan_sequence"]
                all_findings.extend(result["findings"])
        # Recon
        if request.recon:
            try:
                from modules.recon import scan_recon
                all_findings.extend(scan_recon(target_url))
            except Exception as e:
                print(f"Recon error: {e}")

        # Network
        if request.network:
            try:
                from modules.network_scanner import scan_network
                all_findings.extend(scan_network(target_url, fast=request.fast))
            except Exception as e:
                print(f"Network scanner error: {e}")

        # Web
        if request.web:
            try:
                from modules.web_scanner import scan_web_smart
                all_findings.extend(scan_web_smart(
                    target_url,
                    stealth=request.stealth,
                    proxy=request.proxy,
                    session=auth_session,
                    force_headless=request.headless,
                ))
            except Exception as e:
                print(f"Web scanner error: {e}")

        # API
        if request.api:
            try:
                from modules.api_tester import scan_api
                all_findings.extend(scan_api(target_url, fast=request.fast))
            except Exception as e:
                print(f"API scanner error: {e}")

        # Logic
        if request.logic:
            try:
                from modules.logic_scanner import scan_logic
                from modules.web_scanner import crawl_links
                import requests as req

                session_b = None
                if request.login_url2 and request.username2 and request.password2:
                    from modules.auth_handler import create_authenticated_session
                    session_b, _ = create_authenticated_session(
                        login_url=request.login_url2,
                        username=request.username2,
                        password=request.password2,
                        proxy=request.proxy,
                    )
                crawl_session = auth_session or req.Session()
                pages = crawl_links(target_url, crawl_session, depth=1)
                all_findings.extend(scan_logic(
                    target_url,
                    session_a=auth_session,
                    session_b=session_b,
                    pages=pages,
                ))
            except Exception as e:
                print(f"Logic scanner error: {e}")

        # AI Triage
        if request.ai and all_findings:
            try:
                from modules.ai_triage import triage_findings
                all_findings = triage_findings(all_findings)
            except Exception as e:
                print(f"AI triage error: {e}")

        # Generate Reports & Save
        from modules.reporter import count_by_severity, get_risk_level, generate_json, generate_html
        counts = count_by_severity(all_findings)
        risk_level = get_risk_level(counts)

        json_path = generate_json(all_findings, target_url)
        html_path = generate_html(all_findings, target_url)

        conn = get_db()
        conn.execute("""
            UPDATE scans
            SET status = 'completed',
                risk_level = ?,
                total = ?,
                critical = ?,
                high = ?,
                medium = ?,
                low = ?,
                info = ?,
                findings = ?,
                report_json = ?,
                report_html = ?,
                completed_at = ?
            WHERE id = ?
        """, (
            risk_level,
            len(all_findings),
            counts["critical"],
            counts["high"],
            counts["medium"],
            counts["low"],
            counts["info"],
            json.dumps(all_findings),
            json_path,
            html_path,
            datetime.now().isoformat(),
            scan_id,
        ))
        conn.commit()
        conn.close()

    except Exception as e:
        print(f"Scan background task error: {e}")
        conn = get_db()
        conn.execute("UPDATE scans SET status='failed' WHERE id=?", (scan_id,))
        conn.commit()
        conn.close()


def run_scan_with_diff(scan_id: str, request: ScanRequest,
                       target_id: str = None):
    """Run scan and compute diff against previous scan."""
    # First run the normal scan
    run_scan(scan_id, request)

    if target_id is None:
        return

    conn = get_db()
    try:
        # Get completed scan
        new_scan = conn.execute(
            "SELECT * FROM scans WHERE id=?", (scan_id,)
        ).fetchone()

        if not new_scan or new_scan["status"] != "completed":
            return

        # Get previous scan for this target
        prev_scan = conn.execute("""
            SELECT * FROM scans
            WHERE target LIKE ?
              AND status = 'completed'
              AND id != ?
            ORDER BY created_at DESC LIMIT 1
        """, (f"%{request.target.replace('http://', '').replace('https://', '')}%",
              scan_id)).fetchone()

        if not prev_scan:
            # First scan for this target — no diff yet
            conn.execute(
                "UPDATE targets SET last_scan_id=? WHERE id=?",
                (scan_id, target_id)
            )
            conn.commit()
            return

        # Compute diff
        from modules.diff_engine import build_diff_report
        old_dict = {
            "id":         prev_scan["id"],
            "findings":   json.loads(prev_scan["findings"] or "[]"),
            "risk_level": prev_scan["risk_level"],
            "created_at": prev_scan["created_at"],
            "target":     prev_scan["target"],
        }
        new_dict = {
            "id":         new_scan["id"],
            "findings":   json.loads(new_scan["findings"] or "[]"),
            "risk_level": new_scan["risk_level"],
            "created_at": new_scan["created_at"],
            "target":     new_scan["target"],
        }

        diff_report = build_diff_report(old_dict, new_dict)
        diff_id     = str(uuid.uuid4())

        conn.execute("""
            INSERT INTO diff_reports
            (id, target_id, old_scan_id, new_scan_id,
             new_count, fixed_count, worsened_count,
             diff_json, created_at)
            VALUES (?,?,?,?,?,?,?,?,?)
        """, (
            diff_id, target_id,
            prev_scan["id"], scan_id,
            diff_report["diff"]["summary"]["new"],
            diff_report["diff"]["summary"]["fixed"],
            diff_report["diff"]["summary"]["worsened"],
            json.dumps(diff_report),
            datetime.now().isoformat(),
        ))

        conn.execute(
            "UPDATE targets SET last_scan_id=? WHERE id=?",
            (scan_id, target_id)
        )
        conn.commit()

    except Exception as e:
        print(f"Diff error: {e}")
    finally:
        conn.close()   

# ─────────────────────────────────────────
# ROUTES
# ─────────────────────────────────────────

@app.get("/")
def root():
    return {
        "name":    "HawkEye API",
        "version": "1.0.0",
        "status":  "running",
    }


@app.post("/scan")
def start_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    # Validate target
    if not request.target or len(request.target) > 500:
        raise HTTPException(status_code=400, detail="Invalid target")
    if not request.target.startswith(("http://", "https://", "192.", "10.", "172.")):
        # Basic scheme check
        request.target = "https://" + request.target
    # Rest of function...

    scan_id = str(uuid.uuid4())
    modules = []
    if request.headers: modules.append("headers")
    if request.network: modules.append("network")
    if request.web:     modules.append("web")
    if request.api:     modules.append("api")
    if request.recon:   modules.append("recon")
    if request.logic:   modules.append("logic")

    conn = get_db()
    conn.execute("""
        INSERT INTO scans (id, target, modules, status, created_at)
        VALUES (?, ?, ?, 'pending', ?)
    """, (scan_id, request.target, ",".join(modules), datetime.now().isoformat()))
    conn.commit()
    conn.close()

    background_tasks.add_task(run_scan, scan_id, request)

    return {
        "scan_id": scan_id,
        "status":  "pending",
        "message": f"Scan started for {request.target}",
    }


@app.get("/scan/{scan_id}")
def get_scan(scan_id: str):
    """Get scan status and results."""
    conn = get_db()
    row  = conn.execute(
        "SELECT * FROM scans WHERE id=?", (scan_id,)
    ).fetchone()
    conn.close()

    if not row:
        raise HTTPException(status_code=404, detail="Scan not found")

    findings = json.loads(row["findings"]) if row["findings"] else []

    return {
        "id":           row["id"],
        "target":       row["target"],
        "modules":      row["modules"].split(","),
        "status":       row["status"],
        "risk_level":   row["risk_level"],
        "summary": {
            "total":    row["total"],
            "critical": row["critical"],
            "high":     row["high"],
            "medium":   row["medium"],
            "low":      row["low"],
            "info":     row["info"],
        },
        "findings":     findings,
        "created_at":   row["created_at"],
        "completed_at": row["completed_at"],
    }


@app.get("/scans")
def list_scans():
    """List all past scans."""
    conn  = get_db()
    rows  = conn.execute(
        "SELECT * FROM scans ORDER BY created_at DESC LIMIT 50"
    ).fetchall()
    conn.close()

    return [
        {
            "id":           r["id"],
            "target":       r["target"],
            "modules":      r["modules"].split(","),
            "status":       r["status"],
            "risk_level":   r["risk_level"],
            "total":        r["total"],
            "critical":     r["critical"],
            "high":         r["high"],
            "medium":       r["medium"],
            "low":          r["low"],
            "created_at":   r["created_at"],
            "completed_at": r["completed_at"],
        }
        for r in rows
    ]


@app.delete("/scan/{scan_id}")
def delete_scan(scan_id: str):
    """Delete a scan record."""
    conn = get_db()
    conn.execute("DELETE FROM scans WHERE id=?", (scan_id,))
    conn.commit()
    conn.close()
    return {"message": "Scan deleted"}


@app.get("/report/{scan_id}/json")
def download_json(scan_id: str):
    """Download JSON report."""
    conn = get_db()
    row  = conn.execute(
        "SELECT report_json FROM scans WHERE id=?", (scan_id,)
    ).fetchone()
    conn.close()

    if not row or not row["report_json"]:
        raise HTTPException(status_code=404, detail="Report not found")

    path = row["report_json"]
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail="Report file not found")

    return FileResponse(path, media_type="application/json",
                        filename="hawkeye_report.json")


@app.get("/report/{scan_id}/html")
def download_html(scan_id: str):
    """Download HTML report."""
    conn = get_db()
    row  = conn.execute(
        "SELECT report_html FROM scans WHERE id=?", (scan_id,)
    ).fetchone()
    conn.close()

    if not row or not row["report_html"]:
        raise HTTPException(status_code=404, detail="Report not found")

    path = row["report_html"]
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail="Report file not found")

    return FileResponse(path, media_type="text/html",
                        filename="hawkeye_report.html")


@app.get("/stats")
def get_stats():
    """Get overall statistics."""
    conn  = get_db()
    rows  = conn.execute("SELECT * FROM scans").fetchall()
    conn.close()

    total_scans    = len(rows)
    completed      = sum(1 for r in rows if r["status"] == "completed")
    total_findings = sum(r["total"]    for r in rows)
    total_critical = sum(r["critical"] for r in rows)
    total_high     = sum(r["high"]     for r in rows)

    return {
        "total_scans":    total_scans,
        "completed":      completed,
        "total_findings": total_findings,
        "total_critical": total_critical,
        "total_high":     total_high,
    }

# Simple API key auth for now
@app.post("/register")
def register(email: str, name: str):
    """Register new customer — generate API key"""
    import secrets
    api_key = secrets.token_urlsafe(32)
    conn = get_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id       TEXT PRIMARY KEY,
            email    TEXT UNIQUE,
            name     TEXT,
            api_key  TEXT UNIQUE,
            plan     TEXT DEFAULT 'free',
            scans_used INTEGER DEFAULT 0,
            created_at TEXT
        )
    """)
    import uuid
    user_id = str(uuid.uuid4())
    conn.execute(
        "INSERT INTO users VALUES (?,?,?,?,'free',0,?)",
        (user_id, email, name, api_key,
         datetime.now().isoformat())
    )
    conn.commit()
    conn.close()
    return {"api_key": api_key, "plan": "free"}
# ─────────────────────────────────────────
# TARGET MONITORING ROUTES
# ─────────────────────────────────────────

@app.post("/targets")
def add_target(request: TargetRequest):
    """Add a domain to monitored targets."""
    conn    = get_db()
    target_id = str(uuid.uuid4())
    try:
        conn.execute("""
            INSERT INTO targets
            (id, domain, modules, frequency, ai_enabled,
             fast_mode, created_at)
            VALUES (?,?,?,?,?,?,?)
        """, (
            target_id, request.domain, request.modules,
            request.frequency, request.ai, request.fast,
            datetime.now().isoformat(),
        ))
        conn.commit()
        return {
            "id":        target_id,
            "domain":    request.domain,
            "frequency": request.frequency,
            "message":   f"Target added — will scan {request.frequency}",
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
    finally:
        conn.close()


@app.get("/targets")
def list_targets():
    """List all monitored targets."""
    conn = get_db()
    rows = conn.execute(
        "SELECT * FROM targets ORDER BY created_at DESC"
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


@app.delete("/targets/{target_id}")
def delete_target(target_id: str):
    """Remove a target from monitoring."""
    conn = get_db()
    conn.execute("DELETE FROM targets WHERE id=?", (target_id,))
    conn.commit()
    conn.close()
    return {"message": "Target removed from monitoring"}


@app.post("/targets/{target_id}/scan")
def trigger_manual_scan(target_id: str,
                        background_tasks: BackgroundTasks):
    """Manually trigger a scan for a monitored target."""
    conn = get_db()
    row  = conn.execute(
        "SELECT * FROM targets WHERE id=?", (target_id,)
    ).fetchone()
    conn.close()

    if not row:
        raise HTTPException(status_code=404, detail="Target not found")

    modules = row["modules"].split(",")
    req = ScanRequest(
        target  = f"http://{row['domain']}",
        headers = "headers" in modules,
        network = "network" in modules,
        web     = "web"     in modules,
        api     = "api"     in modules,
        ai      = bool(row["ai_enabled"]),
        fast    = bool(row["fast_mode"]),
    )

    scan_id = str(uuid.uuid4())
    conn2   = get_db()
    conn2.execute("""
        INSERT INTO scans (id, target, modules, status, created_at)
        VALUES (?,?,?,'pending',?)
    """, (scan_id, req.target, row["modules"],
          datetime.now().isoformat()))
    conn2.commit()
    conn2.close()

    background_tasks.add_task(
        run_scan_with_diff, scan_id, req, target_id
    )
    return {"scan_id": scan_id, "status": "pending"}


@app.get("/targets/{target_id}/trend")
def get_trend(target_id: str):
    """Get risk trend for a monitored target."""
    conn = get_db()
    row  = conn.execute(
        "SELECT * FROM targets WHERE id=?", (target_id,)
    ).fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="Target not found")

    # Get last 10 scans for this target
    scans = conn.execute("""
        SELECT s.id, s.risk_level, s.total, s.critical,
               s.high, s.medium, s.low, s.created_at
        FROM scans s
        WHERE s.target LIKE ?
          AND s.status = 'completed'
        ORDER BY s.created_at DESC
        LIMIT 10
    """, (f"%{row['domain']}%",)).fetchall()
    conn.close()

    scan_list = [dict(s) for s in reversed(scans)]

    from modules.diff_engine import get_risk_trend
    trend = get_risk_trend(scan_list)

    return {
        "target_id": target_id,
        "domain":    row["domain"],
        "trend":     trend,
        "scans":     scan_list,
    }


@app.get("/targets/{target_id}/diff")
def get_latest_diff(target_id: str):
    """Get latest diff report for a target."""
    conn = get_db()
    row  = conn.execute("""
        SELECT * FROM diff_reports
        WHERE target_id = ?
        ORDER BY created_at DESC LIMIT 1
    """, (target_id,)).fetchone()
    conn.close()

    if not row:
        return {"message": "No diff available yet — need at least 2 scans"}

    return {
        "id":            row["id"],
        "target_id":     row["target_id"],
        "new_count":     row["new_count"],
        "fixed_count":   row["fixed_count"],
        "worsened_count":row["worsened_count"],
        "diff":          json.loads(row["diff_json"]),
        "created_at":    row["created_at"],
    }