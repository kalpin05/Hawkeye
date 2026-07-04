from fastapi import FastAPI, BackgroundTasks, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel
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
    allow_methods=["*"],
    allow_headers=["*"],
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
    conn.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id          TEXT PRIMARY KEY,
            target      TEXT NOT NULL,
            modules     TEXT NOT NULL,
            status      TEXT DEFAULT 'pending',
            risk_level  TEXT DEFAULT '',
            total       INTEGER DEFAULT 0,
            critical    INTEGER DEFAULT 0,
            high        INTEGER DEFAULT 0,
            medium      INTEGER DEFAULT 0,
            low         INTEGER DEFAULT 0,
            info        INTEGER DEFAULT 0,
            findings    TEXT DEFAULT '[]',
            report_html TEXT DEFAULT '',
            report_json TEXT DEFAULT '',
            created_at  TEXT NOT NULL,
            completed_at TEXT DEFAULT ''
        )
    """)
    conn.commit()
    conn.close()


init_db()


# ─────────────────────────────────────────
# MODELS
# ─────────────────────────────────────────

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


# ─────────────────────────────────────────
# BACKGROUND SCAN TASK
# ─────────────────────────────────────────

def run_scan(scan_id: str, request: ScanRequest):
    conn = get_db()
    try:
        conn.execute("UPDATE scans SET status='running' WHERE id=?", (scan_id,))
        conn.commit()

        all_findings = []
        targets_scanned = [request.target]

        # ── SUBDOMAIN DISCOVERY ──
        if request.subdomains:
            from modules.subdomain_enum import discover_subdomains
            bare_domain = request.target.replace("https://", "").replace("http://", "").split("/")[0]
            disc = discover_subdomains(bare_domain, active=True, passive=True)

            all_findings.append({
                "check":    "Subdomain Discovery Complete",
                "severity": "info",
                "detail":   f"Found {disc['total_discovered']} subdomains, "
                            f"{disc['total_alive']} are live. "
                            f"Sources: {disc['sources']}",
                "module":   "recon",
            })

            scan_targets = [s["final_url"] for s in disc["alive_subdomains"][:request.max_subs]]
            scan_hosts   = [s["subdomain"] for s in disc["alive_subdomains"][:request.max_subs]]
            targets_scanned = scan_targets
        else:
            scan_targets = [request.target]
            scan_hosts   = [request.target]

        # ── SCAN EACH TARGET ──
        for t_url, t_host in zip(scan_targets, scan_hosts):
            if request.headers:
                from modules.header_checker import scan_headers
                findings = scan_headers(t_url)
                for f in findings: f["subdomain"] = t_host
                all_findings.extend(findings)

            if request.network:
                from modules.network_scanner import scan_network
                findings = scan_network(t_host, fast=request.fast)
                for f in findings: f["subdomain"] = t_host
                all_findings.extend(findings)

            if request.web:
                from modules.web_scanner import scan_web
                findings = scan_web(t_url, stealth=request.stealth, proxy=request.proxy)
                for f in findings: f["subdomain"] = t_host
                all_findings.extend(findings)

            if request.api:
                from modules.api_tester import scan_api
                findings = scan_api(t_url, fast=request.fast)
                for f in findings: f["subdomain"] = t_host
                all_findings.extend(findings)

        if request.ai and all_findings:
            from modules.ai_triage import triage_findings
            all_findings = triage_findings(all_findings)

        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in all_findings:
            sev = f.get("severity", "info").lower()
            counts[sev] = counts.get(sev, 0) + 1

        risk = (
            "CRITICAL" if counts["critical"] > 0 else
            "HIGH"     if counts["high"]     > 0 else
            "MEDIUM"   if counts["medium"]   > 0 else
            "LOW"      if counts["low"]      > 0 else
            "CLEAN"
        )

        # ── AUTH ──
        auth_session = None
        if request.login_url or request.token:
            from modules.auth_handler import create_authenticated_session
            auth_session, auth_result = create_authenticated_session(
                login_url    = request.login_url,
                username     = request.username,
                password     = request.password,
                token        = request.token,
                token_header = request.token_header,
                proxy        = request.proxy,
            )
            if auth_result["success"]:
                all_findings.append({
                    "check":    "Authentication Successful",
                    "severity": "info",
                    "detail":   f"Logged in via {auth_result['method']} — scanning as authenticated user",
                    "module":   "auth",
                })
            else:
                all_findings.append({
                    "check":    "Authentication Failed",
                    "severity": "medium",
                    "detail":   f"Could not authenticate: {auth_result.get('error')} — running unauthenticated scan",
                    "module":   "auth",
                })
                auth_session = None

        # Update web scan call to pass session
        if request.web:
            from modules.web_scanner import scan_web
            findings = scan_web(
                t_url,
                stealth=request.stealth,
                proxy=request.proxy,
                session=auth_session,
            )
            for f in findings: f["subdomain"] = t_host
            all_findings.extend(findings)
            
        from modules.reporter import generate_json, generate_html
        json_path = generate_json(all_findings, target=request.target)
        html_path = generate_html(all_findings, target=request.target)

        conn.execute("""
            UPDATE scans SET
                status='completed', risk_level=?, total=?, critical=?, high=?,
                medium=?, low=?, info=?, findings=?, report_json=?, report_html=?,
                completed_at=?
            WHERE id=?
        """, (
            risk, len(all_findings), counts["critical"], counts["high"],
            counts["medium"], counts["low"], counts["info"],
            json.dumps(all_findings), json_path, html_path,
            datetime.now().isoformat(), scan_id,
        ))
        conn.commit()
    # ── LOGIC SCANNER ──
        if request.logic:
            from modules.logic_scanner import scan_logic
            from modules.web_scanner import crawl_links
            import requests as req

            session_b = None
            if request.login_url2 and request.username2 and request.password2:
                from modules.auth_handler import create_authenticated_session
                session_b, auth_b = create_authenticated_session(
                    login_url=request.login_url2,
                    username=request.username2,
                    password=request.password2,
                    proxy=request.proxy,
                )
                if not auth_b["success"]:
                    session_b = None

            crawl_session = auth_session or req.Session()
            pages = crawl_links(t_url, crawl_session, depth=1)

            findings = scan_logic(
                t_url,
                session_a=auth_session,
                session_b=session_b,
                pages=pages,
            )
            for f in findings:
                f["subdomain"] = t_host
            all_findings.extend(findings)  

    except Exception as e:
        conn.execute("UPDATE scans SET status='failed' WHERE id=?", (scan_id,))
        conn.commit()
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
    """Start a new scan job."""
    if not any([request.headers, request.network, request.web, request.api]):
        raise HTTPException(
            status_code=400,
            detail="Select at least one module: headers, network, web, or api"
        )

    scan_id = str(uuid.uuid4())
    modules = []
    if request.headers: modules.append("headers")
    if request.network: modules.append("network")
    if request.web:     modules.append("web")
    if request.api:     modules.append("api")

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