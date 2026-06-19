import requests
import re
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse
from bs4 import BeautifulSoup
import os

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ─────────────────────────────────────────
# CONSTANTS
# ─────────────────────────────────────────

BASE_DIR     = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PAYLOADS_DIR = os.path.join(BASE_DIR, "payloads")

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Accept":     "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
}

SQLI_ERRORS = {
    "MySQL": [
        "you have an error in your sql syntax",
        "warning: mysql",
        "mysql_fetch",
        "mysql_num_rows",
        "supplied argument is not a valid mysql",
        "unclosed quotation mark",
        "quoted string not properly terminated",
    ],
    "PostgreSQL": [
        "pg_query()",
        "pg_exec()",
        "postgresql",
        "syntax error at or near",
    ],
    "MSSQL": [
        "microsoft ole db provider for sql server",
        "odbc sql server driver",
        "unclosed quotation mark",
        "sqlsrv_query()",
    ],
    "Oracle": [
        "ora-00933",
        "ora-00921",
        "oracle error",
        "quoted string not properly terminated",
    ],
    "SQLite": [
        "sqlite_exception",
        "sqlite error",
        "sqlite3.operationalerror",
        "no such table",
    ],
    "Generic": [
        "sql syntax",
        "syntax error",
        "invalid query",
        "sql command not properly ended",
        "division by zero",
        "supplied argument",
        "warning: pg_",
    ],
}


# ─────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────

def normalize_url(target: str) -> str:
    if not target.startswith(("http://", "https://")):
        return "http://" + target
    return target


def load_payloads(filename: str) -> list:
    path = os.path.join(PAYLOADS_DIR, filename)
    try:
        with open(path, "r") as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        return []


def get_all_forms(url: str, session: requests.Session) -> list:
    try:
        resp = session.get(url, timeout=10, verify=False)
        soup = BeautifulSoup(resp.text, "html.parser")
        return soup.find_all("form")
    except Exception:
        return []


def get_form_details(form) -> dict:
    action = form.attrs.get("action", "")
    method = form.attrs.get("method", "get").lower()
    inputs = []
    for tag in form.find_all(["input", "textarea", "select"]):
        input_type  = tag.attrs.get("type", "text")
        input_name  = tag.attrs.get("name", "")
        input_value = tag.attrs.get("value", "test")
        if input_name:
            inputs.append({
                "type":  input_type,
                "name":  input_name,
                "value": input_value,
            })
    return {"action": action, "method": method, "inputs": inputs}


def submit_form(form_details: dict, url: str, payload: str,
                session: requests.Session):
    target_url = urljoin(url, form_details["action"])
    data = {}
    for inp in form_details["inputs"]:
        if inp["type"] in ("text", "search", "email", "password", "hidden", ""):
            data[inp["name"]] = payload
        else:
            data[inp["name"]] = inp["value"]
    try:
        if form_details["method"] == "post":
            return session.post(target_url, data=data, timeout=10, verify=False)
        else:
            return session.get(target_url, params=data, timeout=10, verify=False)
    except Exception:
        return None


def inject_url_params(url: str, payload: str, session: requests.Session):
    parsed   = urlparse(url)
    params   = parse_qs(parsed.query)
    if not params:
        return None
    injected  = {k: payload for k in params}
    new_query = urlencode(injected)
    new_url   = urlunparse(parsed._replace(query=new_query))
    try:
        return session.get(new_url, timeout=10, verify=False)
    except Exception:
        return None


def detect_sqli_error(response_text: str) -> tuple:
    text_lower = response_text.lower()
    for db_type, patterns in SQLI_ERRORS.items():
        for pattern in patterns:
            if re.search(pattern, text_lower):
                return True, db_type
    return False, ""


# ─────────────────────────────────────────
# CRAWL — find all links + param URLs
# ─────────────────────────────────────────

def crawl_links(url: str, session: requests.Session, depth: int = 1) -> list:
    visited     = set()
    to_visit    = [url]
    base_domain = urlparse(url).netloc
    all_links   = [url]

    for _ in range(depth):
        next_level = []
        for link_url in to_visit:
            if link_url in visited:
                continue
            visited.add(link_url)
            try:
                resp = session.get(link_url, timeout=8, verify=False)
                soup = BeautifulSoup(resp.text, "html.parser")
                for tag in soup.find_all("a", href=True):
                    full_url = urljoin(link_url, tag["href"])
                    # Only same domain
                    if urlparse(full_url).netloc == base_domain:
                        if full_url not in visited:
                            next_level.append(full_url)
                            if full_url not in all_links:
                                all_links.append(full_url)
            except Exception:
                continue
        to_visit = next_level[:30]

    return list(set(all_links))


# ─────────────────────────────────────────
# XSS SCANNER
# ─────────────────────────────────────────

def scan_xss(url: str, session: requests.Session) -> list:
    findings = []
    payloads = load_payloads("xss.txt")
    if not payloads:
        return findings

    forms = get_all_forms(url, session)

    # Test forms
    for form in forms:
        details = get_form_details(form)
        for payload in payloads:
            response = submit_form(details, url, payload, session)
            if response and payload in response.text:
                target_url = urljoin(url, details["action"])
                findings.append({
                    "check":    "XSS: Reflected Cross-Site Scripting",
                    "severity": "high",
                    "detail":   f"XSS payload reflected in form at {target_url} | Payload: {payload[:60]}",
                    "module":   "web",
                    "url":      target_url,
                    "payload":  payload,
                })
                break

    # Test URL params
    parsed = urlparse(url)
    if parsed.query:
        for payload in payloads:
            response = inject_url_params(url, payload, session)
            if response and payload in response.text:
                findings.append({
                    "check":    "XSS: Reflected in URL Parameter",
                    "severity": "high",
                    "detail":   f"XSS reflected via URL param | URL: {url} | Payload: {payload[:60]}",
                    "module":   "web",
                    "url":      url,
                    "payload":  payload,
                })
                break

    return findings


# ─────────────────────────────────────────
# SQLi SCANNER
# ─────────────────────────────────────────

def scan_sqli(url: str, session: requests.Session) -> list:
    findings = []
    payloads = load_payloads("sqli.txt")
    if not payloads:
        return findings

    forms = get_all_forms(url, session)

    # Test forms
    for form in forms:
        details = get_form_details(form)
        for payload in payloads:
            response = submit_form(details, url, payload, session)
            if response:
                found, db_type = detect_sqli_error(response.text)
                if found:
                    target_url = urljoin(url, details["action"])
                    findings.append({
                        "check":    f"SQLi: SQL Injection ({db_type})",
                        "severity": "critical",
                        "detail":   f"SQL error ({db_type}) at {target_url} | Payload: {payload[:60]}",
                        "module":   "web",
                        "url":      target_url,
                        "payload":  payload,
                        "db_type":  db_type,
                    })
                    break

    # Test URL params
    parsed = urlparse(url)
    if parsed.query:
        for payload in payloads:
            response = inject_url_params(url, payload, session)
            if response:
                found, db_type = detect_sqli_error(response.text)
                if found:
                    findings.append({
                        "check":    f"SQLi: SQL Injection in URL Param ({db_type})",
                        "severity": "critical",
                        "detail":   f"SQL error ({db_type}) via URL param | URL: {url} | Payload: {payload[:60]}",
                        "module":   "web",
                        "url":      url,
                        "payload":  payload,
                        "db_type":  db_type,
                    })
                    break

    return findings


# ─────────────────────────────────────────
# MAIN ENTRY
# ─────────────────────────────────────────

def scan_web(target: str) -> list:
    findings = []
    url      = normalize_url(target)
    session  = requests.Session()
    session.headers.update(HEADERS)

    # Crawl pages
    pages = crawl_links(url, session, depth=1)

    xss_found  = []
    sqli_found = []

    for page in pages[:20]:
        xss_found.extend(scan_xss(page, session))
        sqli_found.extend(scan_sqli(page, session))

    # Deduplicate
    seen = set()
    for f in xss_found + sqli_found:
        key = f"{f['check']}:{f.get('url', '')}"
        if key not in seen:
            seen.add(key)
            findings.append(f)

    if not findings:
        findings.append({
            "check":    "Web Scan Complete",
            "severity": "info",
            "detail":   f"No XSS or SQLi found across {len(pages)} pages scanned",
            "module":   "web",
        })

    return findings