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
    ],
    "PostgreSQL": [
        "pg_query()", "pg_exec()", "postgresql", "syntax error at or near",
    ],
    "MSSQL": [
        "microsoft ole db provider for sql server",
        "odbc sql server driver", "unclosed quotation mark",
    ],
    "Oracle": [
        "ora-00933", "ora-00921", "oracle error",
        "quoted string not properly terminated",
    ],
    "SQLite": [
        "sqlite_exception", "sqlite error",
        "sqlite3.operationalerror", "no such table",
    ],
    "Generic": [
        "sql syntax", "syntax error", "invalid query",
        "sql command not properly ended", "division by zero",
        "supplied argument", "warning: pg_",
    ],
}

# SSRF redirect/url parameter names
SSRF_PARAMS = [
    "url", "redirect", "next", "return", "returnurl", "return_url",
    "goto", "dest", "destination", "target", "link", "src", "source",
    "path", "ref", "referer", "callback", "file", "load", "fetch",
    "open", "continue", "forward", "location", "view", "img",
]

# SSRF test payloads
SSRF_PAYLOADS = [
    "http://127.0.0.1",
    "http://localhost",
    "http://169.254.169.254",           # AWS metadata
    "http://169.254.169.254/latest/meta-data/",
    "http://192.168.0.1",
    "http://10.0.0.1",
    "http://0.0.0.0",
    "http://[::1]",                     # IPv6 localhost
    "http://127.0.0.1:22",             # SSH
    "http://127.0.0.1:3306",           # MySQL
    "file:///etc/passwd",              # LFI via SSRF
    "dict://127.0.0.1:6379/info",      # Redis
]

# IDOR patterns — numeric ID params likely to be vulnerable
IDOR_PARAMS = [
    "id", "user_id", "userid", "account", "account_id",
    "order", "order_id", "orderid", "invoice", "invoice_id",
    "profile", "profile_id", "customer", "customer_id",
    "record", "doc", "document", "file_id", "uid",
    "pid", "cid", "num", "no", "number",
]


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
# CRAWLER — fixed to properly collect links
# ─────────────────────────────────────────

def crawl_links(url: str, session: requests.Session, depth: int = 2) -> list:
    """
    Crawl target site up to given depth.
    Returns all unique same-domain URLs found including ones with params.
    """
    visited     = set()
    to_visit    = [url]
    base_domain = urlparse(url).netloc
    all_links   = []

    for _ in range(depth):
        next_level = []
        for link_url in to_visit:
            if link_url in visited:
                continue
            visited.add(link_url)
            if link_url not in all_links:
                all_links.append(link_url)

            try:
                resp = session.get(link_url, timeout=8, verify=False)
                soup = BeautifulSoup(resp.text, "html.parser")

                for tag in soup.find_all("a", href=True):
                    href     = tag["href"].strip()
                    full_url = urljoin(link_url, href)
                    parsed   = urlparse(full_url)

                    # Same domain only, skip anchors and mailto
                    if (parsed.netloc == base_domain and
                            parsed.scheme in ("http", "https") and
                            "#" not in full_url and
                            "mailto:" not in full_url and
                            full_url not in visited):
                        next_level.append(full_url)

            except Exception:
                continue

        to_visit = next_level[:40]  # Max 40 per depth level

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

    parsed = urlparse(url)
    if parsed.query:
        for payload in payloads:
            response = inject_url_params(url, payload, session)
            if response and payload in response.text:
                findings.append({
                    "check":    "XSS: Reflected in URL Parameter",
                    "severity": "high",
                    "detail":   f"XSS via URL param | URL: {url} | Payload: {payload[:60]}",
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
# IDOR SCANNER
# ─────────────────────────────────────────

def scan_idor(url: str, session: requests.Session) -> list:
    """
    Detect IDOR by finding numeric ID params and testing
    if incrementing/decrementing returns different valid responses.
    """
    findings = []
    parsed   = urlparse(url)
    params   = parse_qs(parsed.query)

    if not params:
        return findings

    for param_name, param_values in params.items():
        # Check if param name looks like an ID field
        is_id_param = any(
            idor_p in param_name.lower()
            for idor_p in IDOR_PARAMS
        )

        # Check if value is numeric
        original_value = param_values[0] if param_values else ""
        is_numeric     = original_value.isdigit()

        if not (is_id_param or is_numeric):
            continue

        try:
            orig_val = int(original_value)
        except (ValueError, TypeError):
            continue

        # Get baseline response
        try:
            baseline = session.get(url, timeout=10, verify=False)
            baseline_len = len(baseline.text)
            baseline_status = baseline.status_code
        except Exception:
            continue

        # Test adjacent IDs
        test_values = [
            orig_val - 1,
            orig_val + 1,
            orig_val + 100,
            1,
            2,
            0,
        ]

        for test_val in test_values:
            if test_val < 0:
                continue
            test_params = {k: (str(test_val) if k == param_name else v[0])
                          for k, v in params.items()}
            test_query  = urlencode(test_params)
            test_url    = urlunparse(parsed._replace(query=test_query))

            try:
                resp = session.get(test_url, timeout=10, verify=False)

                # IDOR indicators:
                # 1. Got 200 with different content (different user data)
                # 2. Significant content length difference
                content_diff = abs(len(resp.text) - baseline_len)
                different_content = (
                    resp.status_code == 200 and
                    baseline_status == 200 and
                    content_diff > 50 and
                    resp.text != baseline.text
                )

                if different_content:
                    findings.append({
                        "check":    f"IDOR: Insecure Direct Object Reference",
                        "severity": "high",
                        "detail":   (
                            f"Param '{param_name}' changed from {orig_val} to {test_val} "
                            f"returned different content ({content_diff} bytes diff) at {url}"
                        ),
                        "module":   "web",
                        "url":      test_url,
                        "param":    param_name,
                        "original": str(orig_val),
                        "tested":   str(test_val),
                    })
                    break  # One finding per param is enough

            except Exception:
                continue

    return findings


# ─────────────────────────────────────────
# SSRF SCANNER
# ─────────────────────────────────────────

def scan_ssrf(url: str, session: requests.Session) -> list:
    """
    Detect open redirect and SSRF entry points by:
    1. Finding URL/redirect params in links and forms
    2. Testing with internal IP payloads
    3. Checking response for signs of successful SSRF
    """
    findings      = []
    parsed        = urlparse(url)
    params        = parse_qs(parsed.query)
    ssrf_findings = []

    # Check URL params for SSRF-prone parameter names
    for param_name in params:
        if any(sp in param_name.lower() for sp in SSRF_PARAMS):

            for payload in SSRF_PAYLOADS[:6]:  # Test first 6 payloads
                test_params = {k: (payload if k == param_name else v[0])
                               for k, v in params.items()}
                test_query  = urlencode(test_params)
                test_url    = urlunparse(parsed._replace(query=test_query))

                try:
                    resp = session.get(
                        test_url, timeout=8, verify=False,
                        allow_redirects=False,
                    )

                    # Open redirect detection
                    if resp.status_code in (301, 302, 303, 307, 308):
                        location = resp.headers.get("Location", "")
                        if any(internal in location for internal in
                               ["127.0.0.1", "localhost", "169.254", "192.168", "10."]):
                            ssrf_findings.append({
                                "check":    "SSRF: Open Redirect to Internal Host",
                                "severity": "critical",
                                "detail":   (
                                    f"Param '{param_name}' redirects to internal "
                                    f"address: {location} | URL: {url}"
                                ),
                                "module":   "web",
                                "url":      test_url,
                                "payload":  payload,
                            })
                        else:
                            ssrf_findings.append({
                                "check":    "SSRF: Open Redirect Detected",
                                "severity": "medium",
                                "detail":   (
                                    f"Param '{param_name}' causes redirect to "
                                    f"user-controlled URL | Payload: {payload[:60]}"
                                ),
                                "module":   "web",
                                "url":      test_url,
                                "payload":  payload,
                            })
                        break

                    # Check response body for SSRF indicators
                    body_lower = resp.text.lower()
                    ssrf_indicators = [
                        "root:x:0:0",            # /etc/passwd
                        "aws_secret_access_key", # AWS creds
                        "ami-id",                # AWS metadata
                        "connection refused",    # Internal connection attempt
                        "failed to connect",
                    ]
                    for indicator in ssrf_indicators:
                        if indicator in body_lower:
                            ssrf_findings.append({
                                "check":    "SSRF: Server-Side Request Forgery",
                                "severity": "critical",
                                "detail":   (
                                    f"SSRF confirmed via param '{param_name}' — "
                                    f"internal response indicator found | Payload: {payload[:60]}"
                                ),
                                "module":   "web",
                                "url":      test_url,
                                "payload":  payload,
                            })
                            break

                except Exception:
                    continue

    # Also scan page links for open redirect patterns
    try:
        resp = session.get(url, timeout=10, verify=False)
        soup = BeautifulSoup(resp.text, "html.parser")

        for tag in soup.find_all("a", href=True):
            href = tag["href"]
            full = urljoin(url, href)
            fp   = urlparse(full)
            fq   = parse_qs(fp.query)

            for param_name in fq:
                if any(sp in param_name.lower() for sp in SSRF_PARAMS):
                    ssrf_findings.append({
                        "check":    "SSRF: Potential Redirect Parameter Found",
                        "severity": "low",
                        "detail":   (
                            f"URL parameter '{param_name}' accepts URLs — "
                            f"potential open redirect/SSRF entry point at {full[:100]}"
                        ),
                        "module":   "web",
                        "url":      full,
                        "param":    param_name,
                    })
    except Exception:
        pass

    findings.extend(ssrf_findings)
    return findings


# ─────────────────────────────────────────
# MAIN ENTRY
# ─────────────────────────────────────────

def scan_web(target: str) -> list:
    """
    Full web vulnerability scan:
    XSS + SQLi (Sprint 4) + IDOR + SSRF (Sprint 5)
    Crawls site and tests all discovered pages.
    """
    findings = []
    url      = normalize_url(target)
    session  = requests.Session()
    session.headers.update(HEADERS)

    # Crawl — now depth=2 to find more pages
    pages = crawl_links(url, session, depth=2)

    all_found = []
    for page in pages[:25]:  # Test up to 25 pages
        all_found.extend(scan_xss(page, session))
        all_found.extend(scan_sqli(page, session))
        all_found.extend(scan_idor(page, session))
        all_found.extend(scan_ssrf(page, session))

    # Deduplicate by check + url
    seen = set()
    for f in all_found:
        key = f"{f['check']}:{f.get('url', '')}"
        if key not in seen:
            seen.add(key)
            findings.append(f)

    # Sort by severity
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda x: order.get(x["severity"], 5))

    if not findings:
        findings.append({
            "check":    "Web Scan Complete",
            "severity": "info",
            "detail":   f"No vulnerabilities detected across {len(pages)} pages scanned",
            "module":   "web",
        })

    return findings