import requests
import re
import json
import copy
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse
from bs4 import BeautifulSoup

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ─────────────────────────────────────────
# CONSTANTS
# ─────────────────────────────────────────

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Accept":     "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
}

ID_PARAMS = [
    "id", "user_id", "userid", "account_id", "order_id",
    "invoice_id", "profile_id", "customer_id", "record_id",
    "doc_id", "file_id", "uid", "pid", "cid", "item_id",
    "product_id", "post_id", "comment_id", "ticket_id",
    "report_id", "message_id", "chat_id", "group_id",
]

PRICE_PARAMS = [
    "price", "amount", "cost", "total", "subtotal",
    "value", "fee", "charge", "rate",
]

QUANTITY_PARAMS = [
    "qty", "quantity", "count", "num", "number",
    "amount", "units", "items",
]

ADMIN_PATTERNS = [
    "/admin", "/administrator", "/manage", "/management",
    "/dashboard/admin", "/control", "/panel",
    "/api/admin", "/api/v1/admin", "/api/users",
    "/api/v1/users", "/api/accounts", "/api/v1/accounts",
    "/users/all", "/accounts/all", "/reports/all",
    "/settings/global", "/config",
    "/internal", "/private", "/staff", "/superuser",
]

SENSITIVE_PATTERNS = {
    "password in response":  r'"password"\s*:\s*"[^"]{3,}"',
    "API key exposed":       r'"api[_-]?key"\s*:\s*"[^"]{8,}"',
    "secret exposed":        r'"secret"\s*:\s*"[^"]{8,}"',
    "private key":           r"-----BEGIN (RSA |EC )?PRIVATE KEY-----",
    "AWS access key":        r"AKIA[0-9A-Z]{16}",
    "JWT token exposed":     r"eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+",
    "credit card pattern":   r"\b(?:\d{4}[-\s]?){3}\d{4}\b",
    "token in response":     r'"(access_token|auth_token|refresh_token)"\s*:\s*"[^"]{8,}"',
}


# ─────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────

def safe_get(session: requests.Session, url: str,
             timeout: int = 10):
    try:
        return session.get(url, timeout=timeout, verify=False,
                           allow_redirects=True, headers=HEADERS)
    except Exception:
        return None


def safe_post(session: requests.Session, url: str,
              data: dict, timeout: int = 10):
    try:
        return session.post(url, data=data, timeout=timeout,
                            verify=False, allow_redirects=True)
    except Exception:
        return None


def get_forms(url: str, session: requests.Session) -> list:
    resp = safe_get(session, url)
    if not resp:
        return []
    soup = BeautifulSoup(resp.text, "html.parser")
    return soup.find_all("form")


def get_form_details(form, base_url: str) -> dict:
    action = urljoin(base_url, form.get("action", base_url))
    method = form.get("method", "get").lower()
    fields = {}
    for inp in form.find_all(["input", "select", "textarea"]):
        name  = inp.get("name", "")
        value = inp.get("value", "")
        if name:
            fields[name] = value
    return {"action": action, "method": method, "fields": fields}


def build_replay(method: str, url: str, data: dict = None) -> str:
    if method.upper() == "POST":
        body = "&".join(f"{k}={v}" for k, v in (data or {}).items())
        return f"POST {url}\nBody: {body}"
    params = "&".join(f"{k}={v}" for k, v in (data or {}).items())
    return f"GET {url}?{params}" if params else f"GET {url}"


def responses_differ_significantly(r1, r2,
                                   threshold: int = 100) -> bool:
    if r1 is None or r2 is None:
        return False
    if r1.status_code != r2.status_code:
        return True
    diff = abs(len(r1.text) - len(r2.text))
    return diff > threshold and r1.text != r2.text


# ─────────────────────────────────────────
# CHECK 1 — HORIZONTAL PRIVILEGE
# ─────────────────────────────────────────

def check_horizontal_privilege(session_a, session_b,
                                url: str) -> list:
    findings = []
    parsed   = urlparse(url)
    params   = parse_qs(parsed.query)

    if not params:
        return findings

    resp_a = safe_get(session_a, url)
    if not resp_a or resp_a.status_code not in (200, 201):
        return findings

    for param_name, param_values in params.items():
        if not any(ip in param_name.lower() for ip in ID_PARAMS):
            continue

        original_val  = param_values[0]
        resp_cross    = safe_get(session_b, url)
        if not resp_cross:
            continue

        if (resp_cross.status_code == 200 and
                resp_a.status_code == 200 and
                len(resp_cross.text) > 100 and
                not responses_differ_significantly(resp_a, resp_cross, 200)):
            findings.append({
                "check":    "IDOR: Horizontal Privilege Escalation",
                "severity": "high",
                "detail":   (
                    f"User B can access User A's resource via "
                    f"param '{param_name}'={original_val} at {url}"
                ),
                "module":   "logic",
                "url":      url,
                "param":    param_name,
                "replay":   build_replay("GET", url,
                                         {param_name: original_val}),
            })
            break

    return findings


# ─────────────────────────────────────────
# CHECK 2 — VERTICAL PRIVILEGE
# ─────────────────────────────────────────

def check_vertical_privilege(low_priv_session,
                              base_url: str) -> list:
    findings = []
    base     = base_url.rstrip("/")

    for path in ADMIN_PATTERNS:
        url  = base + path
        resp = safe_get(low_priv_session, url)
        if resp is None:
            continue

        if resp.status_code in (200, 201) and len(resp.text) > 50:
            body_lower = resp.text.lower()
            is_login_redirect = any(
                kw in body_lower for kw in
                ["please log in", "login required", "sign in to"]
            )
            if not is_login_redirect:
                findings.append({
                    "check":    "Vertical Privilege: Admin Endpoint Accessible",
                    "severity": "critical",
                    "detail":   (
                        f"Low-privilege user can access admin endpoint: "
                        f"{url} (HTTP {resp.status_code})"
                    ),
                    "module":   "logic",
                    "url":      url,
                    "replay":   build_replay("GET", url),
                })

    return findings


# ─────────────────────────────────────────
# CHECK 3 — PRICE MANIPULATION
# ─────────────────────────────────────────

def check_price_manipulation(session, url: str) -> list:
    findings = []
    forms    = get_forms(url, session)

    for form in forms:
        details      = get_form_details(form, url)
        fields       = details["fields"]
        price_fields = [
            f for f in fields
            if any(pp in f.lower() for pp in PRICE_PARAMS)
        ]
        if not price_fields:
            continue

        test_values = ["0", "-1", "0.001", "-999",
                       "0.00", "-0.01", "0.0000001"]

        for field in price_fields:
            for test_val in test_values:
                modified = {**fields, field: test_val}
                resp = (
                    safe_post(session, details["action"], modified)
                    if details["method"] == "post"
                    else safe_get(
                        session,
                        details["action"] + "?" + urlencode(modified)
                    )
                )
                if resp is None:
                    continue

                body_lower = resp.text.lower()
                success_kw = [
                    "success", "order placed", "confirmed",
                    "thank you", "payment", "checkout complete",
                    "order complete", "receipt",
                ]
                error_kw = [
                    "invalid", "error", "must be greater",
                    "positive", "minimum", "invalid amount",
                ]
                has_success = any(kw in body_lower for kw in success_kw)
                has_error   = any(kw in body_lower for kw in error_kw)

                if has_success and not has_error:
                    findings.append({
                        "check":    "Price Manipulation: Accepted Invalid Price",
                        "severity": "critical",
                        "detail":   (
                            f"Form accepted manipulated price '{test_val}' "
                            f"for field '{field}' at {details['action']}"
                        ),
                        "module":   "logic",
                        "url":      details["action"],
                        "replay":   build_replay(
                            details["method"],
                            details["action"], modified
                        ),
                    })
                    break

    return findings


# ─────────────────────────────────────────
# CHECK 4 — QUANTITY MANIPULATION
# ─────────────────────────────────────────

def check_quantity_manipulation(session, url: str) -> list:
    findings = []
    forms    = get_forms(url, session)

    for form in forms:
        details    = get_form_details(form, url)
        fields     = details["fields"]
        qty_fields = [
            f for f in fields
            if any(qp in f.lower() for qp in QUANTITY_PARAMS)
        ]
        if not qty_fields:
            continue

        test_values = ["-1", "-999", "0", "99999999",
                       "-0.5", "1.5", "2147483648"]

        for field in qty_fields:
            for test_val in test_values:
                modified = {**fields, field: test_val}
                resp = (
                    safe_post(session, details["action"], modified)
                    if details["method"] == "post"
                    else safe_get(
                        session,
                        details["action"] + "?" + urlencode(modified)
                    )
                )
                if resp is None:
                    continue

                body_lower = resp.text.lower()
                error_kw   = [
                    "invalid quantity", "must be positive",
                    "minimum quantity", "invalid amount",
                ]
                processed_kw = [
                    "cart", "added", "updated",
                    "total", "subtotal", "checkout",
                ]
                has_error     = any(kw in body_lower for kw in error_kw)
                was_processed = any(kw in body_lower for kw in processed_kw)

                if not has_error and resp.status_code == 200 and was_processed:
                    findings.append({
                        "check":    "Quantity Manipulation: Invalid Value Accepted",
                        "severity": "high",
                        "detail":   (
                            f"Form accepted invalid quantity '{test_val}' "
                            f"for field '{field}' at {details['action']}"
                        ),
                        "module":   "logic",
                        "url":      details["action"],
                        "replay":   build_replay(
                            details["method"],
                            details["action"], modified
                        ),
                    })
                    break

    return findings


# ─────────────────────────────────────────
# CHECK 5 — WORKFLOW SKIP
# ─────────────────────────────────────────

def check_workflow_skip(session, steps: list) -> list:
    findings = []

    if len(steps) < 2:
        return findings

    fresh = requests.Session()
    fresh.headers.update(HEADERS)

    for i in range(1, len(steps)):
        target_step = steps[i]
        resp        = safe_get(fresh, target_step)

        if resp is None:
            continue

        if resp.status_code == 200 and len(resp.text) > 100:
            body_lower = resp.text.lower()
            is_start   = any(kw in body_lower for kw in
                             ["step 1", "start here", "begin"])
            is_login   = any(kw in body_lower for kw in
                             ["log in", "sign in", "login"])

            if not is_start and not is_login:
                findings.append({
                    "check":    "Workflow Skip: Step Accessible Without Prerequisites",
                    "severity": "high",
                    "detail":   (
                        f"Step {i+1} ({target_step}) directly accessible "
                        f"without completing previous steps"
                    ),
                    "module":   "logic",
                    "url":      target_step,
                    "replay":   build_replay("GET", target_step),
                })

    return findings


# ─────────────────────────────────────────
# CHECK 6 — SENSITIVE DATA EXPOSURE
# ─────────────────────────────────────────

def check_sensitive_data(session, url: str) -> list:
    findings = []
    resp     = safe_get(session, url)

    if not resp or resp.status_code != 200:
        return findings

    body = resp.text
    for data_type, pattern in SENSITIVE_PATTERNS.items():
        if re.search(pattern, body, re.IGNORECASE):
            findings.append({
                "check":    f"Sensitive Data: {data_type.title()} Found",
                "severity": "high",
                "detail":   (
                    f"Page {url} exposes {data_type} in response body"
                ),
                "module":   "logic",
                "url":      url,
                "replay":   build_replay("GET", url),
            })

    return findings


# ─────────────────────────────────────────
# CHECK 7 — MASS ASSIGNMENT
# ─────────────────────────────────────────

def check_mass_assignment(session, url: str) -> list:
    findings          = []
    forms             = get_forms(url, session)
    privileged_fields = [
        "role", "is_admin", "admin", "is_superuser",
        "permission", "privilege", "level", "user_type",
        "account_type", "plan", "verified", "approved",
        "status", "balance", "credits",
    ]

    for form in forms:
        details = get_form_details(form, url)
        for priv_field in privileged_fields:
            modified = {**details["fields"], priv_field: "admin"}
            resp = (
                safe_post(session, details["action"], modified)
                if details["method"] == "post"
                else None
            )
            if resp is None:
                continue

            if priv_field in resp.text or "admin" in resp.text.lower():
                body_lower = resp.text.lower()
                if "welcome" in body_lower or "success" in body_lower:
                    findings.append({
                        "check":    f"Mass Assignment: Field '{priv_field}' Accepted",
                        "severity": "critical",
                        "detail":   (
                            f"Form at {details['action']} accepted injected "
                            f"privileged field '{priv_field}=admin'"
                        ),
                        "module":   "logic",
                        "url":      details["action"],
                        "replay":   build_replay(
                            "POST", details["action"], modified
                        ),
                    })
                    break

    return findings


# ─────────────────────────────────────────
# PUBLIC ALIASES — keep test_* names for CLI/API compatibility
# ─────────────────────────────────────────

def test_horizontal_privilege(session_a, session_b, url):
    return check_horizontal_privilege(session_a, session_b, url)

def test_vertical_privilege(low_priv_session, base_url):
    return check_vertical_privilege(low_priv_session, base_url)

def test_price_manipulation(session, url):
    return check_price_manipulation(session, url)

def test_quantity_manipulation(session, url):
    return check_quantity_manipulation(session, url)

def test_workflow_skip(session, steps):
    return check_workflow_skip(session, steps)

def test_sensitive_data_exposure(session, url):
    return check_sensitive_data(session, url)

def test_mass_assignment(session, url):
    return check_mass_assignment(session, url)


# ─────────────────────────────────────────
# MAIN ENTRY
# ─────────────────────────────────────────

def scan_logic(target: str, session_a=None,
               session_b=None, pages: list = None) -> list:
    findings = []

    if session_a is None:
        session_a = requests.Session()
        session_a.headers.update(HEADERS)

    test_pages = pages or [target]

    for page_url in test_pages[:20]:
        findings.extend(check_price_manipulation(session_a, page_url))
        findings.extend(check_quantity_manipulation(session_a, page_url))
        findings.extend(check_sensitive_data(session_a, page_url))
        findings.extend(check_mass_assignment(session_a, page_url))

        if session_b is not None:
            findings.extend(
                check_horizontal_privilege(session_a, session_b, page_url)
            )

    findings.extend(check_vertical_privilege(session_a, target))

    # Deduplicate
    seen   = set()
    deduped = []
    for f in findings:
        key = f"{f['check']}:{f.get('url', '')}"
        if key not in seen:
            seen.add(key)
            deduped.append(f)

    # Sort by severity
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    deduped.sort(key=lambda x: order.get(x["severity"], 5))

    if not deduped:
        deduped.append({
            "check":    "Logic Scan Complete",
            "severity": "info",
            "detail":   (
                f"No business logic vulnerabilities found "
                f"across {len(test_pages)} pages"
            ),
            "module":   "logic",
        })

    return deduped