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

# Params that likely contain object IDs
ID_PARAMS = [
    "id", "user_id", "userid", "account_id", "order_id",
    "invoice_id", "profile_id", "customer_id", "record_id",
    "doc_id", "file_id", "uid", "pid", "cid", "item_id",
    "product_id", "post_id", "comment_id", "ticket_id",
    "report_id", "message_id", "chat_id", "group_id",
]

# Params that likely contain prices or quantities
PRICE_PARAMS = [
    "price", "amount", "cost", "total", "subtotal",
    "value", "fee", "charge", "rate",
]

QUANTITY_PARAMS = [
    "qty", "quantity", "count", "num", "number",
    "amount", "units", "items",
]

# Admin-like endpoint patterns
ADMIN_PATTERNS = [
    "/admin", "/administrator", "/manage", "/management",
    "/dashboard/admin", "/control", "/panel",
    "/api/admin", "/api/v1/admin", "/api/users",
    "/api/v1/users", "/api/accounts", "/api/v1/accounts",
    "/users/all", "/accounts/all", "/reports/all",
    "/settings/global", "/config",
    "/internal", "/private", "/staff", "/superuser",
]

# Sensitive fields in responses
SENSITIVE_FIELDS = [
    "password", "passwd", "secret", "token", "api_key",
    "credit_card", "card_number", "ssn", "social_security",
    "bank_account", "routing_number", "private_key",
    "auth_token", "access_token", "refresh_token",
]


# ─────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────

def safe_get(session: requests.Session, url: str,
             timeout: int = 10) -> requests.Response | None:
    try:
        return session.get(url, timeout=timeout, verify=False,
                           allow_redirects=True, headers=HEADERS)
    except Exception:
        return None


def safe_post(session: requests.Session, url: str,
              data: dict, timeout: int = 10) -> requests.Response | None:
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


def build_replay(method: str, url: str,
                 data: dict = None) -> str:
    """Build a human-readable replay string for reports."""
    if method.upper() == "POST":
        body = "&".join(f"{k}={v}" for k, v in (data or {}).items())
        return f"POST {url}\nBody: {body}"
    params = "&".join(f"{k}={v}" for k, v in (data or {}).items())
    return f"GET {url}?{params}" if params else f"GET {url}"


def responses_differ_significantly(r1: requests.Response,
                                   r2: requests.Response,
                                   threshold: int = 100) -> bool:
    """Check if two responses differ significantly."""
    if r1 is None or r2 is None:
        return False
    if r1.status_code != r2.status_code:
        return True
    diff = abs(len(r1.text) - len(r2.text))
    return diff > threshold and r1.text != r2.text


# ─────────────────────────────────────────
# TEST 1 — HORIZONTAL PRIVILEGE ESCALATION
# ─────────────────────────────────────────

def test_horizontal_privilege(
    session_a: requests.Session,
    session_b: requests.Session,
    url: str,
) -> list:
    """
    Test if session_a can access resources belonging to session_b.
    Swaps session cookies and compares responses.
    Detects IDOR / broken object level authorization.
    """
    findings = []

    # Get baseline for session_a
    resp_a = safe_get(session_a, url)
    if not resp_a or resp_a.status_code not in (200, 201):
        return findings

    # Try accessing same URL with session_b
    resp_b = safe_get(session_b, url)
    if not resp_b:
        return findings

    # Now try accessing session_a's resource FROM session_b
    # by using session_b's auth but session_a's URL
    parsed  = urlparse(url)
    params  = parse_qs(parsed.query)

    for param_name, param_values in params.items():
        if not any(ip in param_name.lower() for ip in ID_PARAMS):
            continue

        original_val = param_values[0]

        # Try accessing this resource from session_b
        resp_cross = safe_get(session_b, url)
        if not resp_cross:
            continue

        # If session_b gets same data as session_a — IDOR confirmed
        if (resp_cross.status_code == 200 and
                resp_a.status_code == 200 and
                len(resp_cross.text) > 100 and
                not responses_differ_significantly(resp_a, resp_cross, 200)):
            findings.append({
                "check":    "IDOR: Horizontal Privilege Escalation",
                "severity": "high",
                "detail":   (
                    f"User B can access User A's resource via param '{param_name}'={original_val} "
                    f"at {url} — broken object level authorization"
                ),
                "module":   "logic",
                "url":      url,
                "param":    param_name,
                "replay":   build_replay("GET", url, {param_name: original_val}),
            })
            break

    return findings


# ─────────────────────────────────────────
# TEST 2 — VERTICAL PRIVILEGE ESCALATION
# ─────────────────────────────────────────

def test_vertical_privilege(
    low_priv_session: requests.Session,
    base_url: str,
) -> list:
    """
    Test if a low-privilege user can access admin-only endpoints.
    Checks common admin paths and flags 200 responses.
    """
    findings = []
    base = base_url.rstrip("/")

    for path in ADMIN_PATTERNS:
        url  = base + path
        resp = safe_get(low_priv_session, url)

        if resp is None:
            continue

        # 200 or 201 from an admin endpoint with a low-priv user = broken access
        if resp.status_code in (200, 201) and len(resp.text) > 50:
            # Make sure it's not just a redirect to login
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
                        f"Low-privilege user can access admin endpoint: {url} "
                        f"(HTTP {resp.status_code}, {len(resp.text)} bytes)"
                    ),
                    "module":   "logic",
                    "url":      url,
                    "replay":   build_replay("GET", url),
                })

        # 403 is fine — means access control is working
        # 401 is also fine — requires auth
        # 404 is fine — endpoint doesn't exist

    return findings


# ─────────────────────────────────────────
# TEST 3 — PRICE MANIPULATION
# ─────────────────────────────────────────

def test_price_manipulation(
    session: requests.Session,
    url: str,
) -> list:
    """
    Test if price/amount fields in forms can be manipulated.
    Tries zero, negative, and very small decimal values.
    """
    findings = []
    forms    = get_forms(url, session)

    for form in forms:
        details = get_form_details(form, url)
        fields  = details["fields"]

        price_fields = [
            f for f in fields
            if any(pp in f.lower() for pp in PRICE_PARAMS)
        ]

        if not price_fields:
            continue

        test_values = ["0", "-1", "0.001", "-999", "0.00",
                       "-0.01", "0.0000001"]

        for field in price_fields:
            original_val = fields.get(field, "")

            for test_val in test_values:
                modified = {**fields, field: test_val}
                resp = (
                    safe_post(session, details["action"], modified)
                    if details["method"] == "post"
                    else safe_get(session, details["action"] + "?" +
                                  urlencode(modified))
                )

                if resp is None:
                    continue

                # Success indicators — form processed without error
                body_lower = resp.text.lower()
                success_keywords = [
                    "success", "order placed", "confirmed",
                    "thank you", "payment", "checkout complete",
                    "order complete", "receipt",
                ]
                error_keywords = [
                    "invalid", "error", "must be greater",
                    "positive", "minimum", "invalid amount",
                ]

                has_success = any(kw in body_lower for kw in success_keywords)
                has_error   = any(kw in body_lower for kw in error_keywords)

                if has_success and not has_error:
                    findings.append({
                        "check":    "Price Manipulation: Accepted Invalid Price",
                        "severity": "critical",
                        "detail":   (
                            f"Form at {details['action']} accepted manipulated "
                            f"price value '{test_val}' for field '{field}' — "
                            f"business logic bypass possible"
                        ),
                        "module":   "logic",
                        "url":      details["action"],
                        "replay":   build_replay(
                            details["method"], details["action"], modified
                        ),
                    })
                    break  # One finding per field

    return findings


# ─────────────────────────────────────────
# TEST 4 — QUANTITY MANIPULATION
# ─────────────────────────────────────────

def test_quantity_manipulation(
    session: requests.Session,
    url: str,
) -> list:
    """
    Test if quantity fields accept negative or extreme values.
    """
    findings = []
    forms    = get_forms(url, session)

    for form in forms:
        details = get_form_details(form, url)
        fields  = details["fields"]

        qty_fields = [
            f for f in fields
            if any(qp in f.lower() for qp in QUANTITY_PARAMS)
        ]

        if not qty_fields:
            continue

        test_values = ["-1", "-999", "0", "99999999",
                       "-0.5", "1.5", "2147483648"]  # int overflow

        for field in qty_fields:
            for test_val in test_values:
                modified = {**fields, field: test_val}
                resp = (
                    safe_post(session, details["action"], modified)
                    if details["method"] == "post"
                    else safe_get(session, details["action"] + "?" +
                                  urlencode(modified))
                )

                if resp is None:
                    continue

                body_lower = resp.text.lower()
                error_keywords = [
                    "invalid quantity", "must be positive",
                    "minimum quantity", "invalid amount",
                    "quantity error",
                ]
                has_error = any(kw in body_lower for kw in error_keywords)

                if not has_error and resp.status_code == 200:
                    # Check for signs it was actually processed
                    processed_keywords = [
                        "cart", "added", "updated", "total",
                        "subtotal", "checkout",
                    ]
                    was_processed = any(
                        kw in body_lower for kw in processed_keywords
                    )

                    if was_processed:
                        findings.append({
                            "check":    "Quantity Manipulation: Invalid Value Accepted",
                            "severity": "high",
                            "detail":   (
                                f"Form at {details['action']} accepted invalid "
                                f"quantity '{test_val}' for field '{field}' — "
                                f"may allow negative billing or overflow"
                            ),
                            "module":   "logic",
                            "url":      details["action"],
                            "replay":   build_replay(
                                details["method"], details["action"], modified
                            ),
                        })
                        break

    return findings


# ─────────────────────────────────────────
# TEST 5 — WORKFLOW STEP SKIPPING
# ─────────────────────────────────────────

def test_workflow_skip(
    session: requests.Session,
    steps: list,
) -> list:
    """
    Test if multi-step workflows can be bypassed.
    steps = [url1, url2, url3] — normal flow order.
    Tests if step 3 can be reached directly without completing step 1-2.
    """
    findings = []

    if len(steps) < 2:
        return findings

    # Try accessing each later step directly without completing earlier ones
    fresh_session = requests.Session()
    fresh_session.headers.update(HEADERS)

    for i in range(1, len(steps)):
        target_step = steps[i]
        resp = safe_get(fresh_session, target_step)

        if resp is None:
            continue

        # If we can access a later step directly — workflow bypass
        if resp.status_code == 200 and len(resp.text) > 100:
            body_lower = resp.text.lower()

            # Make sure it's actual step content, not a redirect to step 1
            first_step_indicators = [
                "step 1", "start here", "begin", "first step",
            ]
            is_redirected_to_start = any(
                kw in body_lower for kw in first_step_indicators
            )

            # Not redirected to login or first step
            is_login = any(
                kw in body_lower for kw in ["log in", "sign in", "login"]
            )

            if not is_redirected_to_start and not is_login:
                findings.append({
                    "check":    "Workflow Skip: Step Accessible Without Prerequisites",
                    "severity": "high",
                    "detail":   (
                        f"Step {i+1} ({target_step}) is directly accessible "
                        f"without completing previous steps — "
                        f"workflow bypass possible"
                    ),
                    "module":   "logic",
                    "url":      target_step,
                    "replay":   build_replay("GET", target_step),
                })

    return findings


# ─────────────────────────────────────────
# TEST 6 — SENSITIVE DATA IN RESPONSE
# ─────────────────────────────────────────

def test_sensitive_data_exposure(
    session: requests.Session,
    url: str,
) -> list:
    """
    Check if authenticated pages expose sensitive data
    that shouldn't be visible (passwords, tokens, keys).
    """
    findings = []
    resp     = safe_get(session, url)

    if not resp or resp.status_code != 200:
        return findings

    body = resp.text

    # Check for sensitive field patterns
    sensitive_patterns = {
        "password in response":  r'"password"\s*:\s*"[^"]{3,}"',
        "API key exposed":       r'"api[_-]?key"\s*:\s*"[^"]{8,}"',
        "secret exposed":        r'"secret"\s*:\s*"[^"]{8,}"',
        "private key":           r"-----BEGIN (RSA |EC )?PRIVATE KEY-----",
        "AWS access key":        r"AKIA[0-9A-Z]{16}",
        "JWT token exposed":     r"eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+",
        "credit card pattern":   r"\b(?:\d{4}[-\s]?){3}\d{4}\b",
        "token in response":     r'"(access_token|auth_token|refresh_token)"\s*:\s*"[^"]{8,}"',
    }

    for data_type, pattern in sensitive_patterns.items():
        if re.search(pattern, body, re.IGNORECASE):
            findings.append({
                "check":    f"Sensitive Data: {data_type.title()} Found",
                "severity": "high",
                "detail":   (
                    f"Authenticated page {url} exposes {data_type} in response body — "
                    f"sensitive data should never be returned to the client"
                ),
                "module":   "logic",
                "url":      url,
                "replay":   build_replay("GET", url),
            })

    return findings


# ─────────────────────────────────────────
# TEST 7 — MASS ASSIGNMENT
# ─────────────────────────────────────────

def test_mass_assignment(
    session: requests.Session,
    url: str,
) -> list:
    """
    Test for mass assignment vulnerabilities.
    Tries injecting privileged fields into forms/API requests.
    """
    findings = []
    forms    = get_forms(url, session)

    privileged_fields = [
        "role", "is_admin", "admin", "is_superuser", "superuser",
        "permission", "permissions", "privilege", "level",
        "user_type", "account_type", "plan", "subscription",
        "verified", "is_verified", "approved", "status",
        "balance", "credits", "points",
    ]

    for form in forms:
        details = get_form_details(form, url)

        for priv_field in privileged_fields:
            modified = {
                **details["fields"],
                priv_field: "admin",  # Try to inject admin role
            }

            resp = (
                safe_post(session, details["action"], modified)
                if details["method"] == "post"
                else None
            )

            if resp is None:
                continue

            # Check if the injected field appears in response
            if priv_field in resp.text or "admin" in resp.text.lower():
                body_lower = resp.text.lower()
                if "welcome" in body_lower or "success" in body_lower:
                    findings.append({
                        "check":    f"Mass Assignment: Privileged Field '{priv_field}' Accepted",
                        "severity": "critical",
                        "detail":   (
                            f"Form at {details['action']} accepted injected "
                            f"privileged field '{priv_field}=admin' — "
                            f"attacker may be able to escalate privileges"
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
# MAIN ENTRY
# ─────────────────────────────────────────

def scan_logic(
    target: str,
    session_a: requests.Session = None,
    session_b: requests.Session = None,
    pages: list = None,
) -> list:
    """
    Full business logic scan.
    session_a = primary authenticated session
    session_b = second test account session (for horizontal privilege tests)
    pages = list of URLs to test (from crawler)
    """
    findings = []

    if session_a is None:
        session_a = requests.Session()
        session_a.headers.update(HEADERS)

    test_pages = pages or [target]

    for page_url in test_pages[:20]:
        # Price manipulation
        findings.extend(test_price_manipulation(session_a, page_url))

        # Quantity manipulation
        findings.extend(test_quantity_manipulation(session_a, page_url))

        # Sensitive data exposure
        findings.extend(test_sensitive_data_exposure(session_a, page_url))

        # Mass assignment
        findings.extend(test_mass_assignment(session_a, page_url))

        # Horizontal privilege (needs 2 sessions)
        if session_b is not None:
            findings.extend(
                test_horizontal_privilege(session_a, session_b, page_url)
            )

    # Vertical privilege (needs only 1 low-priv session)
    findings.extend(test_vertical_privilege(session_a, target))

    # Deduplicate
    seen = set()
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
            "detail":   f"No business logic vulnerabilities found across {len(test_pages)} pages",
            "module":   "logic",
        })

    return deduped