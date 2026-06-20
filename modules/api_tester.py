import requests
import re
import json
import time
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ─────────────────────────────────────────
# CONSTANTS
# ─────────────────────────────────────────

HEADERS = {
    "User-Agent":   "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Accept":       "application/json, text/html, */*",
    "Content-Type": "application/json",
}

# Common API paths to probe
API_WORDLIST = [
    "/api", "/api/v1", "/api/v2", "/api/v3",
    "/api/users", "/api/user", "/api/admin",
    "/api/login", "/api/auth", "/api/token",
    "/api/register", "/api/signup",
    "/api/profile", "/api/account",
    "/api/orders", "/api/order",
    "/api/products", "/api/items",
    "/api/config", "/api/settings",
    "/api/debug", "/api/test",
    "/api/health", "/api/status",
    "/api/docs", "/api/swagger",
    "/api/graphql", "/graphql",
    "/rest", "/rest/v1", "/rest/v2",
    "/v1", "/v2", "/v3",
    "/swagger", "/swagger-ui",
    "/swagger.json", "/openapi.json",
    "/api-docs", "/api/documentation",
    "/admin/api", "/backend/api",
    "/internal/api", "/private/api",
    "/.well-known/openid-configuration",
    "/actuator", "/actuator/health",
    "/actuator/env", "/actuator/mappings",
]

# Sensitive data patterns to flag in responses
SENSITIVE_PATTERNS = {
    "password":    r"\"password\"\s*:\s*\"[^\"]+\"",
    "token":       r"\"(token|access_token|auth_token|jwt)\"\s*:\s*\"[^\"]+\"",
    "secret":      r"\"(secret|api_secret|client_secret)\"\s*:\s*\"[^\"]+\"",
    "credit_card": r"\b(?:\d{4}[-\s]?){3}\d{4}\b",
    "ssn":         r"\b\d{3}-\d{2}-\d{4}\b",
    "email":       r"\"email\"\s*:\s*\"[^\"@]+@[^\"]+\"",
    "private_key": r"-----BEGIN (RSA |EC )?PRIVATE KEY-----",
    "aws_key":     r"AKIA[0-9A-Z]{16}",
}


# ─────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────

def normalize_url(target: str) -> str:
    if not target.startswith(("http://", "https://")):
        return "http://" + target
    return target.rstrip("/")


def is_json_response(response: requests.Response) -> bool:
    ct = response.headers.get("Content-Type", "")
    return "application/json" in ct or "text/json" in ct


def safe_get(session: requests.Session, url: str,
             headers: dict = None, timeout: int = 8) -> requests.Response | None:
    try:
        return session.get(
            url, headers=headers, timeout=timeout,
            verify=False, allow_redirects=True,
        )
    except Exception:
        return None


# ─────────────────────────────────────────
# CHECK 1 — ENDPOINT DISCOVERY
# ─────────────────────────────────────────

def discover_endpoints(base_url: str, session: requests.Session,
                       fast: bool = False) -> list:
    """
    Discover API endpoints.
    fast=True uses shorter wordlist and skips JS parsing.
    """
    found = []
    base  = normalize_url(base_url)

    # Shorter wordlist for fast mode
    wordlist = API_WORDLIST[:15] if fast else API_WORDLIST

    # Wordlist probe
    for path in wordlist:
        url = base + path
        try:
            resp = session.get(url, timeout=4, verify=False)
            if resp and resp.status_code not in (404, 410):
                found.append({
                    "url":    url,
                    "status": resp.status_code,
                    "size":   len(resp.text),
                })
        except Exception:
            continue

    # Skip JS parsing in fast mode
    if not fast:
        try:
            resp = session.get(base, timeout=5, verify=False)
            if resp:
                soup    = BeautifulSoup(resp.text, "html.parser")
                js_urls = [
                    urljoin(base, tag["src"])
                    for tag in soup.find_all("script", src=True)
                ]
                for js_url in js_urls[:5]:
                    js_resp = session.get(js_url, timeout=4, verify=False)
                    if js_resp:
                        api_paths = re.findall(
                            r'["\'](/api/[^"\'?\s]{2,60})["\']',
                            js_resp.text
                        )
                        for path in api_paths:
                            full = urljoin(base, path)
                            if not any(e["url"] == full for e in found):
                                found.append({"url": full, "status": 0, "size": 0})
        except Exception:
            pass

    # robots.txt
    try:
        robots = session.get(base + "/robots.txt", timeout=4, verify=False)
        if robots and robots.status_code == 200:
            disallowed = re.findall(r"Disallow:\s*(/\S+)", robots.text)
            for path in disallowed:
                if "api" in path.lower() or "admin" in path.lower():
                    found.append({"url": base + path, "status": 0, "size": 0})
    except Exception:
        pass

    return found

    # 2. Extract from JS files
    try:
        resp = safe_get(session, base)
        if resp:
            soup    = BeautifulSoup(resp.text, "html.parser")
            js_urls = [
                urljoin(base, tag["src"])
                for tag in soup.find_all("script", src=True)
            ]
            for js_url in js_urls[:10]:
                js_resp = safe_get(session, js_url)
                if js_resp:
                    # Find API paths in JS
                    api_paths = re.findall(
                        r'["\'](/api/[^"\'?\s]{2,60})["\']',
                        js_resp.text
                    )
                    for path in api_paths:
                        full = urljoin(base, path)
                        if not any(e["url"] == full for e in found):
                            found.append({
                                "url":    full,
                                "status": 0,
                                "size":   0,
                            })
    except Exception:
        pass

    # 3. robots.txt
    try:
        robots = safe_get(session, base + "/robots.txt")
        if robots and robots.status_code == 200:
            disallowed = re.findall(r"Disallow:\s*(/\S+)", robots.text)
            for path in disallowed:
                if "api" in path.lower() or "admin" in path.lower():
                    found.append({
                        "url":    base + path,
                        "status": 0,
                        "size":   0,
                    })
    except Exception:
        pass

    return found


# ─────────────────────────────────────────
# CHECK 2 — BROKEN AUTHENTICATION
# ─────────────────────────────────────────

def check_broken_auth(endpoints: list, session: requests.Session) -> list:
    """
    Test endpoints for broken authentication:
    - Accessible without any auth token
    - Accepts invalid/empty tokens
    - Returns 200 on auth endpoints without credentials
    """
    findings = []

    auth_keywords = [
        "user", "admin", "profile", "account",
        "order", "dashboard", "private", "secret",
        "config", "setting", "internal",
    ]

    for ep in endpoints:
        url    = ep["url"]
        status = ep.get("status", 0)

        # Only test endpoints that responded
        if status == 0:
            resp = safe_get(session, url)
            if not resp:
                continue
            status = resp.status_code
        else:
            resp = safe_get(session, url)
            if not resp:
                continue

        # Flag sensitive endpoints accessible without auth
        url_lower = url.lower()
        is_sensitive = any(kw in url_lower for kw in auth_keywords)

        if is_sensitive and status == 200:
            findings.append({
                "check":    "Broken Auth: Sensitive Endpoint Accessible Without Auth",
                "severity": "high",
                "detail":   f"Endpoint {url} returned 200 without authentication",
                "module":   "api",
                "url":      url,
            })

        # Test with invalid auth tokens
        invalid_tokens = [
            "Bearer invalid_token_12345",
            "Bearer null",
            "Bearer undefined",
            "Bearer ",
        ]
        for token in invalid_tokens:
            token_resp = safe_get(
                session, url,
                headers={"Authorization": token}
            )
            if token_resp and token_resp.status_code == 200 and is_sensitive:
                findings.append({
                    "check":    "Broken Auth: Invalid Token Accepted",
                    "severity": "critical",
                    "detail":   f"Endpoint {url} accepted invalid token: {token}",
                    "module":   "api",
                    "url":      url,
                })
                break

    return findings


# ─────────────────────────────────────────
# CHECK 3 — RATE LIMITING
# ─────────────────────────────────────────

def check_rate_limiting(endpoints: list, session: requests.Session) -> list:
    """
    Send rapid requests to detect missing rate limiting.
    Flags endpoints that never return 429.
    """
    findings  = []
    test_eps  = [
        ep for ep in endpoints
        if any(kw in ep["url"].lower() for kw in
               ["login", "auth", "token", "register", "signup", "password"])
    ][:5]  # Only test auth endpoints, max 5

    for ep in test_eps:
        url       = ep["url"]
        got_429   = False
        responses = []

        for i in range(20):
            resp = safe_get(session, url)
            if resp:
                responses.append(resp.status_code)
                if resp.status_code == 429:
                    got_429 = True
                    break
            time.sleep(0.1)

        if responses and not got_429:
            findings.append({
                "check":    "Missing Rate Limiting",
                "severity": "medium",
                "detail":   (
                    f"Endpoint {url} did not return 429 after "
                    f"20 rapid requests — brute force risk"
                ),
                "module":   "api",
                "url":      url,
            })

    return findings


# ─────────────────────────────────────────
# CHECK 4 — EXCESSIVE DATA EXPOSURE
# ─────────────────────────────────────────

def check_excessive_data(endpoints: list, session: requests.Session) -> list:
    """
    Check API responses for sensitive data being exposed:
    passwords, tokens, secrets, PII in JSON responses.
    """
    findings = []

    for ep in endpoints:
        url  = ep["url"]
        resp = safe_get(session, url)
        if not resp or resp.status_code != 200:
            continue

        body = resp.text

        for data_type, pattern in SENSITIVE_PATTERNS.items():
            if re.search(pattern, body, re.IGNORECASE):
                findings.append({
                    "check":    f"Excessive Data Exposure: {data_type.replace('_', ' ').title()} Exposed",
                    "severity": "high",
                    "detail":   (
                        f"API endpoint {url} returns {data_type.replace('_', ' ')} "
                        f"in response — filter sensitive fields server-side"
                    ),
                    "module":   "api",
                    "url":      url,
                    "data_type": data_type,
                })

    return findings


# ─────────────────────────────────────────
# CHECK 5 — SECURITY HEADERS ON API
# ─────────────────────────────────────────

def check_api_security_headers(base_url: str, session: requests.Session) -> list:
    """
    Check API-specific security headers:
    CORS misconfiguration, missing security headers.
    """
    findings = []
    url      = normalize_url(base_url)

    # CORS check
    resp = safe_get(
        session, url,
        headers={"Origin": "https://evil.com"}
    )
    if resp:
        acao = resp.headers.get("Access-Control-Allow-Origin", "")
        acac = resp.headers.get("Access-Control-Allow-Credentials", "")

        if acao == "*":
            findings.append({
                "check":    "CORS: Wildcard Origin Allowed",
                "severity": "medium",
                "detail":   "API allows requests from any origin (*) — restrict to known domains",
                "module":   "api",
                "url":      url,
            })
        elif "evil.com" in acao:
            findings.append({
                "check":    "CORS: Arbitrary Origin Reflected",
                "severity": "high",
                "detail":   (
                    f"API reflects arbitrary Origin header ({acao}) — "
                    f"any site can make cross-origin requests"
                ),
                "module":   "api",
                "url":      url,
            })

        if acac.lower() == "true" and acao != "":
            findings.append({
                "check":    "CORS: Credentials Allowed with Permissive Origin",
                "severity": "high",
                "detail":   "API allows credentials with permissive CORS — CSRF/data theft risk",
                "module":   "api",
                "url":      url,
            })

    # Check for API key in URL (bad practice)
    resp2 = safe_get(session, url)
    if resp2:
        api_key_patterns = [
            r"[?&]api[_-]?key=([^&\s]{8,})",
            r"[?&]token=([^&\s]{8,})",
            r"[?&]secret=([^&\s]{8,})",
            r"[?&]auth=([^&\s]{8,})",
        ]
        for pattern in api_key_patterns:
            if re.search(pattern, url, re.IGNORECASE):
                findings.append({
                    "check":    "API Key in URL",
                    "severity": "high",
                    "detail":   "API key/token passed in URL — use Authorization header instead",
                    "module":   "api",
                    "url":      url,
                })
                break

    return findings


# ─────────────────────────────────────────
# CHECK 6 — SWAGGER / API DOCS EXPOSED
# ─────────────────────────────────────────

def check_exposed_docs(base_url: str, session: requests.Session) -> list:
    """Check if API documentation is publicly exposed."""
    findings  = []
    base      = normalize_url(base_url)
    doc_paths = [
        "/swagger", "/swagger-ui", "/swagger-ui.html",
        "/swagger.json", "/swagger.yaml",
        "/openapi.json", "/openapi.yaml",
        "/api-docs", "/api/docs",
        "/graphql", "/graphiql",
        "/redoc", "/docs",
    ]

    for path in doc_paths:
        url  = base + path
        resp = safe_get(session, url)
        if resp and resp.status_code == 200 and len(resp.text) > 100:
            findings.append({
                "check":    "Exposed API Documentation",
                "severity": "low",
                "detail":   (
                    f"API docs publicly accessible at {url} — "
                    f"exposes endpoint structure to attackers"
                ),
                "module":   "api",
                "url":      url,
            })

    return findings


# ─────────────────────────────────────────
# MAIN ENTRY — called by CLI
# ─────────────────────────────────────────
def scan_api(target: str, fast: bool = False) -> list:
    """
    Full API security scan.
    fast=True skips rate limit testing and reduces wordlist.
    """
    findings = []
    session  = requests.Session()
    session.headers.update(HEADERS)
    session.timeout = 5  # Global timeout

    base_url = normalize_url(target)

    # Step 1 — discover endpoints (shorter list in fast mode)
    endpoints = discover_endpoints(base_url, session, fast=fast)

    # Step 2 — run checks (skip rate limiting in fast mode)
    findings.extend(check_broken_auth(endpoints, session))
    if not fast:
        findings.extend(check_rate_limiting(endpoints, session))
    findings.extend(check_excessive_data(endpoints, session))
    findings.extend(check_api_security_headers(base_url, session))
    findings.extend(check_exposed_docs(base_url, session))

    # Add discovered endpoints as info
    for ep in endpoints:
        if ep.get("status", 0) not in (0, 404):
            findings.append({
                "check":    "API Endpoint Discovered",
                "severity": "info",
                "detail":   f"Endpoint: {ep['url']} — Status: {ep['status']} — Size: {ep['size']} bytes",
                "module":   "api",
                "url":      ep["url"],
            })

    # Sort by severity
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda x: order.get(x["severity"], 5))

    if not findings:
        findings.append({
            "check":    "API Scan Complete",
            "severity": "info",
            "detail":   f"No API security issues detected on {base_url}",
            "module":   "api",
        })

    return findings