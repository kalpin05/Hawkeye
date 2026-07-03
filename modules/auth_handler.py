import requests
import re
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ─────────────────────────────────────────
# CONSTANTS
# ─────────────────────────────────────────

HEADERS = {
    "User-Agent":                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language":           "en-US,en;q=0.9",
    "Accept-Encoding":           "gzip, deflate",
    "Connection":                "keep-alive",
    "Upgrade-Insecure-Requests": "1",
}

# Keywords that indicate successful login
LOGIN_SUCCESS_INDICATORS = [
    "logout", "log out", "sign out", "signout",
    "dashboard", "welcome", "profile", "account",
    "my account", "settings", "hello", "hi ",
]

# Keywords that indicate failed login
LOGIN_FAIL_INDICATORS = [
    "invalid", "incorrect", "wrong", "failed",
    "error", "try again", "bad credentials",
    "authentication failed", "login failed",
    "invalid username", "invalid password",
    "no account found",
]

# Common username/password field names
USERNAME_FIELDS = [
    "username", "user", "email", "login",
    "user_name", "usr", "uid", "userid",
    "user_email", "identifier",
]

PASSWORD_FIELDS = [
    "password", "pass", "pwd", "passwd",
    "user_password", "login_password",
]


# ─────────────────────────────────────────
# FORM DETECTION
# ─────────────────────────────────────────

def detect_login_form(url: str,
                      session: requests.Session) -> dict | None:
    """
    Find the login form on a page.
    Returns form details dict or None if no login form found.
    """
    try:
        resp = session.get(url, timeout=10, verify=False)
        soup = BeautifulSoup(resp.text, "html.parser")
        forms = soup.find_all("form")

        for form in forms:
            inputs = form.find_all("input")
            field_names = [
                inp.get("name", "").lower()
                for inp in inputs
                if inp.get("name")
            ]
            field_types = [
                inp.get("type", "").lower()
                for inp in inputs
            ]

            # Check if form has password field — strong indicator of login form
            has_password = (
                "password" in field_types or
                any(pf in field_names for pf in PASSWORD_FIELDS)
            )

            if not has_password:
                continue

            # Find username and password field names
            username_field = None
            password_field = None

            for inp in inputs:
                name = inp.get("name", "").lower()
                typ  = inp.get("type", "text").lower()

                if not username_field:
                    if (any(uf in name for uf in USERNAME_FIELDS) or
                            typ in ("email", "text")):
                        username_field = inp.get("name")

                if not password_field:
                    if (any(pf in name for pf in PASSWORD_FIELDS) or
                            typ == "password"):
                        password_field = inp.get("name")

            if not (username_field and password_field):
                continue

            # Get form action and method
            action = form.get("action", url)
            method = form.get("method", "post").lower()
            form_url = urljoin(url, action)

            # Get hidden fields (CSRF tokens etc.)
            hidden_fields = {}
            for inp in inputs:
                if inp.get("type", "").lower() == "hidden":
                    name  = inp.get("name", "")
                    value = inp.get("value", "")
                    if name:
                        hidden_fields[name] = value

            return {
                "form_url":       form_url,
                "method":         method,
                "username_field": username_field,
                "password_field": password_field,
                "hidden_fields":  hidden_fields,
                "login_page_url": url,
            }

    except Exception:
        pass

    return None


# ─────────────────────────────────────────
# FORM-BASED LOGIN
# ─────────────────────────────────────────

def login_with_form(login_url: str, username: str,
                    password: str,
                    session: requests.Session) -> dict:
    """
    Attempt form-based login.
    Returns result dict with success flag and session.
    """
    result = {
        "success":      False,
        "method":       "form",
        "login_url":    login_url,
        "username":     username,
        "error":        None,
        "cookies":      {},
        "post_login_url": None,
    }

    try:
        # Detect login form
        form = detect_login_form(login_url, session)
        if not form:
            result["error"] = f"No login form found at {login_url}"
            return result

        # Build POST data
        post_data = {**form["hidden_fields"]}
        post_data[form["username_field"]] = username
        post_data[form["password_field"]] = password

        # Submit login
        if form["method"] == "post":
            resp = session.post(
                form["form_url"],
                data=post_data,
                timeout=15,
                verify=False,
                allow_redirects=True,
            )
        else:
            resp = session.get(
                form["form_url"],
                params=post_data,
                timeout=15,
                verify=False,
                allow_redirects=True,
            )

        # Check if login succeeded
        success, reason = verify_login_success(resp, login_url)
        result["success"]        = success
        result["post_login_url"] = resp.url
        result["cookies"]        = dict(session.cookies)

        if not success:
            result["error"] = f"Login failed — {reason}"

    except requests.exceptions.ConnectionError:
        result["error"] = f"Cannot connect to {login_url}"
    except requests.exceptions.Timeout:
        result["error"] = f"Timeout connecting to {login_url}"
    except Exception as e:
        result["error"] = str(e)

    return result


# ─────────────────────────────────────────
# TOKEN-BASED LOGIN
# ─────────────────────────────────────────

def login_with_token(token: str, header_name: str,
                     session: requests.Session) -> dict:
    """
    Set Bearer token / API key for authenticated scanning.
    Returns result dict — always succeeds (token validity checked later).
    """
    # Set auth header on session for all future requests
    session.headers[header_name] = token

    return {
        "success":   True,
        "method":    "token",
        "header":    header_name,
        "token":     token[:8] + "..." + token[-4:],  # masked
        "error":     None,
        "cookies":   {},
    }


# ─────────────────────────────────────────
# LOGIN VERIFICATION
# ─────────────────────────────────────────

def verify_login_success(response: requests.Response,
                         original_login_url: str) -> tuple:
    """
    Heuristic check to determine if login succeeded.
    Returns (bool, reason_string).
    """
    body_lower = response.text.lower()

    # Check for failure indicators first (more reliable)
    for indicator in LOGIN_FAIL_INDICATORS:
        if indicator in body_lower:
            return False, f"failure indicator found: '{indicator}'"

    # Check for success indicators
    for indicator in LOGIN_SUCCESS_INDICATORS:
        if indicator in body_lower:
            return True, f"success indicator found: '{indicator}'"

    # If redirected away from login page — likely success
    if response.url != original_login_url:
        login_domain   = urlparse(original_login_url).path
        response_path  = urlparse(response.url).path
        if login_domain != response_path:
            return True, "redirected away from login page"

    # If cookies were set — likely success
    if response.cookies:
        cookie_names = [c.lower() for c in response.cookies.keys()]
        session_cookies = ["session", "auth", "token", "login",
                          "user", "jwt", "access"]
        if any(sc in cn for sc in session_cookies for cn in cookie_names):
            return True, "session cookie set"

    # Default — uncertain
    return False, "no clear success/failure indicators found"


# ─────────────────────────────────────────
# SESSION KEEPALIVE
# ─────────────────────────────────────────

def is_session_alive(session: requests.Session,
                     check_url: str,
                     login_url: str) -> bool:
    """
    Check if the authenticated session is still valid.
    Returns False if we've been logged out.
    """
    try:
        resp = session.get(check_url, timeout=8, verify=False,
                           allow_redirects=True)
        # If redirected back to login page — session expired
        if urlparse(resp.url).path == urlparse(login_url).path:
            return False
        body_lower = resp.text.lower()
        # Check for logout/login page indicators
        for indicator in ["please log in", "please sign in",
                          "login required", "session expired"]:
            if indicator in body_lower:
                return False
        return True
    except Exception:
        return False


# ─────────────────────────────────────────
# MAIN ENTRY
# ─────────────────────────────────────────

def create_authenticated_session(
    login_url: str     = "",
    username: str      = "",
    password: str      = "",
    token: str         = "",
    token_header: str  = "Authorization",
    proxy: str         = "",
) -> tuple:
    """
    Create an authenticated requests session.

    Supports:
    - Form-based login (login_url + username + password)
    - Token/Bearer auth (token + token_header)

    Returns (session, auth_result_dict)
    """
    session = requests.Session()
    session.headers.update(HEADERS)

    if proxy:
        session.proxies = {"http": proxy, "https": proxy}

    # Token auth takes priority
    if token:
        # Format token properly
        if token_header.lower() == "authorization" and not token.startswith("Bearer "):
            token = f"Bearer {token}"
        auth_result = login_with_token(token, token_header, session)
        return session, auth_result

    # Form-based login
    if login_url and username and password:
        auth_result = login_with_form(login_url, username, password, session)
        return session, auth_result

    # No auth — return plain session
    return session, {
        "success": False,
        "method":  "none",
        "error":   "No credentials provided",
    }