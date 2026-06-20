import requests
import ssl
import socket
from datetime import datetime
from urllib.parse import urlparse

# ─────────────────────────────────────────
# CONSTANTS
# ─────────────────────────────────────────

SECURITY_HEADERS = {
    "Content-Security-Policy": {
        "severity": "high",
        "detail": "CSP header missing — prevents XSS and data injection attacks",
    },
    "Strict-Transport-Security": {
        "severity": "high",
        "detail": "HSTS missing — site may be vulnerable to SSL stripping attacks",
    },
    "X-Frame-Options": {
        "severity": "medium",
        "detail": "X-Frame-Options missing — site may be vulnerable to clickjacking",
    },
    "X-Content-Type-Options": {
        "severity": "medium",
        "detail": "X-Content-Type-Options missing — browser may MIME-sniff responses",
    },
    "Referrer-Policy": {
        "severity": "low",
        "detail": "Referrer-Policy missing — sensitive URLs may leak to third parties",
    },
    "Permissions-Policy": {
        "severity": "low",
        "detail": "Permissions-Policy missing — browser features not explicitly restricted",
    },
    "X-XSS-Protection": {
        "severity": "low",
        "detail": "X-XSS-Protection missing — legacy XSS filter not enabled",
    },
}

WEAK_TLS_VERSIONS = ["SSLv2", "SSLv3", "TLSv1", "TLSv1.1"]

DANGEROUS_HEADERS = {
    "Server": "Exposes server software and version — remove or genericize",
    "X-Powered-By": "Exposes backend technology — remove this header",
    "X-AspNet-Version": "Exposes ASP.NET version — remove this header",
    "X-AspNetMvc-Version": "Exposes MVC version — remove this header",
}


# ─────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────

def normalize_url(target: str) -> str:
    """Ensure target has https:// or http:// prefix."""
    if not target.startswith(("http://", "https://")):
        return "https://" + target
    return target


def get_hostname(target: str) -> str:
    return urlparse(normalize_url(target)).hostname


# ─────────────────────────────────────────
# CHECK 1 — HTTP SECURITY HEADERS
# ─────────────────────────────────────────

def check_security_headers(target: str) -> list:
    findings = []
    url = normalize_url(target)

    # Try HTTPS first, fall back to HTTP
    urls_to_try = []
    if url.startswith("https://"):
        urls_to_try = [url, url.replace("https://", "http://")]
    else:
        urls_to_try = [url, url.replace("http://", "https://")]

    resp = None
    for try_url in urls_to_try:
        try:
            resp = requests.get(
                try_url, timeout=10, verify=False,
                allow_redirects=True,
                headers={
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                }
            )
            break  # Got a response — use it
        except requests.exceptions.SSLError:
            findings.append({
                "check":    "SSL Certificate Error",
                "severity": "critical",
                "detail":   "SSL certificate is invalid or self-signed",
                "module":   "headers",
            })
            continue
        except requests.exceptions.ConnectionError:
            continue
        except Exception:
            continue

    if resp is None:
        findings.append({
            "check":    "Connection Failed",
            "severity": "info",
            "detail":   f"Could not connect to {url} on HTTP or HTTPS",
            "module":   "headers",
        })
        return findings

    headers = {k.lower(): v for k, v in resp.headers.items()}

    # Check missing security headers
    for header, meta in SECURITY_HEADERS.items():
        if header.lower() not in headers:
            findings.append({
                "check":    f"Missing: {header}",
                "severity": meta["severity"],
                "detail":   meta["detail"],
                "module":   "headers",
            })

    # Check dangerous info-leaking headers
    for header, detail in DANGEROUS_HEADERS.items():
        if header.lower() in headers:
            findings.append({
                "check":    f"Exposed: {header}",
                "severity": "medium",
                "detail":   f"{detail} (value: {headers[header.lower()]})",
                "module":   "headers",
            })

    # Cookie checks
    if "set-cookie" in headers:
        cookie_val = headers["set-cookie"]
        if "secure" not in cookie_val.lower():
            findings.append({
                "check":    "Cookie: Missing Secure flag",
                "severity": "medium",
                "detail":   "Cookie sent without Secure flag",
                "module":   "headers",
            })
        if "httponly" not in cookie_val.lower():
            findings.append({
                "check":    "Cookie: Missing HttpOnly flag",
                "severity": "medium",
                "detail":   "Cookie missing HttpOnly — accessible via JavaScript",
                "module":   "headers",
            })
        if "samesite" not in cookie_val.lower():
            findings.append({
                "check":    "Cookie: Missing SameSite flag",
                "severity": "low",
                "detail":   "Cookie missing SameSite — CSRF risk",
                "module":   "headers",
            })

    return findings


# ─────────────────────────────────────────
# CHECK 2 — SSL CERTIFICATE
# ─────────────────────────────────────────

def check_ssl(target: str) -> list:
    findings = []
    hostname = get_hostname(target)

    if not hostname:
        return findings

    try:
        context = ssl.create_default_context()
        conn = context.wrap_socket(
            socket.create_connection((hostname, 443), timeout=10),
            server_hostname=hostname,
        )
        cert = conn.getpeercert()
        conn.close()

        # Check expiry
        expire_str = cert.get("notAfter", "")
        if expire_str:
            expire_date = datetime.strptime(expire_str, "%b %d %H:%M:%S %Y %Z")
            days_left   = (expire_date - datetime.utcnow()).days

            if days_left < 0:
                findings.append({
                    "check":    "SSL: Certificate Expired",
                    "severity": "critical",
                    "detail":   f"Certificate expired {abs(days_left)} days ago",
                    "module":   "ssl",
                })
            elif days_left < 15:
                findings.append({
                    "check":    "SSL: Expiring Very Soon",
                    "severity": "high",
                    "detail":   f"Certificate expires in {days_left} days — renew immediately",
                    "module":   "ssl",
                })
            elif days_left < 30:
                findings.append({
                    "check":    "SSL: Expiring Soon",
                    "severity": "medium",
                    "detail":   f"Certificate expires in {days_left} days — plan renewal",
                    "module":   "ssl",
                })
            else:
                findings.append({
                    "check":    "SSL: Certificate Valid",
                    "severity": "info",
                    "detail":   f"Certificate valid for {days_left} more days (expires {expire_date.strftime('%Y-%m-%d')})",
                    "module":   "ssl",
                })

        # Check TLS version
        tls_version = conn.version() if hasattr(conn, "version") else "Unknown"
        if any(weak in str(tls_version) for weak in WEAK_TLS_VERSIONS):
            findings.append({
                "check":    f"SSL: Weak TLS Version ({tls_version})",
                "severity": "high",
                "detail":   f"{tls_version} is deprecated — upgrade to TLS 1.2 or 1.3",
                "module":   "ssl",
            })

    except ssl.SSLCertVerificationError:
        findings.append({
            "check":    "SSL: Certificate Verification Failed",
            "severity": "critical",
            "detail":   "Certificate is self-signed or from untrusted CA",
            "module":   "ssl",
        })
    except ssl.SSLError as e:
        findings.append({
            "check":    "SSL: Error",
            "severity": "high",
            "detail":   str(e),
            "module":   "ssl",
        })
    except (socket.timeout, ConnectionRefusedError):
        findings.append({
            "check":    "SSL: Port 443 Unreachable",
            "severity": "medium",
            "detail":   f"Could not connect to {hostname}:443 — HTTPS may not be configured",
            "module":   "ssl",
        })
    except Exception as e:
        findings.append({
            "check":    "SSL: Scan Error",
            "severity": "info",
            "detail":   str(e),
            "module":   "ssl",
        })

    return findings


# ─────────────────────────────────────────
# MAIN ENTRY — called by CLI
# ─────────────────────────────────────────

def scan_headers(target: str) -> list:
    """
    Run full header + SSL scan on target.
    Returns list of finding dicts.
    """
    findings = []
    findings.extend(check_security_headers(target))
    findings.extend(check_ssl(target))
    return findings