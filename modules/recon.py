import dns.resolver
import requests
import re
import json
import socket
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ─────────────────────────────────────────
# CONSTANTS
# ─────────────────────────────────────────

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
}

# ── JS Secret Patterns ──
JS_SECRET_PATTERNS = {
    "AWS Access Key":        r"AKIA[0-9A-Z]{16}",
    "AWS Secret Key":        r"(?i)aws.{0,20}secret.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]",
    "Google API Key":        r"AIza[0-9A-Za-z\-_]{35}",
    "Stripe Secret Key":     r"sk_live_[0-9a-zA-Z]{24,}",
    "Stripe Public Key":     r"pk_live_[0-9a-zA-Z]{24,}",
    "GitHub Token":          r"ghp_[0-9a-zA-Z]{36}",
    "GitHub OAuth":          r"gho_[0-9a-zA-Z]{36}",
    "Slack Token":           r"xox[baprs]-[0-9a-zA-Z\-]{10,}",
    "Slack Webhook":         r"https://hooks\.slack\.com/services/[A-Z0-9/]+",
    "Firebase URL":          r"https://[a-z0-9-]+\.firebaseio\.com",
    "Firebase Key":          r"(?i)firebase.{0,20}['\"][0-9a-zA-Z]{20,}['\"]",
    "Razorpay Key":          r"rzp_(live|test)_[0-9a-zA-Z]{14,}",
    "PayPal Client ID":      r"(?i)paypal.{0,20}client.{0,10}['\"][0-9a-zA-Z]{10,}['\"]",
    "Twilio Account SID":    r"AC[0-9a-fA-F]{32}",
    "Twilio Auth Token":     r"(?i)twilio.{0,20}['\"][0-9a-fA-F]{32}['\"]",
    "SendGrid API Key":      r"SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}",
    "Mailgun API Key":       r"key-[0-9a-zA-Z]{32}",
    "Hardcoded Password":    r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"][^'\"]{6,}['\"]",
    "Hardcoded Secret":      r"(?i)(secret|api_secret|client_secret)\s*[:=]\s*['\"][^'\"]{8,}['\"]",
    "Private Key":           r"-----BEGIN (RSA |EC )?PRIVATE KEY-----",
    "Bearer Token":          r"(?i)bearer\s+[0-9a-zA-Z\-_\.]{20,}",
    "Generic API Key":       r"(?i)(api_key|apikey|api-key)\s*[:=]\s*['\"][^'\"]{8,}['\"]",
    "MongoDB URI":           r"mongodb(\+srv)?://[^\s\"']+",
    "MySQL URI":             r"mysql://[^\s\"']+",
    "PostgreSQL URI":        r"postgres(ql)?://[^\s\"']+",
    "JWT Token":             r"eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+",
}

# ── Subdomain Takeover Fingerprints ──
TAKEOVER_SIGNATURES = {
    "GitHub Pages":      ["There isn't a GitHub Pages site here",
                          "For root URLs (like http://example.com/) you must provide an index"],
    "Heroku":            ["No such app", "herokucdn.com/error-pages/no-such-app"],
    "Shopify":           ["Sorry, this shop is currently unavailable"],
    "Fastly":            ["Fastly error: unknown domain"],
    "Ghost":             ["The thing you were looking for is no longer here"],
    "Surge.sh":          ["project not found"],
    "Netlify":           ["Not found - Request ID"],
    "Pantheon":          ["The gods are wise"],
    "Tumblr":            ["Whatever you were looking for doesn't live here"],
    "WordPress.com":     ["Do you want to register"],
    "Zendesk":           ["Help Center Closed"],
    "Unbounce":          ["The requested URL was not found on this server"],
    "HubSpot":           ["This page isn't available"],
    "AWS S3":            ["NoSuchBucket", "The specified bucket does not exist"],
    "Azure":             ["404 Web Site not found"],
    "Bitbucket":         ["Repository not found"],
    "Freshdesk":         ["There is no helpdesk here"],
    "Intercom":          ["This page is reserved for artistic dogs"],
}


# ─────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────

def normalize_domain(target: str) -> str:
    """Strip scheme and path — return bare domain."""
    target = target.replace("https://", "").replace("http://", "")
    target = target.split("/")[0].split(":")[0]
    if target.startswith("www."):
        target = target[4:]
    return target.strip()


def safe_get(url: str, timeout: int = 8) -> requests.Response | None:
    try:
        return requests.get(
            url, timeout=timeout, verify=False,
            headers=HEADERS, allow_redirects=True,
        )
    except Exception:
        return None


# ─────────────────────────────────────────
# CHECK 1 — EMAIL SECURITY
# ─────────────────────────────────────────

def check_email_security(domain: str) -> list:
    """
    Check SPF, DKIM, DMARC DNS records.
    Missing or misconfigured = phishing risk.
    """
    findings = []
    domain   = normalize_domain(domain)

    resolver = dns.resolver.Resolver()
    resolver.timeout        = 5
    resolver.lifetime       = 5

    # ── SPF Check ──
    try:
        answers = resolver.resolve(domain, "TXT")
        spf_records = [
            r.to_text() for r in answers
            if "v=spf1" in r.to_text().lower()
        ]
        if not spf_records:
            findings.append({
                "check":    "Email Security: Missing SPF Record",
                "severity": "high",
                "detail":   (
                    f"{domain} has no SPF record. Attackers can send "
                    f"emails pretending to be from @{domain} — "
                    f"enables phishing attacks on your customers."
                ),
                "module":   "recon",
                "fix":      'Add TXT record: "v=spf1 include:_spf.google.com ~all"',
            })
        else:
            spf = spf_records[0]
            # Check for overly permissive SPF
            if "+all" in spf:
                findings.append({
                    "check":    "Email Security: SPF Too Permissive (+all)",
                    "severity": "high",
                    "detail":   (
                        f"SPF record uses +all which allows ANY server "
                        f"to send email as @{domain} — completely defeats SPF protection."
                    ),
                    "module":   "recon",
                    "fix":      "Change +all to ~all (softfail) or -all (hardfail)",
                })
            elif "?all" in spf:
                findings.append({
                    "check":    "Email Security: SPF Neutral (?all)",
                    "severity": "medium",
                    "detail":   (
                        f"SPF uses ?all (neutral) — provides no real protection "
                        f"against email spoofing."
                    ),
                    "module":   "recon",
                    "fix":      "Change ?all to ~all or -all",
                })
            else:
                findings.append({
                    "check":    "Email Security: SPF Configured",
                    "severity": "info",
                    "detail":   f"SPF record found: {spf[:100]}",
                    "module":   "recon",
                })
    except dns.resolver.NXDOMAIN:
        findings.append({
            "check":    "Email Security: Domain Not Found",
            "severity": "info",
            "detail":   f"Could not resolve {domain}",
            "module":   "recon",
        })
    except Exception:
        findings.append({
            "check":    "Email Security: SPF Check Failed",
            "severity": "info",
            "detail":   f"Could not query SPF for {domain}",
            "module":   "recon",
        })

    # ── DMARC Check ──
    try:
        dmarc_domain = f"_dmarc.{domain}"
        answers      = resolver.resolve(dmarc_domain, "TXT")
        dmarc_records = [
            r.to_text() for r in answers
            if "v=dmarc1" in r.to_text().lower()
        ]

        if not dmarc_records:
            findings.append({
                "check":    "Email Security: Missing DMARC Record",
                "severity": "high",
                "detail":   (
                    f"No DMARC record at _dmarc.{domain}. "
                    f"Without DMARC, email spoofing attacks are undetected "
                    f"and unenforced — your customers can be phished."
                ),
                "module":   "recon",
                "fix":      'Add TXT record at _dmarc.domain.com: "v=DMARC1; p=quarantine; rua=mailto:dmarc@domain.com"',
            })
        else:
            dmarc = dmarc_records[0]
            # Check DMARC policy strength
            if "p=none" in dmarc.lower():
                findings.append({
                    "check":    "Email Security: DMARC Policy Too Weak (p=none)",
                    "severity": "medium",
                    "detail":   (
                        f"DMARC policy is p=none — only monitors, "
                        f"doesn't block spoofed emails. "
                        f"Attackers can still impersonate @{domain}."
                    ),
                    "module":   "recon",
                    "fix":      "Change p=none to p=quarantine or p=reject",
                })
            elif "p=quarantine" in dmarc.lower():
                findings.append({
                    "check":    "Email Security: DMARC Quarantine Policy",
                    "severity": "info",
                    "detail":   f"DMARC p=quarantine — good, consider upgrading to p=reject",
                    "module":   "recon",
                })
            elif "p=reject" in dmarc.lower():
                findings.append({
                    "check":    "Email Security: DMARC Reject Policy",
                    "severity": "info",
                    "detail":   "DMARC p=reject — strongest protection configured correctly",
                    "module":   "recon",
                })
    except Exception:
        findings.append({
            "check":    "Email Security: Missing DMARC Record",
            "severity": "high",
            "detail":   (
                f"No DMARC record found for {domain}. "
                f"Email spoofing attacks are undetected."
            ),
            "module":   "recon",
            "fix":      'Add TXT at _dmarc.domain.com: "v=DMARC1; p=quarantine; rua=mailto:dmarc@domain.com"',
        })

    # ── DKIM Check (common selectors) ──
    dkim_found    = False
    dkim_selectors = [
        "default", "google", "mail", "email",
        "dkim", "k1", "s1", "s2", "smtp",
        "mailjet", "sendgrid", "mailchimp",
    ]
    for selector in dkim_selectors:
        try:
            dkim_domain = f"{selector}._domainkey.{domain}"
            resolver.resolve(dkim_domain, "TXT")
            dkim_found = True
            findings.append({
                "check":    f"Email Security: DKIM Configured ({selector})",
                "severity": "info",
                "detail":   f"DKIM record found with selector '{selector}'",
                "module":   "recon",
            })
            break
        except Exception:
            continue

    if not dkim_found:
        findings.append({
            "check":    "Email Security: DKIM Not Found",
            "severity": "medium",
            "detail":   (
                f"No DKIM record found for common selectors on {domain}. "
                f"Emails may not be authenticated — phishing risk."
            ),
            "module":   "recon",
            "fix":      "Configure DKIM with your email provider (Google, Outlook, etc)",
        })

    return findings


# ─────────────────────────────────────────
# CHECK 2 — JS SECRET DETECTION
# ─────────────────────────────────────────

def get_js_files(url: str) -> list:
    """Extract all JavaScript file URLs from a page."""
    js_urls = []
    resp    = safe_get(url)
    if not resp:
        return js_urls

    soup = BeautifulSoup(resp.text, "html.parser")

    for tag in soup.find_all("script"):
        src = tag.get("src", "")
        if src:
            full_url = urljoin(url, src)
            js_urls.append(full_url)

        # Also check inline scripts
        if tag.string and len(tag.string) > 50:
            js_urls.append(f"__inline__{url}")

    return list(set(js_urls))


def scan_js_content(content: str, source_url: str) -> list:
    """Scan JavaScript content for hardcoded secrets."""
    findings = []

    for secret_type, pattern in JS_SECRET_PATTERNS.items():
        matches = re.findall(pattern, content)
        if matches:
            # Mask the actual secret value
            masked = matches[0]
            if len(masked) > 12:
                masked = masked[:6] + "..." + masked[-4:]

            findings.append({
                "check":    f"Exposed Secret: {secret_type}",
                "severity": "critical",
                "detail":   (
                    f"{secret_type} found in JavaScript at {source_url[:80]} "
                    f"— Value: {masked} "
                    f"(attacker can use this to access your services)"
                ),
                "module":   "recon",
                "url":      source_url,
                "fix":      (
                    "Move secrets to server-side environment variables. "
                    "Never hardcode API keys in frontend JavaScript. "
                    "Rotate this key immediately."
                ),
            })

    return findings


def check_js_secrets(target: str) -> list:
    """
    Download and scan all JavaScript files for hardcoded secrets.
    Also checks inline scripts.
    """
    findings  = []
    url       = target if target.startswith("http") else f"https://{target}"
    js_files  = get_js_files(url)

    # Also try HTTP if HTTPS fails
    if not js_files:
        url      = f"http://{normalize_domain(target)}"
        js_files = get_js_files(url)

    if not js_files:
        findings.append({
            "check":    "JS Secret Scan: Could Not Access Site",
            "severity": "info",
            "detail":   f"Could not fetch JavaScript files from {target}",
            "module":   "recon",
        })
        return findings

    scanned = 0
    for js_url in js_files[:20]:  # Limit to 20 JS files
        if js_url.startswith("__inline__"):
            # Scan inline scripts
            page_url = js_url.replace("__inline__", "")
            resp     = safe_get(page_url)
            if resp:
                soup = BeautifulSoup(resp.text, "html.parser")
                for tag in soup.find_all("script"):
                    if tag.string:
                        findings.extend(
                            scan_js_content(tag.string, page_url)
                        )
                        scanned += 1
        else:
            # Skip external CDN files (jQuery, React etc)
            domain = normalize_domain(target)
            if domain not in js_url:
                continue

            resp = safe_get(js_url)
            if resp and resp.text:
                findings.extend(
                    scan_js_content(resp.text, js_url)
                )
                scanned += 1

    # Deduplicate by check type
    seen    = set()
    deduped = []
    for f in findings:
        key = f["check"]
        if key not in seen:
            seen.add(key)
            deduped.append(f)

    if not deduped:
        deduped.append({
            "check":    "JS Secret Scan: No Secrets Found",
            "severity": "info",
            "detail":   f"Scanned {scanned} JavaScript files — no hardcoded secrets detected",
            "module":   "recon",
        })

    return deduped


# ─────────────────────────────────────────
# CHECK 3 — SUBDOMAIN TAKEOVER
# ─────────────────────────────────────────

def check_cname(subdomain: str) -> str | None:
    """Get CNAME record for a subdomain."""
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout  = 3
        resolver.lifetime = 3
        answers = resolver.resolve(subdomain, "CNAME")
        return str(answers[0].target).rstrip(".")
    except Exception:
        return None


def check_dangling_dns(subdomain: str) -> bool:
    """
    Check if subdomain has a CNAME but the target doesn't resolve.
    This is the classic dangling DNS takeover scenario.
    """
    cname = check_cname(subdomain)
    if not cname:
        return False

    try:
        socket.gethostbyname(cname)
        return False  # CNAME resolves — not dangling
    except socket.gaierror:
        return True   # CNAME exists but doesn't resolve — dangling!


def check_service_fingerprint(subdomain: str) -> tuple:
    """
    Check if a subdomain returns a known takeover fingerprint.
    Returns (service_name, is_vulnerable) or (None, False)
    """
    for scheme in ("https", "http"):
        url  = f"{scheme}://{subdomain}"
        resp = safe_get(url, timeout=6)
        if not resp:
            continue

        body = resp.text.lower()
        for service, signatures in TAKEOVER_SIGNATURES.items():
            for signature in signatures:
                if signature.lower() in body:
                    return service, True

    return None, False


def check_subdomain_takeover(target: str,
                             subdomains: list = None) -> list:
    """
    Check discovered subdomains for takeover vulnerabilities.
    Tests both dangling DNS and service fingerprinting.
    """
    findings = []
    domain   = normalize_domain(target)

    # If no subdomains provided, do quick passive discovery first
    if not subdomains:
        from modules.subdomain_enum import enum_crtsh, enum_hackertarget
        passive = enum_crtsh(domain) | enum_hackertarget(domain)
        subdomains = list(passive)[:30]  # Limit to 30

    if not subdomains:
        findings.append({
            "check":    "Subdomain Takeover: No Subdomains Found",
            "severity": "info",
            "detail":   f"No subdomains discovered for {domain}",
            "module":   "recon",
        })
        return findings

    findings.append({
        "check":    "Subdomain Takeover: Scanning Started",
        "severity": "info",
        "detail":   f"Checking {len(subdomains)} subdomains for takeover vulnerability",
        "module":   "recon",
    })

    for subdomain in subdomains:
        # Skip root domain
        if subdomain == domain or subdomain == f"www.{domain}":
            continue

        # Check 1: Dangling DNS
        if check_dangling_dns(subdomain):
            cname = check_cname(subdomain)
            findings.append({
                "check":    "Subdomain Takeover: Dangling CNAME",
                "severity": "critical",
                "detail":   (
                    f"{subdomain} has a CNAME pointing to {cname} "
                    f"but {cname} doesn't resolve. "
                    f"Attacker can register {cname} and take over this subdomain!"
                ),
                "module":   "recon",
                "url":      f"https://{subdomain}",
                "fix":      (
                    f"Either remove the DNS record for {subdomain} "
                    f"or re-register the service at {cname}"
                ),
            })
            continue

        # Check 2: Service fingerprint
        service, vulnerable = check_service_fingerprint(subdomain)
        if vulnerable:
            findings.append({
                "check":    f"Subdomain Takeover: {service} Unclaimed",
                "severity": "critical",
                "detail":   (
                    f"{subdomain} points to an unclaimed {service} page. "
                    f"Attacker can claim this {service} account and "
                    f"serve malicious content under your domain!"
                ),
                "module":   "recon",
                "url":      f"https://{subdomain}",
                "fix":      (
                    f"Either remove the DNS record for {subdomain} "
                    f"or reclaim the {service} account"
                ),
            })

    return findings


# ─────────────────────────────────────────
# BONUS — GOOGLE DORK CHECK
# ─────────────────────────────────────────

def check_exposed_info(domain: str) -> list:
    """
    Check for commonly exposed sensitive files and paths.
    Tests direct access to files that should be private.
    """
    findings = []
    domain   = normalize_domain(domain)

    sensitive_paths = [
        ("/.env",               "critical", "Environment file with secrets"),
        ("/.env.local",         "critical", "Local environment file"),
        ("/.env.production",    "critical", "Production environment file"),
        ("/.git/config",        "critical", "Git repository config exposed"),
        ("/.git/HEAD",          "critical", "Git repository exposed"),
        ("/config.php",         "high",     "PHP config file"),
        ("/wp-config.php",      "critical", "WordPress config with DB credentials"),
        ("/phpinfo.php",        "high",     "PHP info page exposed"),
        ("/.htpasswd",          "critical", "Password file exposed"),
        ("/backup.sql",         "critical", "Database backup exposed"),
        ("/dump.sql",           "critical", "Database dump exposed"),
        ("/db.sql",             "critical", "Database file exposed"),
        ("/config.json",        "high",     "Configuration file exposed"),
        ("/secrets.json",       "critical", "Secrets file exposed"),
        ("/credentials.json",   "critical", "Credentials file exposed"),
        ("/.DS_Store",          "medium",   "Mac filesystem metadata exposed"),
        ("/robots.txt",         "info",     "Robots.txt — check for hidden paths"),
        ("/sitemap.xml",        "info",     "Sitemap found"),
        ("/.well-known/security.txt", "info", "Security contact file"),
        ("/api/v1/users",       "high",     "User API endpoint exposed"),
        ("/graphql",            "medium",   "GraphQL endpoint exposed"),
        ("/swagger-ui.html",    "medium",   "API documentation exposed"),
        ("/actuator",           "high",     "Spring Boot actuator exposed"),
        ("/server-status",      "medium",   "Apache server status exposed"),
        ("/server-info",        "medium",   "Apache server info exposed"),
    ]

    for scheme in ("https", "http"):
        base_url = f"{scheme}://{domain}"
        resp     = safe_get(base_url, timeout=5)
        if resp:
            break
    else:
        return findings

    for path, severity, description in sensitive_paths:
        url  = base_url + path
        resp = safe_get(url, timeout=5)

        if resp and resp.status_code == 200 and len(resp.text) > 10:
            # Extra validation for common false positives
            if path in ("/.DS_Store", "/robots.txt",
                        "/sitemap.xml", "/.well-known/security.txt"):
                findings.append({
                    "check":    f"Info: {path} Accessible",
                    "severity": severity,
                    "detail":   f"{description} at {url}",
                    "module":   "recon",
                    "url":      url,
                })
                continue

            # For sensitive files, verify content looks real
            content_lower = resp.text.lower()
            sensitive_indicators = [
                "password", "secret", "key", "token",
                "database", "mysql", "postgres", "mongo",
                "<?php", "config", "db_",
            ]

            if any(ind in content_lower for ind in sensitive_indicators):
                findings.append({
                    "check":    f"Exposed File: {path}",
                    "severity": severity,
                    "detail":   (
                        f"{description} at {url} — "
                        f"contains sensitive content ({resp.status_code})"
                    ),
                    "module":   "recon",
                    "url":      url,
                    "fix":      f"Block access to {path} in web server config. Never commit sensitive files to public repos.",
                })
            elif severity in ("critical", "high"):
                findings.append({
                    "check":    f"Exposed File: {path}",
                    "severity": severity,
                    "detail":   f"{description} at {url} returned HTTP 200",
                    "module":   "recon",
                    "url":      url,
                    "fix":      f"Block access to {path} in web server configuration",
                })

    return findings


# ─────────────────────────────────────────
# MAIN ENTRY
# ─────────────────────────────────────────

def scan_recon(target: str,
               subdomains: list = None) -> list:
    """
    Full passive recon scan:
    1. Email security (SPF, DKIM, DMARC)
    2. JS secret detection
    3. Subdomain takeover
    4. Exposed sensitive files
    Returns list of finding dicts.
    """
    findings = []
    domain   = normalize_domain(target)
    url      = target if target.startswith("http") else f"https://{domain}"

    # Run all checks
    findings.extend(check_email_security(domain))
    findings.extend(check_js_secrets(url))
    findings.extend(check_subdomain_takeover(target, subdomains))
    findings.extend(check_exposed_info(domain))

    # Sort by severity
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda x: order.get(x.get("severity", "info"), 5))

    if not findings:
        findings.append({
            "check":    "Recon Scan Complete",
            "severity": "info",
            "detail":   f"No passive recon issues found for {domain}",
            "module":   "recon",
        })

    return findings