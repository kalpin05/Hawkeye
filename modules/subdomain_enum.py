import requests
import socket
import re
import concurrent.futures
import os

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ─────────────────────────────────────────
# CONSTANTS
# ─────────────────────────────────────────

BASE_DIR     = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WORDLIST_PATH = os.path.join(BASE_DIR, "payloads", "subdomains.txt")

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
}

# Small built-in fallback wordlist if file is missing
DEFAULT_SUBDOMAINS = [
    "www", "mail", "ftp", "webmail", "smtp", "pop", "ns1", "ns2",
    "api", "dev", "staging", "test", "admin", "portal", "vpn",
    "shop", "store", "blog", "app", "mobile", "secure", "support",
    "help", "docs", "cdn", "static", "assets", "images", "media",
    "beta", "demo", "sandbox", "internal", "intranet", "cpanel",
    "webdisk", "autodiscover", "exchange", "remote", "git", "gitlab",
    "jenkins", "jira", "confluence", "wiki", "status", "monitor",
    "grafana", "kibana", "elastic", "db", "database", "mysql",
    "redis", "cache", "old", "legacy", "backup", "files", "upload",
    "download", "auth", "login", "sso", "oauth", "payment", "pay",
    "checkout", "cart", "account", "accounts", "dashboard", "panel",
    "console", "manage", "management", "crm", "erp", "hr", "intern",
    "career", "careers", "jobs", "press", "news", "events", "forum",
    "community", "social", "chat", "video", "stream", "live",
]


# ─────────────────────────────────────────
# PASSIVE ENUMERATION — crt.sh (Certificate Transparency logs)
# ─────────────────────────────────────────

def enum_crtsh(domain: str) -> set:
    """
    Query crt.sh certificate transparency logs.
    Completely passive — never touches the target directly.
    Finds subdomains that ever had an SSL cert issued.
    """
    found = set()
    try:
        resp = requests.get(
            f"https://crt.sh/?q=%25.{domain}&output=json",
            timeout=20,
            headers=HEADERS,
        )
        if resp.status_code == 200:
            data = resp.json()
            for entry in data:
                name = entry.get("name_value", "")
                for sub in name.split("\n"):
                    sub = sub.strip().lower()
                    sub = sub.lstrip("*.")
                    if sub.endswith(domain) and sub != domain:
                        found.add(sub)
                    elif sub == domain:
                        found.add(sub)
    except Exception:
        pass
    return found


# ─────────────────────────────────────────
# PASSIVE ENUMERATION — AlienVault OTX
# ─────────────────────────────────────────

def enum_otx(domain: str) -> set:
    """
    Query AlienVault OTX passive DNS data.
    Free, no API key required, completely passive.
    """
    found = set()
    try:
        resp = requests.get(
            f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns",
            timeout=20,
            headers=HEADERS,
        )
        if resp.status_code == 200:
            data = resp.json()
            for record in data.get("passive_dns", []):
                hostname = record.get("hostname", "").strip().lower()
                if hostname.endswith(domain):
                    found.add(hostname)
    except Exception:
        pass
    return found


# ─────────────────────────────────────────
# PASSIVE ENUMERATION — HackerTarget
# ─────────────────────────────────────────

def enum_hackertarget(domain: str) -> set:
    """
    Query HackerTarget's free hostsearch API.
    Passive, no auth needed, rate limited to ~50/day on free tier.
    """
    found = set()
    try:
        resp = requests.get(
            f"https://api.hackertarget.com/hostsearch/?q={domain}",
            timeout=15,
            headers=HEADERS,
        )
        if resp.status_code == 200 and "error" not in resp.text.lower():
            for line in resp.text.strip().split("\n"):
                parts = line.split(",")
                if parts and parts[0]:
                    host = parts[0].strip().lower()
                    if host.endswith(domain):
                        found.add(host)
    except Exception:
        pass
    return found


# ─────────────────────────────────────────
# ACTIVE ENUMERATION — DNS brute force
# ─────────────────────────────────────────

def load_subdomain_wordlist() -> list:
    """Load subdomain wordlist from file, fallback to built-in list."""
    try:
        with open(WORDLIST_PATH, "r") as f:
            words = [line.strip() for line in f if line.strip()]
            if words:
                return words
    except FileNotFoundError:
        pass
    return DEFAULT_SUBDOMAINS


def check_dns(subdomain: str) -> str | None:
    """Resolve a single subdomain. Returns subdomain if it resolves."""
    try:
        socket.gethostbyname(subdomain)
        return subdomain
    except socket.gaierror:
        return None


def enum_bruteforce(domain: str, wordlist: list = None,
                    max_workers: int = 50) -> set:
    """
    Active DNS brute-force enumeration.
    Tests common subdomain prefixes against the domain.
    """
    if wordlist is None:
        wordlist = load_subdomain_wordlist()

    candidates = [f"{word}.{domain}" for word in wordlist]
    found = set()

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(check_dns, c): c for c in candidates}
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                found.add(result)

    return found


# ─────────────────────────────────────────
# LIVE CHECK — which subdomains actually respond on HTTP/HTTPS
# ─────────────────────────────────────────

def check_alive(subdomain: str) -> dict | None:
    """Check if a subdomain serves a live website."""
    for scheme in ("https", "http"):
        url = f"{scheme}://{subdomain}"
        try:
            resp = requests.get(
                url, timeout=8, verify=False,
                allow_redirects=True, headers=HEADERS,
            )
            return {
                "subdomain":    subdomain,
                "url":          url,
                "status_code":  resp.status_code,
                "final_url":    resp.url,
                "title":        extract_title(resp.text),
                "scheme":       scheme,
            }
        except requests.exceptions.RequestException:
            continue
    return None


def extract_title(html: str) -> str:
    """Extract <title> tag content for quick identification."""
    match = re.search(r"<title[^>]*>(.*?)</title>",
                      html, re.IGNORECASE | re.DOTALL)
    if match:
        return match.group(1).strip()[:80]
    return ""


def filter_alive(subdomains: set, max_workers: int = 30) -> list:
    """Check which discovered subdomains are actually live."""
    alive = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(check_alive, sub): sub for sub in subdomains}
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                alive.append(result)
    return alive


# ─────────────────────────────────────────
# MAIN ENTRY — full subdomain discovery pipeline
# ─────────────────────────────────────────

def discover_subdomains(domain: str, active: bool = True,
                        passive: bool = True) -> dict:
    """
    Full subdomain discovery pipeline.
    Returns dict with all_subdomains, alive_subdomains, and source breakdown.
    """
    domain = domain.lower().strip()
    domain = re.sub(r"^https?://", "", domain)
    domain = domain.split("/")[0]
    # Strip leading www. to get root domain for searches
    if domain.startswith("www."):
        domain = domain[4:]

    all_found  = set()
    sources    = {}

    # ── PASSIVE ──
    if passive:
        crtsh_results = enum_crtsh(domain)
        sources["crt.sh"] = len(crtsh_results)
        all_found |= crtsh_results

        otx_results = enum_otx(domain)
        sources["alienvault_otx"] = len(otx_results)
        all_found |= otx_results

        ht_results = enum_hackertarget(domain)
        sources["hackertarget"] = len(ht_results)
        all_found |= ht_results

    # ── ACTIVE ──
    if active:
        brute_results = enum_bruteforce(domain)
        sources["dns_bruteforce"] = len(brute_results)
        all_found |= brute_results

    # Always include the root domain itself
    all_found.add(domain)
    all_found.add(f"www.{domain}")

    # ── LIVE CHECK ──
    alive = filter_alive(all_found)

    return {
        "domain":            domain,
        "total_discovered":  len(all_found),
        "total_alive":       len(alive),
        "sources":           sources,
        "all_subdomains":    sorted(all_found),
        "alive_subdomains":  alive,
    }