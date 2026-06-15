import socket
import concurrent.futures
from datetime import datetime

# ─────────────────────────────────────────
# DANGEROUS PORTS
# ─────────────────────────────────────────

DANGEROUS_PORTS = {
    21:    ("FTP",             "high",     "FTP transmits credentials in plaintext"),
    22:    ("SSH",             "medium",   "SSH exposed — ensure strong auth and no default creds"),
    23:    ("Telnet",          "critical", "Telnet is unencrypted — replace with SSH immediately"),
    25:    ("SMTP",            "medium",   "SMTP exposed — may allow email spoofing or relay abuse"),
    53:    ("DNS",             "medium",   "DNS exposed — check for zone transfer vulnerability"),
    80:    ("HTTP",            "low",      "HTTP running — ensure sensitive data is served over HTTPS"),
    110:   ("POP3",            "medium",   "POP3 exposed — email credentials may be sent in plaintext"),
    135:   ("RPC",             "high",     "Windows RPC exposed — common attack vector"),
    139:   ("NetBIOS",         "high",     "NetBIOS exposed — vulnerable to enumeration attacks"),
    143:   ("IMAP",            "medium",   "IMAP exposed — ensure TLS is enforced"),
    443:   ("HTTPS",           "info",     "HTTPS running — expected for web servers"),
    445:   ("SMB",             "critical", "SMB exposed — highly vulnerable (EternalBlue, ransomware)"),
    1433:  ("MSSQL",           "critical", "Microsoft SQL Server exposed to network"),
    1521:  ("Oracle DB",       "critical", "Oracle Database exposed to network"),
    2375:  ("Docker",          "critical", "Docker daemon exposed without TLS — full container takeover"),
    3000:  ("Dev Server",      "medium",   "Development server exposed — should not be public"),
    3306:  ("MySQL",           "critical", "MySQL database exposed to network — restrict to localhost"),
    3389:  ("RDP",             "critical", "RDP exposed — common ransomware entry point"),
    4369:  ("RabbitMQ",        "high",     "RabbitMQ exposed — restrict to internal network"),
    5432:  ("PostgreSQL",      "critical", "PostgreSQL exposed to network — restrict to localhost"),
    5900:  ("VNC",             "critical", "VNC exposed — remote desktop access risk"),
    6379:  ("Redis",           "critical", "Redis exposed without auth — full data access possible"),
    7001:  ("WebLogic",        "high",     "WebLogic exposed — check for known RCE vulnerabilities"),
    8080:  ("HTTP-Alt",        "medium",   "Alternate HTTP port exposed — may be admin/dev panel"),
    8443:  ("HTTPS-Alt",       "medium",   "Alternate HTTPS port exposed — verify what's running"),
    8888:  ("Jupyter",         "critical", "Jupyter Notebook exposed — allows arbitrary code execution"),
    9200:  ("Elasticsearch",   "critical", "Elasticsearch exposed without auth — full data access"),
    9300:  ("Elasticsearch",   "critical", "Elasticsearch cluster port exposed"),
    27017: ("MongoDB",         "critical", "MongoDB exposed without auth — full data access possible"),
    27018: ("MongoDB",         "critical", "MongoDB shard exposed to network"),
}

# Top 100 ports for fast mode
TOP_100_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
    1723, 3306, 3389, 5900, 8080, 8443, 8888, 9200, 27017,
    20, 69, 79, 88, 119, 123, 137, 138, 161, 194, 389, 427, 464, 500,
    512, 513, 514, 515, 543, 544, 548, 554, 587, 631, 646, 873, 990,
    1025, 1026, 1027, 1028, 1029, 1110, 1433, 1521, 1720, 1755, 1900,
    2000, 2001, 2049, 2121, 2717, 3000, 3128, 3268, 3269, 4343, 4369,
    5000, 5009, 5051, 5060, 5101, 5190, 5357, 5432, 5631, 5666, 5800,
    6000, 6001, 6379, 7001, 7070, 8000, 8008, 8009, 8081, 8888, 9090,
    9100, 9300, 10000, 32768, 49152, 49153, 49154, 49155, 49156,
]

# Full common ports for normal mode
FULL_PORTS = list(range(1, 1025)) + [
    1433, 1521, 2375, 3000, 3306, 3389, 4369, 5432,
    5900, 6379, 7001, 8080, 8443, 8888, 9200, 9300, 27017, 27018,
]


# ─────────────────────────────────────────
# CORE SCANNER
# ─────────────────────────────────────────

def resolve_host(target: str) -> str:
    """Strip scheme and path — get bare hostname or IP."""
    target = target.replace("https://", "").replace("http://", "")
    target = target.split("/")[0].split(":")[0]
    return target


def scan_port(host: str, port: int, timeout: float = 1.0) -> dict | None:
    """
    Try to connect to host:port.
    Returns dict if open, None if closed/filtered.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()

        if result == 0:
            # Try banner grab
            banner = grab_banner(host, port)

            # Look up in dangerous ports list
            if port in DANGEROUS_PORTS:
                service, severity, detail = DANGEROUS_PORTS[port]
            else:
                service  = get_service_name(port)
                severity = "low"
                detail   = f"Port {port} is open"

            return {
                "port":     port,
                "state":    "open",
                "service":  service,
                "banner":   banner,
                "severity": severity,
                "check":    f"Open Port: {port}/{service}",
                "detail":   detail + (f" | Banner: {banner}" if banner else ""),
                "module":   "network",
            }
    except (socket.timeout, ConnectionRefusedError, OSError):
        pass
    return None


def grab_banner(host: str, port: int, timeout: float = 2.0) -> str:
    """Try to grab service banner."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
        banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
        sock.close()
        # Return first line only
        return banner.split("\n")[0][:80] if banner else ""
    except Exception:
        return ""


def get_service_name(port: int) -> str:
    """Try to get service name from port number."""
    try:
        return socket.getservbyport(port)
    except Exception:
        return "unknown"


# ─────────────────────────────────────────
# HOST VALIDATION
# ─────────────────────────────────────────

def validate_host(host: str) -> tuple[bool, str]:
    """Check if host is resolvable."""
    try:
        ip = socket.gethostbyname(host)
        return True, ip
    except socket.gaierror:
        return False, ""


# ─────────────────────────────────────────
# MAIN ENTRY — called by CLI
# ─────────────────────────────────────────

def scan_network(target: str, fast: bool = False) -> list:
    """
    Scan target for open ports and dangerous services.
    Returns list of finding dicts.
    """
    findings = []
    host     = resolve_host(target)

    # Validate host
    reachable, ip = validate_host(host)
    if not reachable:
        return [{
            "check":    "Host Unreachable",
            "severity": "info",
            "detail":   f"Could not resolve {host} — check if target is reachable",
            "module":   "network",
        }]

    # Add host info finding
    findings.append({
        "check":    "Host Info",
        "severity": "info",
        "detail":   f"Resolved {host} → {ip}",
        "module":   "network",
    })

    # Choose port list
    ports = TOP_100_PORTS if fast else FULL_PORTS

    # Threaded port scan
    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        future_to_port = {
            executor.submit(scan_port, host, port): port
            for port in ports
        }
        for future in concurrent.futures.as_completed(future_to_port):
            result = future.result()
            if result:
                open_ports.append(result)

    # Sort by port number
    open_ports.sort(key=lambda x: x["port"])
    findings.extend(open_ports)

    # Summary finding
    critical_ports = [f for f in open_ports if f["severity"] == "critical"]
    if critical_ports:
        findings.append({
            "check":    f"Critical Services Exposed ({len(critical_ports)})",
            "severity": "critical",
            "detail":   "One or more critical services are publicly exposed — immediate action required",
            "module":   "network",
        })

    return findings