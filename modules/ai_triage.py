import os
import json
import requests
import time

# ─────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────

GROQ_API_URL = "https://api.groq.com/openai/v1/chat/completions"
GROQ_MODEL   = "llama3-8b-8192"  # Free, fast model on Groq

# Get API key from environment variable
GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "")


# ─────────────────────────────────────────
# PROMPT BUILDER
# ─────────────────────────────────────────

def build_prompt(finding: dict) -> str:
    return f"""You are a senior cybersecurity expert writing a professional vulnerability report.

Analyze this security finding and respond in EXACTLY this JSON format with no extra text:

{{
  "risk_score": <integer 0-10>,
  "severity":   "<critical|high|medium|low|info>",
  "title":      "<short professional title>",
  "explanation": "<2-3 sentence plain English explanation for a non-technical business owner>",
  "impact":     "<1-2 sentence business impact>",
  "fix":        "<3 specific actionable fix steps as a single string, numbered 1. 2. 3.>"
}}

Finding to analyze:
- Check:    {finding.get("check", "Unknown")}
- Severity: {finding.get("severity", "info")}
- Detail:   {finding.get("detail", "No detail provided")}
- Module:   {finding.get("module", "unknown")}
- URL:      {finding.get("url", "N/A")}

Respond ONLY with the JSON object. No markdown, no backticks, no extra text."""


# ─────────────────────────────────────────
# GROQ API CALL
# ─────────────────────────────────────────

def call_groq(prompt: str) -> dict | None:
    """Call Groq API and return parsed JSON response."""
    if not GROQ_API_KEY:
        return None

    headers = {
        "Authorization": f"Bearer {GROQ_API_KEY}",
        "Content-Type":  "application/json",
    }

    payload = {
        "model":       GROQ_MODEL,
        "messages":    [{"role": "user", "content": prompt}],
        "temperature": 0.1,
        "max_tokens":  500,
    }

    try:
        resp = requests.post(
            GROQ_API_URL,
            headers=headers,
            json=payload,
            timeout=15,
        )
        resp.raise_for_status()
        data    = resp.json()
        content = data["choices"][0]["message"]["content"].strip()

        # Clean response — remove markdown if present
        content = content.replace("```json", "").replace("```", "").strip()

        return json.loads(content)

    except requests.exceptions.Timeout:
        return None
    except requests.exceptions.RequestException:
        return None
    except (json.JSONDecodeError, KeyError):
        return None


# ─────────────────────────────────────────
# FALLBACK — no API key
# ─────────────────────────────────────────

SEVERITY_SCORES = {
    "critical": 9,
    "high":     7,
    "medium":   5,
    "low":      3,
    "info":     1,
}

FALLBACK_EXPLANATIONS = {
    "critical": "This is a critical security vulnerability that requires immediate attention. It could allow attackers to fully compromise the system.",
    "high":     "This is a high severity vulnerability that poses significant risk. Attackers could exploit this to gain unauthorized access or steal data.",
    "medium":   "This is a medium severity issue that should be addressed soon. It may allow attackers to gather information or perform limited attacks.",
    "low":      "This is a low severity issue with limited direct impact. However, it may assist attackers in combination with other vulnerabilities.",
    "info":     "This is an informational finding with no direct security impact. It provides useful context about the target system.",
}

FALLBACK_FIXES = {
    "xss":      "1. Encode all user input before rendering in HTML. 2. Implement Content-Security-Policy header. 3. Use a web application firewall (WAF).",
    "sqli":     "1. Use parameterized queries / prepared statements. 2. Never concatenate user input into SQL strings. 3. Apply principle of least privilege to DB user.",
    "idor":     "1. Implement server-side authorization checks on every request. 2. Use non-sequential IDs (UUIDs). 3. Log and monitor access to sensitive objects.",
    "ssrf":     "1. Whitelist allowed domains for outbound requests. 2. Block internal IP ranges (127.x, 10.x, 192.168.x). 3. Disable unnecessary URL fetch features.",
    "ssl":      "1. Install a valid SSL certificate (Let's Encrypt is free). 2. Enable HTTPS redirect from HTTP. 3. Configure HSTS header.",
    "header":   "1. Add missing security headers to web server config. 2. Use a security headers checker (securityheaders.com). 3. Test after deployment.",
    "cors":     "1. Restrict Access-Control-Allow-Origin to known domains. 2. Never use wildcard (*) with credentials. 3. Validate Origin header server-side.",
    "port":     "1. Close or firewall unnecessary open ports. 2. Restrict database ports to localhost only. 3. Use a cloud security group / firewall rule.",
    "default":  "1. Review and fix the identified vulnerability following OWASP guidelines. 2. Test the fix in staging before deploying. 3. Rescan after patching.",
}


def get_fallback_triage(finding: dict) -> dict:
    """Return rule-based triage when AI is not available."""
    sev        = finding.get("severity", "info").lower()
    check      = finding.get("check", "").lower()
    risk_score = SEVERITY_SCORES.get(sev, 1)
    explanation = FALLBACK_EXPLANATIONS.get(sev, FALLBACK_EXPLANATIONS["info"])

    # Pick best fix based on check type
    fix = FALLBACK_FIXES["default"]
    for key in FALLBACK_FIXES:
        if key in check:
            fix = FALLBACK_FIXES[key]
            break

    return {
        "risk_score":  risk_score,
        "severity":    sev,
        "title":       finding.get("check", "Security Finding"),
        "explanation": explanation,
        "impact":      "This vulnerability could impact the security posture of the application and its users.",
        "fix":         fix,
        "ai_powered":  False,
    }


# ─────────────────────────────────────────
# MAIN ENTRY — called by CLI
# ─────────────────────────────────────────

def triage_findings(findings: list) -> list:
    """
    Enrich each finding with AI analysis.
    Uses Groq API if key available, falls back to rule-based triage.
    Returns enriched findings list.
    """
    # Skip info-only findings to save API calls
    skip_checks = {"pages discovered", "web scan complete",
                   "api scan complete", "host info", "web scan failed"}

    enriched = []
    use_ai   = bool(GROQ_API_KEY)

    for i, finding in enumerate(findings):
        check_lower = finding.get("check", "").lower()

        # Skip purely informational findings
        if any(s in check_lower for s in skip_checks):
            enriched.append(finding)
            continue

        if use_ai:
            prompt  = build_prompt(finding)
            ai_data = call_groq(prompt)

            if ai_data:
                finding["ai_triage"]   = {
                    "risk_score":  ai_data.get("risk_score", 5),
                    "title":       ai_data.get("title", finding["check"]),
                    "explanation": ai_data.get("explanation", ""),
                    "impact":      ai_data.get("impact", ""),
                    "fix":         ai_data.get("fix", ""),
                    "ai_powered":  True,
                }
            else:
                # AI call failed — use fallback
                finding["ai_triage"] = get_fallback_triage(finding)

            # Rate limit — 30 req/min on free Groq
            if i < len(findings) - 1:
                time.sleep(0.5)
        else:
            # No API key — use rule-based fallback
            finding["ai_triage"] = get_fallback_triage(finding)

        enriched.append(finding)

    return enriched