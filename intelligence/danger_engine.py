"""
Executive Threat & Plain-English Danger Engine for AutoSecAudit.

Translates technical DAST findings (CWE, OWASP, CVSS, raw HTTP payloads) into
concrete business risks and non-technical impact assessments for founders,
executives, and non-technical stakeholders.
"""

import logging
from typing import Dict, List, Any, Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Core Threat Categories
# ---------------------------------------------------------------------------
CATEGORY_CUSTOMER_DATA = "customer_data_theft"
CATEGORY_ACCOUNT_TAKEOVER = "account_takeover"
CATEGORY_PHISHING_DEFACEMENT = "phishing_defacement"
CATEGORY_SERVER_CONTROL = "server_control"

CATEGORY_METADATA = {
    CATEGORY_CUSTOMER_DATA: {
        "title": "Customer Data & Database Theft",
        "icon": "🚨",
        "description": "Risk of outsiders downloading, modifying, or deleting user records, emails, or credentials.",
        "badge_color": "#ef4444",
    },
    CATEGORY_ACCOUNT_TAKEOVER: {
        "title": "Account Hijacking & Auth Bypass",
        "icon": "💳",
        "description": "Risk of attackers impersonating legitimate users, stealing sessions, or altering balances.",
        "badge_color": "#f59e0b",
    },
    CATEGORY_PHISHING_DEFACEMENT: {
        "title": "Phishing, XSS & Brand Defacement",
        "icon": "🌐",
        "description": "Risk of malicious sites stealing client tokens or embedding your app in fake deceptive pages.",
        "badge_color": "#3b82f6",
    },
    CATEGORY_SERVER_CONTROL: {
        "title": "Full Server Takeover & RCE",
        "icon": "🛑",
        "description": "Risk of an attacker executing system-level terminal commands or locking down the server.",
        "badge_color": "#dc2626",
    },
}


# ---------------------------------------------------------------------------
# Threat Mapping Heuristics
# ---------------------------------------------------------------------------
def classify_threat_category(finding: Dict[str, Any]) -> str:
    """Map finding to one of the 4 real-world business threat categories."""
    title = (finding.get("title") or "").lower()
    tool = (finding.get("tool_name") or finding.get("tool") or "").lower()
    owasp = (finding.get("owasp_tag") or finding.get("owasp") or "").upper()
    desc = (finding.get("description") or "").lower()

    if any(k in title or k in tool for k in ["rce", "command injection", "remote code", "exec"]):
        return CATEGORY_SERVER_CONTROL

    if any(k in title or k in tool for k in ["sqli", "sql injection", "database", "git", "env", "dirbrute", "directory listing", "backup", "source code"]):
        return CATEGORY_CUSTOMER_DATA

    if any(k in title or k in tool for k in ["auth", "jwt", "session", "cookie", "password", "brute", "idor", "token"]):
        return CATEGORY_ACCOUNT_TAKEOVER

    if any(k in title or k in tool for k in ["cors", "xss", "cross-site", "csp", "clickjacking", "frame", "header", "hsts", "redirect"]):
        return CATEGORY_PHISHING_DEFACEMENT

    # OWASP tag fallback
    if "A03:2021" in owasp:
        return CATEGORY_CUSTOMER_DATA
    if "A01:2021" in owasp or "A07:2021" in owasp:
        return CATEGORY_ACCOUNT_TAKEOVER
    if "A05:2021" in owasp:
        return CATEGORY_PHISHING_DEFACEMENT

    return CATEGORY_CUSTOMER_DATA


def analyze_real_danger(finding: Dict[str, Any]) -> Dict[str, Any]:
    """Generate a non-technical Plain-English Danger Assessment for a finding."""
    title = finding.get("title", "Security Vulnerability")
    title_lower = title.lower()
    category = classify_threat_category(finding)
    meta = CATEGORY_METADATA.get(category, CATEGORY_METADATA[CATEGORY_CUSTOMER_DATA])

    headline = "Potential Security Weakness"
    what_is_broken = "A web server endpoint did not strictly validate incoming requests."
    what_attacker_can_do = "An unauthorized visitor could probe this endpoint to gather system intelligence."
    business_impact = "Moderate operational risk."
    estimated_fix_time = "5-15 minutes"

    if "sql injection" in title_lower or "sqli" in title_lower:
        headline = "Database Extraction / Data Breach Hazard"
        what_is_broken = "The application sends user input directly into database queries without parameterization."
        what_attacker_can_do = "Anyone on the internet can type custom database commands into search/input fields and download your entire customer table, user passwords, or delete records."
        business_impact = "🔴 Critical Data Breach Risk — High risk of GDPR/regulatory fines and customer notification liabilities."
        estimated_fix_time = "5-10 minutes (parameterize queries)"

    elif "directory listing" in title_lower or "dirbrute" in title_lower or ".git" in title_lower:
        headline = "Sensitive File / Source Blueprint Exposure"
        what_is_broken = "Your web server exposes internal directories and system files to public browsing."
        what_attacker_can_do = "An attacker can browse private directories, download configuration backups, database dumps, or source code containing API keys."
        business_impact = "🟠 High Risk — Attackers gain a direct roadmap of your private architecture and credentials."
        estimated_fix_time = "2 minutes (disable directory listing in Nginx/Apache)"

    elif "cors" in title_lower:
        headline = "Cross-Domain Data Leakage"
        what_is_broken = "Your API permits any external third-party domain (wildcard '*') to read user responses."
        what_attacker_can_do = "A malicious website can trick your logged-in users into visiting their site, then secretly send requests to your API and steal their private data."
        business_impact = "🟠 High Risk — Unauthorized theft of customer session data via browser spoofing."
        estimated_fix_time = "5 minutes (restrict CORS origins to your domain)"

    elif "auth" in title_lower or "password" in title_lower or "jwt" in title_lower:
        headline = "Authentication & Login Verification Weakness"
        what_is_broken = "The login or authorization handler does not strictly verify identity or lacks rate limiting."
        what_attacker_can_do = "Attackers can brute-force passwords, forge authentication tokens, or access restricted endpoints without valid credentials."
        business_impact = "🔴 Critical Risk — Direct account takeover and unauthorized administrative access."
        estimated_fix_time = "10-20 minutes (add rate limiting and token signature verification)"

    elif "cookie" in title_lower or "httponly" in title_lower:
        headline = "Session Cookie Theft Hazard"
        what_is_broken = "Session cookies lack the 'HttpOnly' or 'Secure' flags."
        what_attacker_can_do = "Malicious browser scripts or insecure networks can intercept or copy the user's active session cookie, enabling session hijacking."
        business_impact = "🟡 Medium Risk — Increases vulnerability to session theft."
        estimated_fix_time = "3 minutes (add HttpOnly; Secure; SameSite=Lax to cookie config)"

    elif "csp" in title_lower or "frame" in title_lower or "clickjacking" in title_lower:
        headline = "Clickjacking & Deceptive Embedding Risk"
        what_is_broken = "Missing 'Content-Security-Policy' or 'X-Frame-Options' headers."
        what_attacker_can_do = "A scammer can embed your site inside an invisible iframe on a fake website and trick users into clicking buttons they didn't intend to click."
        business_impact = "🟡 Medium Risk — Phishing, unauthorized actions, and brand reputation damage."
        estimated_fix_time = "2 minutes (add security headers middleware)"

    return {
        "category": category,
        "category_title": meta["title"],
        "category_icon": meta["icon"],
        "headline": headline,
        "what_is_broken": what_is_broken,
        "what_attacker_can_do": what_attacker_can_do,
        "business_impact": business_impact,
        "estimated_fix_time": estimated_fix_time,
    }


# ---------------------------------------------------------------------------
# Posture Grade & Threat Matrix Calculator
# ---------------------------------------------------------------------------
def calculate_security_posture(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Calculate letter grade (A+ to F), numerical score, and executive summary."""
    total = len(findings)
    crit_count = sum(1 for f in findings if (f.get("severity") or "").lower() == "critical")
    high_count = sum(1 for f in findings if (f.get("severity") or "").lower() == "high")
    med_count = sum(1 for f in findings if (f.get("severity") or "").lower() == "medium")
    low_count = sum(1 for f in findings if (f.get("severity") or "").lower() == "low")

    # Score calculation out of 100
    score = 100 - (crit_count * 25 + high_count * 12 + med_count * 5 + low_count * 1)
    score = max(10, min(100, score))

    if crit_count > 0 or score < 50:
        grade = "F"
        grade_label = "Severe Danger"
        grade_color = "#ef4444"
        summary = f"⚠️ CRITICAL ACTION REQUIRED: {crit_count} critical vulnerability detected that poses an immediate data breach threat."
    elif high_count > 1 or score < 70:
        grade = "D"
        grade_label = "High Risk"
        grade_color = "#f97316"
        summary = f"High Risk: {high_count} high-severity findings require urgent patching to protect user accounts and data."
    elif high_count == 1 or med_count > 2 or score < 85:
        grade = "C"
        grade_label = "Needs Attention"
        grade_color = "#f59e0b"
        summary = "Needs Attention: Moderate weaknesses detected in headers or endpoint configurations."
    elif med_count > 0 or low_count > 2 or score < 95:
        grade = "B"
        grade_label = "Good Posture"
        grade_color = "#3b82f6"
        summary = "Good Posture: Minor configuration hardening recommended."
    else:
        grade = "A+"
        grade_label = "Hardened & Secure"
        grade_color = "#10b981"
        summary = "Excellent Posture: No critical or high risk vectors detected."

    # Threat category breakdown
    category_counts = {
        CATEGORY_CUSTOMER_DATA: 0,
        CATEGORY_ACCOUNT_TAKEOVER: 0,
        CATEGORY_PHISHING_DEFACEMENT: 0,
        CATEGORY_SERVER_CONTROL: 0,
    }

    for f in findings:
        cat = classify_threat_category(f)
        category_counts[cat] = category_counts.get(cat, 0) + 1

    threat_matrix = []
    for cat_id, meta in CATEGORY_METADATA.items():
        count = category_counts.get(cat_id, 0)
        status = "CRITICAL" if count > 0 and crit_count > 0 and cat_id in [CATEGORY_CUSTOMER_DATA, CATEGORY_SERVER_CONTROL] else ("AT RISK" if count > 0 else "SECURE")
        color = "#ef4444" if status == "CRITICAL" else ("#f59e0b" if status == "AT RISK" else "#10b981")

        threat_matrix.append({
            "id": cat_id,
            "title": meta["title"],
            "icon": meta["icon"],
            "description": meta["description"],
            "count": count,
            "status": status,
            "color": color,
        })

    return {
        "grade": grade,
        "grade_label": grade_label,
        "grade_color": grade_color,
        "score": score,
        "summary": summary,
        "total_findings": total,
        "critical_count": crit_count,
        "high_count": high_count,
        "medium_count": med_count,
        "low_count": low_count,
        "threat_matrix": threat_matrix,
    }
