"""
Executive Threat & Plain-English Danger Engine for AutoSecAudit.

Translates technical DAST findings (CWE, OWASP, CVSS, raw HTTP payloads) into
concrete business risks and non-technical impact assessments for founders,
executives, and non-technical stakeholders.
"""

import logging
import re
from typing import Dict, List, Any, Optional, Union

from intelligence.taxonomy import (
    get_taxonomy,
    infer_taxonomy_from_text,
    CATEGORY_CUSTOMER_DATA,
    CATEGORY_ACCOUNT_TAKEOVER,
    CATEGORY_PHISHING_DEFACEMENT,
    CATEGORY_SERVER_CONTROL,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Core Threat Categories Metadata
# ---------------------------------------------------------------------------
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
def classify_threat_category(finding: Union[Dict[str, Any], Any]) -> str:
    """
    Map finding to one of the 4 real-world business threat categories.
    Uses canonical taxonomy first, and word-boundary regexes as fallback.
    Never misclassifies '[Dev Environment Artifact]' as customer data theft,
    and never classifies 'OAuth' by the 'auth' keyword alone.
    """
    # 1. First check vuln_type against taxonomy
    if isinstance(finding, str):
        vuln_type = None
        title = finding
        tool = ""
        owasp = ""
        desc = ""
    elif isinstance(finding, dict):
        vuln_type = finding.get("vuln_type")
        title = finding.get("title") or ""
        tool = finding.get("tool_name") or finding.get("tool") or ""
        owasp = finding.get("owasp_tag") or finding.get("owasp") or ""
        desc = finding.get("description") or ""
    else:
        vuln_type = getattr(finding, "vuln_type", None)
        title = getattr(finding, "title", "") or ""
        tool = getattr(finding, "tool_name", "") or getattr(finding, "tool", "") or ""
        owasp = getattr(finding, "owasp_tag", "") or getattr(finding, "owasp", "") or ""
        desc = getattr(finding, "description", "") or ""

    if vuln_type:
        tax = get_taxonomy(vuln_type)
        if tax:
            return tax.danger_category

    # 2. Clean dev artifact marker
    # Remove dev artifact marker to prevent false-match of 'env' inside 'environment'
    title_clean = re.sub(r"\[Dev Environment Artifact\]", "", title, flags=re.IGNORECASE)
    text = f"{title_clean} {desc} {tool.replace('_', ' ')}".strip()

    # 3. Try taxonomy text inference with word boundaries
    tax = infer_taxonomy_from_text(text)
    if tax:
        return tax.danger_category

    # 4. Fallback keyword matching with word-boundary regexes
    # Server control
    if re.search(r"\b(rce|command injection|remote code|exec|ssti|ssrf)\b", text, re.IGNORECASE):
        return CATEGORY_SERVER_CONTROL

    # Customer data (handles .env and .git without requiring preceding word character)
    if re.search(r"(?:(?<![\w.])\.(?:git|env)\b|\b(?:sqli|sql injection|database|dirbrute|directory listing|backup|source code|path traversal)\b)", text, re.IGNORECASE):
        return CATEGORY_CUSTOMER_DATA

    # Account takeover (Strict \bauth\b to NOT match oauth)
    if re.search(r"\b(auth|jwt|session|cookie|password|brute|idor|token|bola)\b", text, re.IGNORECASE):
        return CATEGORY_ACCOUNT_TAKEOVER

    # Phishing / defacement
    if re.search(r"\b(cors|xss|cross-site|csp|clickjacking|frame|header|hsts|redirect|csrf)\b", text, re.IGNORECASE):
        return CATEGORY_PHISHING_DEFACEMENT

    # OWASP tag fallback
    owasp_upper = owasp.upper()
    if "A03:2021" in owasp_upper:
        return CATEGORY_CUSTOMER_DATA
    if "A01:2021" in owasp_upper or "A07:2021" in owasp_upper:
        return CATEGORY_ACCOUNT_TAKEOVER
    if "A05:2021" in owasp_upper:
        return CATEGORY_PHISHING_DEFACEMENT
    if "A10:2021" in owasp_upper:
        return CATEGORY_SERVER_CONTROL

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

    elif "csrf" in title_lower or "cross-site request forgery" in title_lower:
        headline = "Cross-Site Request Forgery (CSRF) Vulnerability"
        what_is_broken = "State-changing web forms or API endpoints do not require unique synchronized CSRF tokens."
        what_attacker_can_do = "An attacker can create a phishing site that automatically submits unwanted actions (e.g. changing email/password, making payments) using the victim's active login session."
        business_impact = "🟠 High Risk — Unauthorized user actions performed without user knowledge or consent."
        estimated_fix_time = "5-15 minutes (add anti-CSRF token middleware & SameSite cookies)"

    elif "redirect" in title_lower:
        headline = "Open URL Redirection Vulnerability"
        what_is_broken = "A redirect parameter (e.g. ?next= or ?url=) accepts untrusted external domain names without validation."
        what_attacker_can_do = "Scammers can send legitimate-looking links from your domain that silently redirect victims to credential-harvesting phishing pages."
        business_impact = "🟡 Medium Risk — Brand reputation damage and user credential theft via phishing."
        estimated_fix_time = "5 minutes (validate destination paths against a strict allowlist)"

    elif "bola" in title_lower or "idor" in title_lower or "broken object level" in title_lower:
        headline = "Broken Object-Level Authorization (IDOR) Flaw"
        what_is_broken = "API endpoints accept object IDs (e.g. /users/123) without verifying whether the caller owns that record."
        what_attacker_can_do = "An attacker can change the number in the URL to view, modify, or delete private profile and billing data of every user on the platform."
        business_impact = "🔴 Critical Risk — Widespread customer data exfiltration and privacy law violations."
        estimated_fix_time = "10-20 minutes (add user ownership validation checks in service layer)"

    elif "secret" in title_lower or ".env" in title_lower or "sensitive file" in title_lower:
        headline = "Exposed Secret Keys & Infrastructure Blueprint"
        what_is_broken = "Sensitive configuration files (e.g. .env, .git, or backup dumps) are publicly downloadable."
        what_attacker_can_do = "Attackers can download live API keys, database passwords, or private encryption secrets and gain administrative access."
        business_impact = "🔴 Critical Risk — Complete backend compromise and infrastructure hijacking."
        estimated_fix_time = "2-5 minutes (deny access in web server and rotate all leaked keys)"

    elif "tls" in title_lower or "ssl" in title_lower or "hsts" in title_lower:
        headline = "Insecure Cryptographic Transport / Weak TLS"
        what_is_broken = "Missing HSTS headers or support for deprecated SSL/TLS protocols."
        what_attacker_can_do = "Network eavesdroppers or public Wi-Fi attackers can intercept or downgrade user traffic to plaintext."
        business_impact = "🟡 Medium Risk — Network interception and failure to meet compliance standards."
        estimated_fix_time = "5 minutes (enforce TLS 1.2+ and enable HSTS in Nginx/web server)"

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
def calculate_security_posture(findings: List[Union[Dict[str, Any], Any]]) -> Dict[str, Any]:
    """
    Calculate letter grade (A+ to F), numerical score, and executive summary.
    - Findings are deduplicated by fingerprint (or tool:title).
    - Severity penalties are weighted by confidence: high=1.0, medium=0.6, low=0.25 (default 0.6).
    - An automatic 'F' is triggered ONLY if a finding is Critical AND at least medium confidence.
    """
    # Weights by confidence
    CONFIDENCE_WEIGHTS = {
        "high": 1.0,
        "medium": 0.6,
        "low": 0.25,
    }

    SEVERITY_PENALTIES = {
        "critical": 25,
        "high": 12,
        "medium": 5,
        "low": 1,
        "info": 0,
    }

    def _finding_rank(finding_dict: Dict[str, Any]) -> tuple:
        s = (finding_dict.get("severity") or "info").lower()
        c = (finding_dict.get("confidence") or "medium").lower()
        # Rank by confidence weight first, then severity penalty
        return (CONFIDENCE_WEIGHTS.get(c, 0.6), SEVERITY_PENALTIES.get(s, 0))

    deduped_map: Dict[str, Dict[str, Any]] = {}
    for item in findings:
        f = item.to_dict() if hasattr(item, "to_dict") else dict(item) if isinstance(item, dict) else item.__dict__
        fp = f.get("fingerprint")
        if not fp:
            tool = f.get("tool_name") or f.get("tool") or ""
            title = f.get("title") or ""
            fp = f"{tool}:{title}"
        if fp in deduped_map:
            # Retain finding with highest confidence weight and severity
            if _finding_rank(f) > _finding_rank(deduped_map[fp]):
                deduped_map[fp] = f
        else:
            deduped_map[fp] = f

    deduped = list(deduped_map.values())
    total = len(deduped)

    crit_count = 0
    high_count = 0
    med_count = 0
    low_count = 0
    has_confirmed_critical = False
    total_penalty = 0.0

    for f in deduped:
        sev = (f.get("severity") or "info").lower()
        conf = (f.get("confidence") or "medium").lower()
        weight = CONFIDENCE_WEIGHTS.get(conf, 0.6)
        base_penalty = SEVERITY_PENALTIES.get(sev, 0)

        total_penalty += base_penalty * weight

        if sev == "critical":
            crit_count += 1
            if conf in ("high", "medium"):
                has_confirmed_critical = True
        elif sev == "high":
            high_count += 1
        elif sev == "medium":
            med_count += 1
        elif sev == "low":
            low_count += 1

    # Score calculation out of 100
    score = 100 - round(total_penalty)
    score = max(10, min(100, int(score)))

    # Automatic F triggered ONLY if confirmed critical (>= medium confidence) or score < 50
    if has_confirmed_critical or score < 50:
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

    for f in deduped:
        cat = classify_threat_category(f)
        category_counts[cat] = category_counts.get(cat, 0) + 1

    threat_matrix = []
    for cat_id, meta in CATEGORY_METADATA.items():
        count = category_counts.get(cat_id, 0)
        status = "CRITICAL" if count > 0 and has_confirmed_critical and cat_id in [CATEGORY_CUSTOMER_DATA, CATEGORY_SERVER_CONTROL] else ("AT RISK" if count > 0 else "SECURE")
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
