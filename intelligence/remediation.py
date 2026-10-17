"""
Remediation knowledge base for AutoSecAudit.

Maps vulnerability types (by OWASP tag and tool_name) to actionable,
human-readable fix suggestions. The Enricher or Engine can call
`get_remediation()` for each finding to auto-populate the remediation field.
"""

import logging
import re
from typing import Optional, List
from core.models import Finding
from intelligence.taxonomy import get_taxonomy, infer_taxonomy_from_text

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Remediation database – keyed by OWASP tag
# ---------------------------------------------------------------------------
OWASP_REMEDIATIONS = {
    "A01:2021": (
        "1. Implement proper access control checks on every endpoint.\n"
        "2. Deny by default — require explicit grants for each resource.\n"
        "3. Use role-based access control (RBAC) and validate permissions server-side.\n"
        "4. Disable directory listing on your web server.\n"
        "5. Log and alert on access control failures."
    ),
    "A02:2021": (
        "1. Use TLS 1.2+ for all data in transit.\n"
        "2. Encrypt sensitive data at rest using AES-256 or equivalent.\n"
        "3. Never use deprecated algorithms (MD5, SHA1, DES, RC4).\n"
        "4. Rotate cryptographic keys regularly.\n"
        "5. Use HSTS headers to enforce HTTPS."
    ),
    "A03:2021": (
        "1. Use parameterized queries / prepared statements for all database queries.\n"
        "2. Use ORM frameworks that handle escaping automatically.\n"
        "3. Validate and sanitize all user inputs on the server side.\n"
        "4. Apply the principle of least privilege to database accounts.\n"
        "5. Use Content-Security-Policy headers to mitigate XSS."
    ),
    "A04:2021": (
        "1. Use threat modeling during the design phase.\n"
        "2. Implement defense-in-depth with multiple layers of security.\n"
        "3. Use secure design patterns and reference architectures.\n"
        "4. Limit resource consumption with rate limiting and quotas.\n"
        "5. Perform security reviews before deployment."
    ),
    "A05:2021": (
        "1. Remove default credentials and unnecessary features.\n"
        "2. Add security headers: Content-Security-Policy, X-Frame-Options, "
        "X-Content-Type-Options, Strict-Transport-Security.\n"
        "3. Disable detailed error messages in production.\n"
        "4. Keep all software and dependencies updated.\n"
        "5. Automate configuration hardening with security baselines."
    ),
    "A06:2021": (
        "1. Maintain an inventory of all components and their versions.\n"
        "2. Subscribe to CVE alerts for your dependencies.\n"
        "3. Use automated tools (npm audit, pip-audit, Snyk) to detect vulnerabilities.\n"
        "4. Remove unused dependencies.\n"
        "5. Prefer actively maintained libraries with good security track records."
    ),
    "A07:2021": (
        "1. Implement account lockout or exponential backoff after failed attempts.\n"
        "2. Use multi-factor authentication (MFA).\n"
        "3. Never ship with default or weak credentials.\n"
        "4. Use strong, adaptive password hashing (bcrypt, argon2).\n"
        "5. Implement proper session management with secure cookie flags."
    ),
    "A08:2021": (
        "1. Verify the integrity of all software and updates using digital signatures.\n"
        "2. Use Subresource Integrity (SRI) for third-party scripts.\n"
        "3. Implement CI/CD pipeline security checks.\n"
        "4. Ensure libraries are pulled from trusted, verified repositories.\n"
        "5. Use signed commits and code review processes."
    ),
    "A09:2021": (
        "1. Log all authentication events (success and failure).\n"
        "2. Log access control failures and input validation failures.\n"
        "3. Ensure log data is encoded correctly to prevent injection.\n"
        "4. Send logs to a centralized, tamper-resistant logging system.\n"
        "5. Set up alerts for suspicious activity patterns."
    ),
    "A10:2021": (
        "1. Validate and sanitize all client-supplied URLs.\n"
        "2. Block requests to internal/private IP ranges (127.0.0.1, 10.x, 192.168.x).\n"
        "3. Use allowlists for permitted external services.\n"
        "4. Disable URL redirects where possible.\n"
        "5. Enforce firewall rules to limit outbound server requests."
    ),
    "API1:2023": (
        "1. Validate that the authenticated session user has explicit ownership of requested object IDs.\n"
        "2. Avoid using predictable sequential IDs in API URLs; use UUIDs or signed tokens.\n"
        "3. Implement centralized authorization filters at the API route and repository layers."
    ),
    "API2:2023": (
        "1. Strictly verify JWT signatures using secure cryptographic algorithms (RS256/ES256).\n"
        "2. Reject tokens with 'alg: none' and enforce expiration timestamps.\n"
        "3. Implement rate-limiting and account lockout policies on authentication endpoints."
    ),
}

# ---------------------------------------------------------------------------
# Tool-specific remediation overrides – more specific than OWASP generic
# ---------------------------------------------------------------------------
TOOL_REMEDIATIONS = {
    # SQLi scanner
    "sqli_scanner:error_based": (
        "1. Replace string concatenation in SQL queries with parameterized queries.\n"
        "2. Use an ORM (SQLAlchemy, Django ORM, Sequelize) instead of raw SQL.\n"
        "3. Suppress database error messages in production responses.\n"
        "4. Apply input validation — reject special characters in search/filter parameters.\n"
        "5. Use a Web Application Firewall (WAF) as an additional defense layer."
    ),
    "sqli_scanner:login_bypass": (
        "1. Use parameterized queries for authentication queries — NEVER concatenate user input.\n"
        "2. Implement account lockout after 5 failed login attempts.\n"
        "3. Use bcrypt or argon2 for password hashing.\n"
        "4. Add CAPTCHA or rate limiting to login endpoints.\n"
        "5. Consider using an authentication library (Passport.js, Flask-Login)."
    ),
    # XSS scanner
    "xss_scanner:reflected_xss": (
        "1. Encode all user-controlled output using context-appropriate encoding (HTML, JS, URL).\n"
        "2. Use a templating engine with auto-escaping enabled (Jinja2, React JSX).\n"
        "3. Set Content-Security-Policy header to restrict inline scripts.\n"
        "4. Validate input — reject or strip HTML tags from user input.\n"
        "5. Use HttpOnly and Secure flags on cookies to limit XSS impact."
    ),
    "xss_scanner:dom_xss_indicator": (
        "1. Avoid using innerHTML, document.write(), and eval() with user data.\n"
        "2. Use textContent or innerText instead of innerHTML for DOM updates.\n"
        "3. Sanitize user input with a library like DOMPurify before rendering.\n"
        "4. Enable Trusted Types via Content-Security-Policy.\n"
        "5. Perform code review for all DOM manipulation patterns."
    ),
    "xss_scanner:missing_header": (
        "1. Add the missing security header to your server configuration.\n"
        "2. Content-Security-Policy: default-src 'self'; script-src 'self'\n"
        "3. X-Content-Type-Options: nosniff\n"
        "4. X-Frame-Options: DENY\n"
        "5. Test headers with securityheaders.com after deployment."
    ),
    # Auth scanner
    "auth_scanner:brute_force": (
        "1. Implement account lockout after 5 consecutive failed attempts.\n"
        "2. Add exponential backoff (increasing delay between retries).\n"
        "3. Use CAPTCHA after 3 failed login attempts.\n"
        "4. Implement IP-based rate limiting on authentication endpoints.\n"
        "5. Alert on brute-force patterns in your monitoring system."
    ),
    "auth_scanner:default_credentials": (
        "1. Change all default credentials immediately after deployment.\n"
        "2. Force password change on first login.\n"
        "3. Enforce strong password policies (min 12 chars, mixed case, numbers).\n"
        "4. Use a secrets manager for application credentials.\n"
        "5. Audit for default credentials in CI/CD before deployment."
    ),
    "auth_scanner:idor": (
        "1. Implement object-level authorization checks on every data access.\n"
        "2. Use indirect reference maps (UUIDs) instead of sequential IDs.\n"
        "3. Verify the authenticated user owns or has access to the requested resource.\n"
        "4. Log all unauthorized access attempts.\n"
        "5. Use automated IDOR testing in your security test suite."
    ),
    # Misconfig scanner
    "misconfig_scanner:server_info_leak": (
        "1. Remove or obfuscate Server, X-Powered-By, and X-AspNet-Version headers.\n"
        "2. In Nginx: add 'server_tokens off;' to your config.\n"
        "3. In Apache: set 'ServerTokens Prod' and 'ServerSignature Off'.\n"
        "4. In Express.js: use helmet() middleware.\n"
        "5. Remove framework-specific default error pages."
    ),
    # API abuse scanner
    "api_abuse_scanner:rate_limit": (
        "1. Implement rate limiting on all API endpoints (e.g., 100 req/min).\n"
        "2. Use API keys or tokens to track and limit usage per client.\n"
        "3. Return HTTP 429 Too Many Requests with Retry-After header.\n"
        "4. Use a reverse proxy (Nginx, API Gateway) for rate limiting.\n"
        "5. Implement circuit breakers for downstream services."
    ),
    "api_abuse_scanner:sensitive_data": (
        "1. Never expose sensitive fields (passwords, tokens, SSNs) in API responses.\n"
        "2. Use response filtering/serialization to whitelist returned fields.\n"
        "3. Classify data sensitivity levels and enforce access controls.\n"
        "4. Encrypt sensitive data both at rest and in transit.\n"
        "5. Audit API responses regularly for data leaks."
    ),
    # Canonical default mappings keyed by tool_name:remediation_key
    "sqli_scanner:sqli": (
        "1. Replace string concatenation in SQL queries with parameterized queries.\n"
        "2. Use an ORM (SQLAlchemy, Django ORM, Sequelize) instead of raw SQL.\n"
        "3. Suppress database error messages in production responses.\n"
        "4. Apply input validation — reject special characters in search/filter parameters.\n"
        "5. Use a Web Application Firewall (WAF) as an additional defense layer."
    ),
    "xss_scanner:xss": (
        "1. Encode all user-controlled output using context-appropriate encoding (HTML, JS, URL).\n"
        "2. Use a templating engine with auto-escaping enabled (Jinja2, React JSX).\n"
        "3. Set Content-Security-Policy header to restrict inline scripts.\n"
        "4. Validate input — reject or strip HTML tags from user input.\n"
        "5. Use HttpOnly and Secure flags on cookies to limit XSS impact."
    ),
    "auth_scanner:auth": (
        "1. Implement account lockout after 5 consecutive failed attempts.\n"
        "2. Add exponential backoff (increasing delay between retries).\n"
        "3. Use CAPTCHA after 3 failed login attempts.\n"
        "4. Implement IP-based rate limiting on authentication endpoints.\n"
        "5. Alert on brute-force patterns in your monitoring system."
    ),
    "misconfig_scanner:misconfig": (
        "1. Remove or obfuscate Server, X-Powered-By, and X-AspNet-Version headers.\n"
        "2. In Nginx: add 'server_tokens off;' to your config.\n"
        "3. In Apache: set 'ServerTokens Prod' and 'ServerSignature Off'.\n"
        "4. In Express.js: use helmet() middleware.\n"
        "5. Remove framework-specific default error pages."
    ),
    "api_abuse_scanner:api_abuse": (
        "1. Implement rate limiting on all API endpoints (e.g., 100 req/min).\n"
        "2. Use API keys or tokens to track and limit usage per client.\n"
        "3. Return HTTP 429 Too Many Requests with Retry-After header.\n"
        "4. Use a reverse proxy (Nginx, API Gateway) for rate limiting.\n"
        "5. Implement circuit breakers for downstream services."
    ),
}

# ---------------------------------------------------------------------------
# Direct remediation advice database keyed by taxonomy remediation_key
# ---------------------------------------------------------------------------
REMEDIATION_KEY_DATABASE = {
    "sqli": (
        "1. Replace string concatenation in SQL queries with parameterized queries.\n"
        "2. Use an ORM (SQLAlchemy, Django ORM, Sequelize) instead of raw SQL.\n"
        "3. Suppress database error messages in production responses.\n"
        "4. Apply input validation — reject special characters in search/filter parameters.\n"
        "5. Use a Web Application Firewall (WAF) as an additional defense layer."
    ),
    "xss": (
        "1. Encode all user-controlled output using context-appropriate encoding (HTML, JS, URL).\n"
        "2. Use a templating engine with auto-escaping enabled (Jinja2, React JSX).\n"
        "3. Set Content-Security-Policy header to restrict inline scripts.\n"
        "4. Validate input — reject or strip HTML tags from user input.\n"
        "5. Use HttpOnly and Secure flags on cookies to limit XSS impact."
    ),
    "command_injection": (
        "1. Never pass unsanitized input to shell execution functions (system, exec, popen).\n"
        "2. Use parameter arrays instead of shell command strings.\n"
        "3. Use allowlists for permitted commands and input values.\n"
        "4. Run web processes with minimal system privileges."
    ),
    "ssrf": (
        "1. Validate and sanitize all client-supplied URLs.\n"
        "2. Restrict outbound connections using a network allowlist.\n"
        "3. Block private and local IP ranges (127.0.0.1, 10.x, 192.168.x).\n"
        "4. Disable URL redirects where possible.\n"
        "5. Enforce firewall rules to limit outbound server requests."
    ),
    "ssti": (
        "1. Never concatenate user input directly into template strings.\n"
        "2. Pass user input as context variables into pre-compiled templates.\n"
        "3. Use sandboxed template execution environments.\n"
        "4. Enforce strict Content-Security-Policy."
    ),
    "idor": (
        "1. Implement object-level authorization checks on every data access.\n"
        "2. Use indirect reference maps (UUIDs) instead of sequential IDs.\n"
        "3. Verify the authenticated user owns or has access to the requested resource.\n"
        "4. Log all unauthorized access attempts.\n"
        "5. Use automated IDOR testing in your security test suite."
    ),
    "csrf": (
        "1. Implement anti-CSRF tokens for all state-changing POST/PUT/DELETE endpoints.\n"
        "2. Set SameSite=Lax or SameSite=Strict on session cookies.\n"
        "3. Verify Origin and Referer headers on incoming requests."
    ),
    "open_redirect": (
        "1. Validate target redirect URLs against a strict whitelist of internal domains.\n"
        "2. Enforce relative path redirects starting with a single '/' (not '//').\n"
        "3. Avoid using user-supplied parameters directly in redirect targets."
    ),
    "path_traversal": (
        "1. Validate file paths against an allowlist of permitted files.\n"
        "2. Use os.path.basename or equivalent to strip directory traversal sequences.\n"
        "3. Resolve canonical paths and verify they stay within the base directory."
    ),
    "dir_brute": (
        "1. Disable directory listing on the web server.\n"
        "2. Block public access to sensitive paths, configuration files, and backups.\n"
        "3. Return generic 404 responses for restricted paths."
    ),
    "secret_exposure": (
        "1. Immediately rotate any credentials or keys exposed publicly.\n"
        "2. Deny public HTTP access to configuration and dotfiles (.env, .git, .aws).\n"
        "3. Use environment variables and secrets managers instead of committed files."
    ),
    "misconfig": (
        "1. Remove or obfuscate Server, X-Powered-By, and X-AspNet-Version headers.\n"
        "2. In Nginx: add 'server_tokens off;' to your config.\n"
        "3. In Apache: set 'ServerTokens Prod' and 'ServerSignature Off'.\n"
        "4. In Express.js: use helmet() middleware.\n"
        "5. Remove framework-specific default error pages."
    ),
    "info_disclosure": (
        "1. Suppress verbose error messages and stack traces in production.\n"
        "2. Configure custom error pages for 404, 500, and other HTTP errors.\n"
        "3. Strip internal IP addresses, system paths, and debugging comments from responses."
    ),
    "cors": (
        "1. Restrict Access-Control-Allow-Origin to trusted explicit origins (never '*').\n"
        "2. Never combine wildcard origin with Access-Control-Allow-Credentials: true.\n"
        "3. Verify incoming Origin header against a server-side allowlist."
    ),
    "ssl_tls": (
        "1. Enforce HTTPS across all endpoints with Strict-Transport-Security (HSTS).\n"
        "2. Disable deprecated TLS 1.0/1.1 protocols and weak ciphers.\n"
        "3. Use automated certificate renewal with valid trusted CAs."
    ),
    "auth": (
        "1. Implement account lockout after 5 consecutive failed attempts.\n"
        "2. Add exponential backoff (increasing delay between retries).\n"
        "3. Use CAPTCHA after 3 failed login attempts.\n"
        "4. Implement IP-based rate limiting on authentication endpoints.\n"
        "5. Alert on brute-force patterns in your monitoring system."
    ),
    "jwt": (
        "1. Strictly verify JWT signatures using secure cryptographic algorithms (RS256/ES256).\n"
        "2. Reject tokens with 'alg: none' and enforce expiration timestamps.\n"
        "3. Store tokens in HttpOnly Secure cookies to prevent script access."
    ),
    "api_abuse": (
        "1. Implement rate limiting on all API endpoints (e.g., 100 req/min).\n"
        "2. Use API keys or tokens to track and limit usage per client.\n"
        "3. Return HTTP 429 Too Many Requests with Retry-After header.\n"
        "4. Use a reverse proxy (Nginx, API Gateway) for rate limiting.\n"
        "5. Implement circuit breakers for downstream services."
    ),
    "graphql_introspection": (
        "1. Disable GraphQL introspection in production environments.\n"
        "2. Implement field-level authorization and validation on query types.\n"
        "3. Apply rate limiting and query complexity / depth limits.\n"
        "4. Require authentication for sensitive GraphQL queries.\n"
        "5. Suppress verbose schema error messages in API responses."
    ),
    "graphql_endpoint": (
        "1. Ensure GraphQL endpoints are properly authenticated and authorized.\n"
        "2. Disable schema introspection in production.\n"
        "3. Enforce query depth and breadth limiting to prevent resource exhaustion."
    ),
    "graphql": (
        "1. Disable GraphQL introspection in production environments.\n"
        "2. Parameterize queries and validate all input arguments against strict schemas.\n"
        "3. Enforce query depth and complexity limits."
    ),
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
def get_remediation(finding: Finding) -> Optional[str]:
    """
    Look up remediation advice for a finding.

    Priority:
    1. Tool-specific + remediation_key (e.g. sqli_scanner:sqli) or sub-type refinement
    2. Taxonomy remediation_key database lookup (REMEDIATION_KEY_DATABASE)
    3. Taxonomy OWASP mapping from vuln_type
    4. Explicit OWASP tag on finding
    5. Taxonomy text inference
    """
    tax = get_taxonomy(finding.vuln_type) if finding.vuln_type else None
    rem_key = tax.remediation_key if tax else finding.vuln_type

    # 1. Tool-specific lookup using sub-type refinement or remediation_key
    if finding.tool_name:
        # Check sub-type refinement from description (e.g. "Type: error_based" for sqli_scanner)
        # Checked before tool default so specific advice takes precedence.
        if finding.description:
            sub_type = _extract_finding_type(finding.description)
            if sub_type:
                key = f"{finding.tool_name}:{sub_type}"
                if key in TOOL_REMEDIATIONS:
                    # Enforce family consistency against sub_type alone if rem_key is set
                    FAMILY_SUBTYPES = {
                        "sqli": {"error_based", "login_bypass", "sqli"},
                        "xss": {"reflected_xss", "dom_xss_indicator", "missing_header", "xss"},
                        "auth": {"brute_force", "default_credentials", "auth"},
                        "idor": {"idor"},
                        "bola_idor": {"idor"},
                        "misconfig": {"server_info_leak", "missing_header", "misconfig"},
                        "api_abuse": {"rate_limit", "sensitive_data", "api_abuse", "graphql_introspection", "graphql_endpoint"},
                    }
                    allowed = FAMILY_SUBTYPES.get(rem_key, {rem_key} if rem_key else None)
                    if allowed is None or sub_type in allowed:
                        return TOOL_REMEDIATIONS[key]

        # Check tool_name:remediation_key default
        if rem_key:
            tool_rem_key = f"{finding.tool_name}:{rem_key}"
            if tool_rem_key in TOOL_REMEDIATIONS:
                return TOOL_REMEDIATIONS[tool_rem_key]

    # 2. Direct remediation_key database lookup (all 21 taxonomy types)
    if rem_key and rem_key in REMEDIATION_KEY_DATABASE:
        return REMEDIATION_KEY_DATABASE[rem_key]

    # 3. Taxonomy OWASP mapping from vuln_type
    if tax and tax.owasp in OWASP_REMEDIATIONS:
        return OWASP_REMEDIATIONS[tax.owasp]

    # 4. Fall back to OWASP tag on finding
    if finding.owasp_tag:
        if finding.owasp_tag in OWASP_REMEDIATIONS:
            return OWASP_REMEDIATIONS[finding.owasp_tag]
        # Match OWASP code prefix e.g. "A01:2021", "A01:2021-Broken", "API1:2023"
        m = re.match(r"^([A-Za-z0-9]+:\d{4})", finding.owasp_tag)
        if m and m.group(1) in OWASP_REMEDIATIONS:
            return OWASP_REMEDIATIONS[m.group(1)]
        tag_key = finding.owasp_tag.split()[0] if " " in finding.owasp_tag else finding.owasp_tag
        if tag_key in OWASP_REMEDIATIONS:
            return OWASP_REMEDIATIONS[tag_key]

    # 5. Fallback text inference
    text = f"{finding.title or ''} {finding.description or ''}"
    inf_tax = infer_taxonomy_from_text(text)
    if inf_tax:
        if inf_tax.remediation_key in REMEDIATION_KEY_DATABASE:
            return REMEDIATION_KEY_DATABASE[inf_tax.remediation_key]
        if inf_tax.owasp in OWASP_REMEDIATIONS:
            return OWASP_REMEDIATIONS[inf_tax.owasp]

    return None


def enrich_with_remediation(findings: List[Finding]) -> List[Finding]:
    """
    Populate the `remediation` field on each finding that doesn't already have one.
    Returns the same list (mutated in place) for convenience.
    """
    enriched_count = 0
    for f in findings:
        if f.remediation is None:
            advice = get_remediation(f)
            if advice:
                f.remediation = advice
                enriched_count += 1
    logger.info(f"Added remediation advice to {enriched_count}/{len(findings)} findings")
    return findings


def _extract_finding_type(description: str) -> Optional[str]:
    """Extract the 'Type: xxx' value from a finding description."""
    for line in description.split("\n"):
        line = line.strip()
        if line.lower().startswith("type:"):
            return line.split(":", 1)[1].strip()
    return None
