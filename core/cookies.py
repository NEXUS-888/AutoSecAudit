"""Inspect Set-Cookie headers for missing hardening flags on session-like cookies."""

from typing import Any, Dict, List

# Cookie names that plausibly carry a session or credential. Others (theme, locale) are ignored.
SESSION_NAME_HINTS = ("sess", "sid", "token", "auth", "jwt", "login")


def parse_set_cookie(header: str) -> Dict[str, Any]:
    """Split one Set-Cookie header into its name and lower-cased attributes."""
    parts = [p.strip() for p in header.split(";") if p.strip()]
    name = parts[0].split("=", 1)[0].strip() if parts else ""
    attrs = {}
    for part in parts[1:]:
        key, _, value = part.partition("=")
        attrs[key.strip().lower()] = value.strip().lower()
    return {"name": name, "attrs": attrs}


# Anti-CSRF cookies are meant to be read by page scripts (double-submit pattern), so HttpOnly is not expected.
CSRF_NAME_HINTS = ("csrf", "xsrf")


def is_session_cookie(name: str) -> bool:
    lowered = name.lower()
    if any(hint in lowered for hint in CSRF_NAME_HINTS):
        return False
    return any(hint in lowered for hint in SESSION_NAME_HINTS)


def insecure_cookie_flags(set_cookie_headers: List[str], https: bool = False) -> List[Dict[str, Any]]:
    """Return one entry per session-like cookie that is missing HttpOnly, SameSite or (over HTTPS) Secure."""
    issues = []
    for header in set_cookie_headers or []:
        cookie = parse_set_cookie(header)
        name, attrs = cookie["name"], cookie["attrs"]
        if not name or not is_session_cookie(name):
            continue
        missing = []
        if "httponly" not in attrs:
            missing.append("HttpOnly")
        if "samesite" not in attrs:
            missing.append("SameSite")
        if https and "secure" not in attrs:
            missing.append("Secure")
        if missing:
            issues.append({"cookie": name, "missing": missing})
    return issues


def raw_set_cookie_headers(response) -> List[str]:
    """All Set-Cookie header values of a requests.Response (requests merges them in .headers)."""
    raw_headers = getattr(getattr(response, "raw", None), "headers", None)
    if raw_headers is not None and hasattr(raw_headers, "getlist"):
        return list(raw_headers.getlist("Set-Cookie"))
    single = getattr(response, "headers", {}).get("Set-Cookie") if response is not None else None
    return [single] if single else []


def describe_issue(issue: Dict[str, Any]) -> str:
    return (f"Session cookie '{issue['cookie']}' is set without: {', '.join(issue['missing'])}. "
            "HttpOnly keeps scripts from reading it (XSS cookie theft), SameSite limits cross-site "
            "sending (CSRF), and Secure keeps it off plain HTTP.")


def severity_for(issue: Dict[str, Any]) -> str:
    return "Medium" if "HttpOnly" in issue["missing"] else "Low"
