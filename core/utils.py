import re
import json
import logging
from pathlib import Path
from typing import Any, Dict, Optional
from datetime import datetime
import config

logging.basicConfig(
    level=getattr(logging, config.LOG_LEVEL),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


def validate_target(target: str) -> bool:
    """Validate target is a valid URL or IP address."""
    ip_pattern = r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    url_pattern = r"^(?:https?://)?(?:[\w-]+\.)+[\w-]+(?::\d+)?(?:/.*)?$"
    localhost_pattern = r"^(?:https?://)?(?:localhost|127\.0\.0\.1)(?::\d+)?(?:/.*)?$"
    
    if re.match(ip_pattern, target):
        return True
    if re.match(url_pattern, target):
        return True
    if re.match(localhost_pattern, target):
        return True
    return False


def normalize_target(target: str) -> str:
    """Normalize target to a consistent format."""
    if not target.startswith(("http://", "https://")):
        target = f"http://{target}"
    return target.rstrip("/")


def load_json(file_path: str) -> Optional[Dict[str, Any]]:
    """Load JSON from file."""
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        logger.warning(f"File not found: {file_path}")
        return None
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON in {file_path}: {e}")
        return None


def save_json(data: Dict[str, Any], file_path: str, indent: int = 2) -> bool:
    """Save data to JSON file."""
    try:
        path = Path(file_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=indent, ensure_ascii=False)
        return True
    except Exception as e:
        logger.error(f"Failed to save JSON to {file_path}: {e}")
        return False


def get_timestamp() -> str:
    """Get current timestamp in configured format."""
    return datetime.now().strftime(config.REPORT_TIMESTAMP_FORMAT)


def get_severity_order(severity: str) -> int:
    """Return numeric value for severity sorting."""
    order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
    return order.get(severity, 5)


def format_severity(severity: str) -> str:
    """Normalize severity to standard values."""
    severity = severity.upper()
    mapping = {
        "CRITICAL": "Critical",
        "HIGH": "High",
        "MEDIUM": "Medium",
        "LOW": "Low",
        "INFO": "Info",
        "INFORMATIONAL": "Info"
    }
    return mapping.get(severity, "Medium")


# ---------------------------------------------------------------------------
# Target restriction — only allow scanning of authorized targets
# ---------------------------------------------------------------------------

# Domains explicitly allowed for security testing (intentionally vulnerable apps)
ALLOWED_DOMAINS = {
    "localhost",
    "127.0.0.1",
    "0.0.0.0",
    "juice-shop",
    "dvwa",
    "metasploitable",
    "hackthebox",
    "tryhackme",
    "vulnhub",
    "pentesterlab",
    "webgoat",
    "bwapp",
}

# Private IP ranges (RFC 1918)
PRIVATE_IP_PREFIXES = (
    "10.",
    "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.",
    "172.24.", "172.25.", "172.26.", "172.27.",
    "172.28.", "172.29.", "172.30.", "172.31.",
    "192.168.",
)


def is_target_allowed(target: str) -> tuple:
    """Check if the target is allowed for scanning.

    Returns:
        (allowed: bool, reason: str)
    """
    import urllib.parse

    # Normalize
    clean = target.strip()
    if not clean.startswith(("http://", "https://")):
        clean = f"http://{clean}"

    parsed = urllib.parse.urlparse(clean)
    hostname = (parsed.hostname or "").lower()

    if not hostname:
        return False, "Could not parse hostname from target."

    # 1. Check if hostname is in the allowed list
    if hostname in ALLOWED_DOMAINS:
        return True, "Allowed target."

    # 2. Check if hostname ends with an allowed domain (e.g. juice-shop.local)
    for allowed in ALLOWED_DOMAINS:
        if hostname.endswith(f".{allowed}") or hostname.endswith(f"-{allowed}"):
            return True, "Allowed target."

    # 3. Check private IP ranges
    if hostname.startswith(PRIVATE_IP_PREFIXES):
        return True, "Private network target."

    # 4. Check loopback
    if hostname.startswith("127.") or hostname == "::1":
        return True, "Loopback address."

    # 5. Everything else is blocked
    return False, (
        f"Scanning '{hostname}' is not allowed. "
        f"AutoSecAudit only permits scanning of:\n"
        f"  • localhost / 127.0.0.1\n"
        f"  • Private network IPs (192.168.x.x, 10.x.x.x, 172.16-31.x.x)\n"
        f"  • Known practice targets (Juice Shop, DVWA, WebGoat, etc.)\n"
        f"\n"
        f"Scanning third-party websites without written permission is illegal."
    )

