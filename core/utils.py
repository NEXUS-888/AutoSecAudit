import re
import json
import logging
import socket
import ipaddress
import urllib.parse
from pathlib import Path
from typing import Any, Dict, Optional, Tuple
from datetime import datetime
import config

logging.basicConfig(
    level=getattr(logging, config.LOG_LEVEL),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


def _is_valid_hostname(hostname: str) -> bool:
    """Check if hostname is a valid IP literal or valid DNS hostname label(s)."""
    if not hostname or len(hostname) > 253:
        return False
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        pass
    labels = hostname.split(".")
    for label in labels:
        if not label or len(label) > 63:
            return False
        if not re.match(r"^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$", label):
            return False
    return True


def validate_target(target: str) -> bool:
    """Validate target is a valid URL or host/IP.

    Accepts http/https URLs or bare host/IP with optional port/path.
    Scheme must be http or https (if none, http is assumed).
    Hostname must be present and valid.
    Port, if specified, must be between 1 and 65535.
    IPv6 literals (e.g. [::1]) are supported.
    """
    if not target or not isinstance(target, str):
        return False
    clean = target.strip()
    if not clean:
        return False

    if "://" in clean:
        scheme, _ = clean.split("://", 1)
        if scheme.lower() not in ("http", "https"):
            return False
        to_parse = clean
    else:
        to_parse = f"http://{clean}"

    try:
        parsed = urllib.parse.urlsplit(to_parse)
    except Exception:
        return False

    if parsed.scheme.lower() not in ("http", "https"):
        return False

    try:
        hostname = parsed.hostname
        port = parsed.port
    except ValueError:
        # e.g. Port out of range 0-65535
        return False

    if not hostname:
        return False

    if not _is_valid_hostname(hostname):
        return False

    if port is not None and not (1 <= port <= 65535):
        return False

    return True


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


def generate_report_id() -> str:
    """Generate a unique report ID in format <YYYYmmdd_HHMMSS>_<6 hex>."""
    import secrets
    return f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_{secrets.token_hex(3)}"


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


def is_target_allowed(target: str) -> Tuple[bool, str]:
    """Check if the target is allowed for scanning.

    Only targets where every resolved IP is a private (RFC 1918 / RFC 4193)
    or loopback address (IPv4 and IPv6) are permitted.

    Returns:
        (allowed: bool, reason: str)
    """
    if not target or not isinstance(target, str):
        return False, "Target is empty or invalid."

    clean = target.strip()
    if "://" in clean:
        to_parse = clean
    else:
        to_parse = f"http://{clean}"

    try:
        parsed = urllib.parse.urlsplit(to_parse)
        hostname = parsed.hostname
    except Exception as e:
        return False, f"Could not parse hostname from target: {e}"

    if not hostname:
        return False, "Could not parse hostname from target."

    # 1. IP literal check
    try:
        ip = ipaddress.ip_address(hostname)
        if ip.is_private or ip.is_loopback:
            return True, f"IP address '{hostname}' is allowed (private/loopback)."
        return False, (
            f"Scanning public IP '{hostname}' is not allowed. "
            f"AutoSecAudit only permits private networks and loopback targets."
        )
    except ValueError:
        pass

    # 2. Hostname resolution
    try:
        addrinfo = socket.getaddrinfo(hostname, None)
    except (socket.gaierror, socket.herror) as e:
        return False, f"Cannot resolve hostname '{hostname}': {e}"
    except Exception as e:
        return False, f"Resolution error for '{hostname}': {e}"

    if not addrinfo:
        return False, f"Hostname '{hostname}' did not resolve to any addresses."

    resolved_ips = []
    for res in addrinfo:
        ip_str = res[4][0]
        try:
            ip = ipaddress.ip_address(ip_str)
            resolved_ips.append(ip)
        except ValueError:
            return False, f"Invalid resolved IP address: {ip_str}"

    for ip in resolved_ips:
        if not (ip.is_private or ip.is_loopback):
            return False, (
                f"Hostname '{hostname}' resolves to public IP {ip}. "
                f"AutoSecAudit only permits private networks and loopback targets."
            )

    return True, f"Hostname '{hostname}' resolves to allowed private/loopback addresses."


def check_target_reachable(target: str, timeout: float = 2.5) -> Tuple[bool, str]:
    """Check if the target host and port are actually listening and reachable.

    Returns:
        (is_reachable: bool, message: str)
    """
    import urllib.parse
    import socket
    import requests

    clean = target.strip()
    if not clean.startswith(("http://", "https://")):
        clean = f"http://{clean}"

    parsed = urllib.parse.urlparse(clean)
    hostname = (parsed.hostname or "").lower()
    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    if not hostname:
        return False, "Could not determine hostname from target URL."

    # Fast HTTP probe
    try:
        headers = {"User-Agent": getattr(config, "USER_AGENT", "AutoSecAudit/2.0")}
        resp = requests.head(clean, timeout=timeout, allow_redirects=True, verify=False, headers=headers)
        if resp.status_code == 405:  # Method Not Allowed for HEAD
            resp = requests.get(clean, timeout=timeout, allow_redirects=True, verify=False, headers=headers)
        return True, f"Target responded with HTTP {resp.status_code}"
    except requests.exceptions.SSLError:
        return True, "Target is listening (SSL certificate observed)"
    except requests.exceptions.ConnectionError as e:
        err_str = str(e)
        if "Connection refused" in err_str or "10061" in err_str or "WSAECONNREFUSED" in err_str or "timed out" in err_str:
            return False, f"Connection refused on {hostname}:{port}. No active service is listening."
        elif "getaddrinfo failed" in err_str or "11001" in err_str or "Name or service not known" in err_str:
            return False, f"DNS resolution failed for '{hostname}'. Host does not exist."
        return False, f"Could not connect to {hostname}:{port}: Connection failed."
    except requests.exceptions.Timeout:
        return False, f"Connection to {hostname}:{port} timed out after {timeout}s."
    except Exception as e:
        # Fallback: Raw TCP socket probe
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            res = sock.connect_ex((hostname, port))
            sock.close()
            if res == 0:
                return True, f"TCP port {port} is open and listening"
            return False, f"TCP connection to {hostname}:{port} failed (code {res})"
        except Exception as sock_err:
            return False, f"Could not reach {hostname}:{port}: {sock_err}"


