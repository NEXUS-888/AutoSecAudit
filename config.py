import os
import secrets
from pathlib import Path

import ipaddress
import logging

logger = logging.getLogger("config")

BASE_DIR = Path(__file__).parent
PLUGINS_DIR = str(BASE_DIR / "plugins")


def _get_data_dir() -> str:
    return os.environ.get("AUTOSEC_DATA_DIR") or str(BASE_DIR / "data")


def _get_reports_dir() -> str:
    return str(Path(_get_data_dir()) / "reports")


def __getattr__(name: str):
    if name == "DATA_DIR":
        return _get_data_dir()
    if name == "REPORTS_DIR":
        return _get_reports_dir()
    raise AttributeError(f"module '{__name__}' has no attribute '{name}'")


def __dir__():
    return sorted(list(globals().keys()) + ["DATA_DIR", "REPORTS_DIR"])


MOCK_MODE = os.environ.get("AUTOSEC_MOCK_MODE", "true").lower() == "true"


def _is_loopback(host_str: str) -> bool:
    if host_str in ("localhost", "127.0.0.1", "::1"):
        return True
    try:
        return ipaddress.ip_address(host_str).is_loopback
    except ValueError:
        return False


HOST = os.environ.get("AUTOSEC_HOST", "127.0.0.1")
if not _is_loopback(HOST):
    logger.warning("AUTOSEC_HOST '%s' is not a loopback address; server will be exposed to the network.", HOST)


def _get_or_create_secret_key() -> str:
    env_key = os.environ.get("AUTOSEC_SECRET_KEY")
    if env_key:
        return env_key
    secret_path = Path(_get_data_dir()) / ".secret_key"
    try:
        if secret_path.is_file():
            content = secret_path.read_text(encoding="utf-8").strip()
            if content:
                return content
    except Exception as e:
        logger.warning(f"Could not read existing secret key from {secret_path}: {e}")

    key = secrets.token_hex(32)
    try:
        secret_path.parent.mkdir(parents=True, exist_ok=True)
        flags = os.O_WRONLY | os.O_CREAT
        if hasattr(os, "O_EXCL"):
            flags |= os.O_EXCL
        try:
            fd = os.open(str(secret_path), flags, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(key)
        except FileExistsError:
            content = secret_path.read_text(encoding="utf-8").strip()
            if content:
                return content
    except Exception as e:
        logger.warning(f"Could not persist secret key to {secret_path}: {e}")
    return key


# Web application security
SECRET_KEY = _get_or_create_secret_key()
DEBUG = os.environ.get("AUTOSEC_DEBUG", "false").lower() == "true"

THREAD_COUNT = int(os.environ.get("AUTOSEC_THREAD_COUNT", "4"))

NMAP_PATH = os.environ.get("AUTOSEC_NMAP_PATH", "nmap")
# Scan every port on the host instead of just the target's port (opt-in; slow, and on localhost
# it reports unrelated services running on the machine).
NMAP_FULL_SCAN = os.environ.get("AUTOSEC_NMAP_FULL_SCAN", "").lower() in ("1", "true", "yes")
NIKTO_PATH = os.environ.get("AUTOSEC_NIKTO_PATH", "nikto")

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CIRCL_API_URL = "https://cve.circl.lu/api/cve"

LOG_LEVEL = os.environ.get("AUTOSEC_LOG_LEVEL", "INFO")

REPORT_TIMESTAMP_FORMAT = "%Y-%m-%d %H:%M:%S"

# HTTP scanning settings
HTTP_TIMEOUT = int(os.environ.get("AUTOSEC_HTTP_TIMEOUT", "10"))
SCAN_TIMEOUT = int(os.environ.get("AUTOSEC_SCAN_TIMEOUT", "300"))
USER_AGENT = "AutoSecAudit/2.0"

DEFAULT_MAX_RESPONSE_BYTES = 5 * 1024 * 1024  # 5 MiB
MIN_MAX_RESPONSE_BYTES = 64 * 1024            # 64 KiB
MAX_MAX_RESPONSE_BYTES = 100 * 1024 * 1024   # 100 MiB

DEFAULT_MAX_REQUEST_SECONDS = 30
MIN_MAX_REQUEST_SECONDS = 1
MAX_MAX_REQUEST_SECONDS = 300


def _load_bounded_int(env_name: str, default: int, min_val: int, max_val: int) -> int:
    raw = os.environ.get(env_name)
    if raw is None or raw == "":
        return default
    try:
        val = int(raw)
    except (ValueError, TypeError):
        logger.warning(
            "%s=%r is not a valid integer; falling back to default %d.",
            env_name,
            raw,
            default,
        )
        return default
    if val < min_val or val > max_val:
        logger.warning(
            "%s=%d is outside valid range [%d, %d]; falling back to default %d.",
            env_name,
            val,
            min_val,
            max_val,
            default,
        )
        return default
    return val


MAX_RESPONSE_BYTES = _load_bounded_int(
    "AUTOSEC_MAX_RESPONSE_BYTES",
    DEFAULT_MAX_RESPONSE_BYTES,
    MIN_MAX_RESPONSE_BYTES,
    MAX_MAX_RESPONSE_BYTES,
)
MAX_REQUEST_SECONDS = _load_bounded_int(
    "AUTOSEC_MAX_REQUEST_SECONDS",
    DEFAULT_MAX_REQUEST_SECONDS,
    MIN_MAX_REQUEST_SECONDS,
    MAX_MAX_REQUEST_SECONDS,
)

# Scan Profiles configuration
SCAN_PROFILES = {
    "full": {
        "name": "Full Spectrum DAST Audit",
        "description": "Comprehensive security assessment executing all dynamic vulnerability scanners.",
        "plugins": None
    },
    "owasp": {
        "name": "OWASP Top 10 Suite",
        "description": "Targeted assessment focusing on injection, auth, SSRF, misconfigurations, and access controls.",
        "plugins": [
            "SQLiScanner", "XSSScanner", "CSRFScanner", "SSRFScanner", "AuthScanner",
            "MisconfigScanner", "CommandInjectionScanner", "PathTraversalScanner",
            "SSTIScanner", "SecretExposureScanner", "OpenRedirectScanner"
        ]
    },
    "api": {
        "name": "API & Microservices Suite",
        "description": "Headless API security audit covering BOLA/IDOR, JWT flaws, rate limiting, and CORS.",
        "plugins": [
            "BOLAIdorScanner", "JWTScanner", "CORSScanner", "APIAbuseScanner",
            "AuthScanner", "SQLiScanner", "XSSScanner"
        ]
    },
    "recon": {
        "name": "Passive & Non-Intrusive Recon",
        "description": "External reconnaissance, SSL/TLS validation, directory discovery, and port enumeration.",
        "plugins": [
            "SSLTLSScanner", "MisconfigScanner", "DirBruteScanner", "NiktoPlugin",
            "NmapPlugin", "SecretExposureScanner"
        ]
    }
}

