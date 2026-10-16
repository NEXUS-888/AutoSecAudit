import os
import secrets
from pathlib import Path

import ipaddress
import logging

logger = logging.getLogger("config")

BASE_DIR = Path(__file__).parent
PLUGINS_DIR = str(BASE_DIR / "plugins")


def _load_env_file() -> None:
    env_file = BASE_DIR / ".env"
    if env_file.is_file():
        try:
            for line in env_file.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    k, v = k.strip(), v.strip().strip("'\"")
                    if k and k not in os.environ:
                        os.environ[k] = v
        except Exception as e:
            logger.debug("Failed to read .env: %s", e)


_load_env_file()



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
ALLOW_REGISTRATION = os.environ.get("AUTOSEC_ALLOW_REGISTRATION", "false").lower() in ("true", "1", "yes")


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


def resolve_cookie_secure(is_https: bool = False) -> bool:
    """Resolve whether session cookies should carry the Secure flag.

    Honors AUTOSEC_COOKIE_SECURE override ('1'/'true'/'yes' -> True,
    '0'/'false'/'no' -> False). Defaults to True when the request is over
    HTTPS (is_https=True), and False on plain HTTP local connections.
    """
    raw = os.environ.get("AUTOSEC_COOKIE_SECURE", "").strip().lower()
    if raw in ("1", "true", "yes"):
        return True
    if raw in ("0", "false", "no"):
        return False
    return bool(is_https)


# Web application security
SECRET_KEY = _get_or_create_secret_key()
DEBUG = os.environ.get("AUTOSEC_DEBUG", "false").lower() == "true"
COOKIE_SECURE = resolve_cookie_secure(False)
SESSION_COOKIE_SECURE = COOKIE_SECURE
SESSION_COOKIE_SAMESITE = "Lax"
SESSION_COOKIE_HTTPONLY = True

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
# Login-endpoint SQL injection probing limit (AUD-71)
MAX_LOGIN_PROBE_REQUESTS = int(os.environ.get("AUTOSEC_MAX_LOGIN_PROBE_REQUESTS", "25"))
SQLI_MAX_LOGIN_REQUESTS = MAX_LOGIN_PROBE_REQUESTS

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

# Form injection probe limits (AUD-52; raised from 8 after the 2026-10-13 retest, where apps with
# ~12-36 equally-promising forms dropped real vulnerabilities below an 8-form cap). Env-overridable.
def _bounded_int(env_name, default, low, high):
    raw = os.environ.get(env_name)
    if raw is not None:
        try:
            val = int(raw)
            if low <= val <= high:
                return val
        except (TypeError, ValueError):
            pass
    return default

MAX_FORMS_PER_PLUGIN = _bounded_int("AUTOSEC_MAX_FORMS_PER_PLUGIN", 20, 1, 100)
MAX_FIELDS_PER_FORM = _bounded_int("AUTOSEC_MAX_FIELDS_PER_FORM", 6, 1, 30)
FORM_PROBE_MAX_FORMS = MAX_FORMS_PER_PLUGIN
FORM_PROBE_MAX_FIELDS = MAX_FIELDS_PER_FORM
MAX_FORM_PROBES = MAX_FORMS_PER_PLUGIN
MAX_FORM_FIELDS = MAX_FIELDS_PER_FORM

# Crawler budget limits (AUD-55)
DEFAULT_CRAWL_MAX_PAGES = 100
MIN_CRAWL_MAX_PAGES = 1
MAX_CRAWL_MAX_PAGES = 500

DEFAULT_CRAWL_MAX_DEPTH = 4
MIN_CRAWL_MAX_DEPTH = 1
MAX_CRAWL_MAX_DEPTH = 8

DEFAULT_CRAWL_MAX_SECONDS = 60
MIN_CRAWL_MAX_SECONDS = 5
MAX_CRAWL_MAX_SECONDS = 600

CRAWL_MAX_PAGES = _load_bounded_int(
    "AUTOSEC_CRAWL_MAX_PAGES",
    DEFAULT_CRAWL_MAX_PAGES,
    MIN_CRAWL_MAX_PAGES,
    MAX_CRAWL_MAX_PAGES,
)
CRAWL_MAX_DEPTH = _load_bounded_int(
    "AUTOSEC_CRAWL_MAX_DEPTH",
    DEFAULT_CRAWL_MAX_DEPTH,
    MIN_CRAWL_MAX_DEPTH,
    MAX_CRAWL_MAX_DEPTH,
)
CRAWL_MAX_SECONDS = _load_bounded_int(
    "AUTOSEC_CRAWL_MAX_SECONDS",
    DEFAULT_CRAWL_MAX_SECONDS,
    MIN_CRAWL_MAX_SECONDS,
    MAX_CRAWL_MAX_SECONDS,
)

# Engine scan deadline (AUD-59)
DEFAULT_SCAN_DEADLINE_SECONDS = 300
MIN_SCAN_DEADLINE_SECONDS = 30
MAX_SCAN_DEADLINE_SECONDS = 3600

_legacy_scan_timeout = _load_bounded_int(
    "AUTOSEC_SCAN_TIMEOUT",
    DEFAULT_SCAN_DEADLINE_SECONDS,
    MIN_SCAN_DEADLINE_SECONDS,
    MAX_SCAN_DEADLINE_SECONDS,
)
SCAN_DEADLINE_SECONDS = _load_bounded_int(
    "AUTOSEC_SCAN_DEADLINE_SECONDS",
    _legacy_scan_timeout,
    MIN_SCAN_DEADLINE_SECONDS,
    MAX_SCAN_DEADLINE_SECONDS,
)
SCAN_TIMEOUT = SCAN_DEADLINE_SECONDS

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
        "name": "Reconnaissance (Low-Impact Active Probing)",
        "description": "External reconnaissance, SSL/TLS validation, directory discovery, and port enumeration.",
        "plugins": [
            "SSLTLSScanner", "MisconfigScanner", "DirBruteScanner", "NiktoPlugin",
            "NmapPlugin", "SecretExposureScanner"
        ]
    }
}

