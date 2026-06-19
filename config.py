import os
import secrets
from pathlib import Path

BASE_DIR = Path(__file__).parent
DATA_DIR = str(BASE_DIR / "data")
REPORTS_DIR = str(BASE_DIR / "data" / "reports")
PLUGINS_DIR = str(BASE_DIR / "plugins")

MOCK_MODE = os.environ.get("AUTOSEC_MOCK_MODE", "true").lower() == "true"

# Web application security
SECRET_KEY = os.environ.get("AUTOSEC_SECRET_KEY", secrets.token_hex(32))
DEBUG = os.environ.get("AUTOSEC_DEBUG", "false").lower() == "true"

THREAD_COUNT = int(os.environ.get("AUTOSEC_THREAD_COUNT", "4"))

NMAP_PATH = os.environ.get("AUTOSEC_NMAP_PATH", "nmap")
NIKTO_PATH = os.environ.get("AUTOSEC_NIKTO_PATH", "nikto")

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CIRCL_API_URL = "https://cve.circl.lu/api/cve"

LOG_LEVEL = os.environ.get("AUTOSEC_LOG_LEVEL", "INFO")

REPORT_TIMESTAMP_FORMAT = "%Y-%m-%d %H:%M:%S"

# HTTP scanning settings
HTTP_TIMEOUT = int(os.environ.get("AUTOSEC_HTTP_TIMEOUT", "10"))
SCAN_TIMEOUT = int(os.environ.get("AUTOSEC_SCAN_TIMEOUT", "300"))
USER_AGENT = "AutoSecAudit/2.0"

