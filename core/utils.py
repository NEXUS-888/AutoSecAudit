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
    url_pattern = r"^(?:https?://)?(?:[\w-]+\.)+[\w-]+(?:\d+)?(?:/.*)?$"
    
    if re.match(ip_pattern, target):
        return True
    if re.match(url_pattern, target):
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
