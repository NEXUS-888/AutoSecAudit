import logging
import requests
from typing import Dict, Any

logger = logging.getLogger(__name__)


class WebhookNotifier:
    """Sends scan summary alerts to Slack, Discord, or generic webhooks."""

    def __init__(self, webhook_url: str):
        self.webhook_url = webhook_url

    def send_notification(self, report_summary: Dict[str, Any], target: str) -> bool:
        """Format and send notification payload."""
        if not self.webhook_url:
            return False

        total = report_summary.get("total", 0)
        critical = report_summary.get("critical", 0)
        high = report_summary.get("high", 0)
        medium = report_summary.get("medium", 0)
        low = report_summary.get("low", 0)

        # Discord / Slack compatible payload format
        payload = {
            "content": f"🚨 **AutoSecAudit Scan Complete** for `{target}`",
            "embeds": [
                {
                    "title": f"Security Scan Report: {target}",
                    "color": 15158332 if critical > 0 else (15105570 if high > 0 else 3066993),
                    "fields": [
                        {"name": "Total Findings", "value": str(total), "inline": True},
                        {"name": "Critical", "value": str(critical), "inline": True},
                        {"name": "High", "value": str(high), "inline": True},
                        {"name": "Medium", "value": str(medium), "inline": True},
                        {"name": "Low", "value": str(low), "inline": True},
                    ],
                    "footer": {"text": "AutoSecAudit 2.0 Security Framework"}
                }
            ]
        }

        try:
            resp = requests.post(self.webhook_url, json=payload, timeout=5)
            if resp.status_code in [200, 204]:
                logger.info(f"Webhook notification sent to {self.webhook_url}")
                return True
            logger.warning(f"Webhook returned status code {resp.status_code}")
            return False
        except Exception as e:
            logger.error(f"Failed to send webhook notification: {e}")
            return False
