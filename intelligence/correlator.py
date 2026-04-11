import logging
from typing import List, Dict, Any
from collections import defaultdict

from core.models import Finding

logger = logging.getLogger(__name__)


class Correlator:
    """Correlate related findings across different scanners."""

    def __init__(self):
        self.correlation_groups: List[Dict[str, Any]] = []

    def correlate(self, findings: List[Finding]) -> List[Dict[str, Any]]:
        """Group related findings by host and port."""
        self.correlation_groups = []
        
        port_groups = defaultdict(list)
        for f in findings:
            key = f"{f.host}:{f.port}"
            port_groups[key].append(f)

        for key, group in port_groups.items():
            if len(group) > 1:
                correlated = {
                    "host": group[0].host,
                    "port": group[0].port,
                    "findings": [f.to_dict() for f in group],
                    "correlation_type": "multi_tool",
                    "count": len(group)
                }
                self.correlation_groups.append(correlated)
                logger.info(f"Correlated {len(group)} findings for {key}")

        return self.correlation_groups

    def link_related(self, findings: List[Finding]) -> List[Finding]:
        """Link related findings and add correlation metadata."""
        port_map = defaultdict(list)
        for i, f in enumerate(findings):
            key = f"{f.host}:{f.port}"
            port_map[key].append(i)

        for key, indices in port_map.items():
            if len(indices) > 1:
                related_ids = [findings[i].id for i in indices]
                for i in indices:
                    if not findings[i].references:
                        findings[i].references = []
                    findings[i].references.append(f"Related findings: {', '.join(related_ids[:3])}")

        return findings
