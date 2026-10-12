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
            host_clean = f.host.rstrip("/") if f.host else f.host
            key = f"{host_clean}:{f.port}"
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

    def _deduplicate(self, findings: List[Finding]) -> List[Finding]:
        """Deduplicate findings by fingerprint, merging evidence and references."""
        seen = {}
        unique = []
        for f in findings:
            fp = getattr(f, "fingerprint", None)
            if not fp and hasattr(f, "compute_fingerprint"):
                fp = f.compute_fingerprint()
                f.fingerprint = fp
            if not fp:
                from core.models import compute_finding_fingerprint
                fp = compute_finding_fingerprint(
                    tool=getattr(f, "tool_name", None),
                    vuln_type=getattr(f, "vuln_type", None),
                    method=getattr(f, "method", None),
                    endpoint=getattr(f, "endpoint", None),
                    param=getattr(f, "param", None),
                    title=getattr(f, "title", None),
                )
                f.fingerprint = fp

            if fp in seen:
                existing = seen[fp]
                # Merge evidence
                if f.evidence:
                    if not existing.evidence:
                        existing.evidence = f.evidence
                    elif f.evidence not in existing.evidence:
                        existing.evidence = f"{existing.evidence}; {f.evidence}"
                # Merge references
                if f.references:
                    if existing.references is None:
                        existing.references = []
                    for ref in f.references:
                        if ref not in existing.references:
                            existing.references.append(ref)
            else:
                seen[fp] = f
                unique.append(f)
        return unique

    def link_related(self, findings: List[Finding]) -> List[Finding]:
        """Deduplicate findings by fingerprint and link related findings by (endpoint, param).
        
        Guaranteed to be idempotent.
        """
        deduped = self._deduplicate(findings)

        endpoint_param_map = defaultdict(list)
        for f in deduped:
            if getattr(f, "endpoint", None):
                key = (f.endpoint, f.param or "")
                endpoint_param_map[key].append(f)

        for key, group in endpoint_param_map.items():
            if len(group) > 1:
                related_ids = [item.id for item in group if item.id]
                ref_str = f"Related findings: {', '.join(related_ids[:3])}"
                for f in group:
                    if f.references is None:
                        f.references = []
                    existing_related = [r for r in f.references if r.startswith("Related findings:")]
                    if existing_related:
                        if ref_str not in existing_related:
                            f.references = [r for r in f.references if not r.startswith("Related findings:")]
                            f.references.append(ref_str)
                    else:
                        f.references.append(ref_str)

        return deduped
