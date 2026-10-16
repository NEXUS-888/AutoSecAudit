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

    def merge_canonical(self, findings: List[Finding]) -> List[Finding]:
        """Merge findings sharing canonical key vuln_type|method|normalized_endpoint|param.
        
        Ignores which tool reported the finding.
        Keeps highest-confidence evidence, lists every reporting tool,
        and uses one severity per vuln_type from the AUD-37 table.
        """
        from intelligence.taxonomy import get_taxonomy
        from core.utils import format_severity

        CONF_RANK = {"high": 3, "medium": 2, "low": 1}
        groups = defaultdict(list)
        for f in findings:
            key = f.compute_canonical_key() if hasattr(f, "compute_canonical_key") else None
            if not key:
                from core.models import compute_canonical_key
                key = compute_canonical_key(
                    vuln_type=getattr(f, "vuln_type", None),
                    method=getattr(f, "method", None),
                    endpoint=getattr(f, "endpoint", None),
                    param=getattr(f, "param", None),
                    title=getattr(f, "title", None),
                )
            groups[key].append(f)

        merged_results = []
        for key, group in groups.items():
            parts = key.split("|")
            canonical_vuln = parts[0]
            tax = get_taxonomy(canonical_vuln)
            canonical_sev = format_severity(tax.default_severity) if tax and tax.default_severity else None

            if len(group) == 1:
                f = group[0]
                if canonical_sev:
                    f.severity = canonical_sev
                if not getattr(f, "reporting_tools", None):
                    f.reporting_tools = [f.tool_name] if f.tool_name else []
                merged_results.append(f)
                continue

            # Multiple findings sharing canonical key: merge!
            best = max(
                group,
                key=lambda x: (
                    CONF_RANK.get((getattr(x, "confidence", "medium") or "medium").lower(), 2),
                    getattr(x, "id", "") or "",
                    getattr(x, "tool_name", "") or "",
                ),
            )
            highest_conf = best.confidence or "medium"
            evidence = best.evidence or best.raw_output

            # Gather all reporting tools
            tools = []
            for item in group:
                t_val = getattr(item, "tool_name", "") or ""
                for t in str(t_val).split(","):
                    t_clean = t.strip()
                    if t_clean and t_clean not in tools:
                        tools.append(t_clean)
            tools_sorted = sorted(tools)
            tool_str = ", ".join(tools_sorted)

            sev = canonical_sev if canonical_sev else best.severity

            # Merge references
            all_refs = []
            for item in group:
                if item.references:
                    for r in item.references:
                        if r not in all_refs:
                            all_refs.append(r)

            norm_ep = parts[2]
            norm_param = parts[3] or None
            norm_method = parts[1]

            merged = Finding(
                id=best.id,
                title=best.title,
                severity=sev,
                host=best.host,
                port=best.port,
                description=best.description,
                raw_output=best.raw_output,
                cve_id=best.cve_id,
                cvss_score=best.cvss_score,
                references=all_refs or None,
                owasp_tag=best.owasp_tag or (tax.owasp if tax else None),
                tool_name=tool_str,
                confidence=highest_conf,
                remediation=best.remediation or (tax.remediation_key if tax else None),
                cwe_id=best.cwe_id or (tax.cwe if tax else None),
                pci_dss=best.pci_dss or (tax.pci if tax else None),
                vuln_type=canonical_vuln,
                endpoint=norm_ep,
                param=norm_param,
                method=norm_method,
                evidence=evidence,
            )
            merged.reporting_tools = tools_sorted
            merged_results.append(merged)

        return merged_results

    def link_related(self, findings: List[Finding], cross_tool: bool = False) -> List[Finding]:
        """Deduplicate findings by fingerprint and link related findings by (endpoint, param).
        
        Guaranteed to be idempotent.
        """
        deduped = self._deduplicate(findings)
        if cross_tool:
            deduped = self.merge_canonical(deduped)

        endpoint_param_map = defaultdict(list)
        for f in deduped:
            if getattr(f, "endpoint", None):
                key = (f.endpoint, f.param or "")
                endpoint_param_map[key].append(f)

        for key, group in endpoint_param_map.items():
            if len(group) > 1:
                related_ids = sorted([item.id for item in group if item.id])
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
