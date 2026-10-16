"""
Metrics computation and ground-truth matching for AutoSecAudit benchmarks.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from core.models import normalize_endpoint_path


def normalize_vuln_type(vuln_type: Optional[str]) -> str:
    """Normalize vulnerability type strings and aliases for benchmark comparison."""
    if not vuln_type:
        return "generic"
    v = str(vuln_type).strip().lower().replace("-", "_")
    alias_map = {
        "rce": "command_injection",
        "cmd_injection": "command_injection",
        "command injection": "command_injection",
        "bola": "idor",
        "bola_idor": "idor",
        "broken object level authorization": "idor",
        "sql injection": "sqli",
        "cross_site_scripting": "xss",
        "cross site scripting": "xss",
        "dirbrute": "dir_brute",
        "dir_bruteforce": "dir_brute",
        "directory_bruteforce": "dir_brute",
        "sensitive_file": "secret_exposure",
        "secrets": "secret_exposure",
        "secret_leak": "secret_exposure",
        "open redirect": "open_redirect",
        "path traversal": "path_traversal",
        "lfi": "path_traversal",
        "template injection": "ssti",
    }
    return alias_map.get(v, v)


def normalize_benchmark_endpoint(endpoint: Optional[str]) -> str:
    """Normalize endpoint path using core.models conventions.

    Normalizes numeric segments to {id}, placeholder styles to {id},
    strips query parameters and parenthetical notes.
    """
    norm = normalize_endpoint_path(endpoint)
    if not norm.startswith("/"):
        norm = "/" + norm
    return norm


def endpoint_matches(finding_norm_ep: str, truth_norm_ep: str) -> bool:
    """Check if a reported normalized endpoint matches a truth endpoint pattern.

    Supports exact equality and single-segment placeholder matching ({id} matching any
    segment, including non-numeric identifiers such as {username} or {slug}).
    """
    if finding_norm_ep == truth_norm_ep:
        return True

    # If truth endpoint contains /{id}, match any single path segment
    if "/{id}" in truth_norm_ep:
        escaped = re.escape(truth_norm_ep)
        pattern_str = "^" + escaped.replace(r"/\{id\}", r"/[^/]+") + "$"
        if re.match(pattern_str, finding_norm_ep):
            return True

    # If finding endpoint contains /{id} (e.g. from crawler/OpenAPI), match concrete truth
    if "/{id}" in finding_norm_ep:
        escaped = re.escape(finding_norm_ep)
        pattern_str = "^" + escaped.replace(r"/\{id\}", r"/[^/]+") + "$"
        if re.match(pattern_str, truth_norm_ep):
            return True

    return False


@dataclass
class GroundTruthItem:
    id: str
    vuln_type: str
    endpoint: str
    classification: str = "real"  # "real" | "decoy"
    detectable: bool = True
    description: str = ""
    source: str = ""
    param: Optional[str] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> GroundTruthItem:
        return cls(
            id=str(data["id"]),
            vuln_type=normalize_vuln_type(data["vuln_type"]),
            endpoint=str(data["endpoint"]),
            classification=str(data.get("classification", "real")).lower(),
            detectable=bool(data.get("detectable", True)),
            description=str(data.get("description", "")),
            source=str(data.get("source", "")),
            param=data.get("param"),
        )


@dataclass
class GroundTruth:
    target: str
    items: List[Union[GroundTruthItem, Dict[str, Any]]]
    informational: List[Union[str, Dict[str, Any]]] = field(default_factory=list)
    description: str = ""

    def __post_init__(self):
        converted: List[GroundTruthItem] = []
        for it in self.items:
            if isinstance(it, dict):
                converted.append(GroundTruthItem.from_dict(it))
            else:
                converted.append(it)
        self.items = converted

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> GroundTruth:
        raw_items = data.get("items", [])
        items = [GroundTruthItem.from_dict(it) if isinstance(it, dict) else it for it in raw_items]
        return cls(
            target=data.get("target", "unknown"),
            items=items,
            informational=data.get("informational", []),
            description=data.get("description", ""),
        )

    @classmethod
    def from_file(cls, path: Union[str, Path]) -> GroundTruth:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return cls.from_dict(data)


def _matches_informational(
    vuln_type: str,
    norm_ep: str,
    informational: List[Union[str, Dict[str, Any]]]
) -> bool:
    """Check if an unmatched finding belongs to the accepted informational list."""
    for info in informational:
        if isinstance(info, str):
            if normalize_vuln_type(info) == vuln_type:
                return True
        elif isinstance(info, dict):
            info_vt = normalize_vuln_type(info.get("vuln_type"))
            info_ep = info.get("endpoint")
            if info_vt == vuln_type:
                if info_ep is None or endpoint_matches(norm_ep, normalize_benchmark_endpoint(info_ep)):
                    return True
    return False


def compute_metrics(
    findings: List[Any],
    truth: Union[GroundTruth, Dict[str, Any]],
    duration_seconds: float = 0.0,
) -> Dict[str, Any]:
    """Compute precision, recall, F1, and breakdown of findings against ground truth.

    Findings are matched to ground-truth items strictly by (normalized vuln_type, normalized endpoint).

    Args:
        findings: List of Finding instances or finding dictionaries.
        truth: GroundTruth instance or dictionary loaded from a ground-truth file.
        duration_seconds: Elapsed scan duration in seconds.

    Returns:
        Dictionary with true_positives, false_positives, false_negatives,
        precision, recall, f1, duration_seconds, matched_items, and details.
    """
    if isinstance(truth, dict):
        truth_obj = GroundTruth.from_dict(truth)
    else:
        truth_obj = truth

    # Group real and decoy items
    real_items: List[GroundTruthItem] = [it for it in truth_obj.items if it.classification != "decoy"]
    decoy_items: List[GroundTruthItem] = [it for it in truth_obj.items if it.classification == "decoy"]
    detectable_real_items = [it for it in real_items if it.detectable]

    matched_real_ids: Set[str] = set()
    matched_decoy_ids: Set[str] = set()
    false_positive_findings: List[Dict[str, Any]] = []
    ignored_findings: List[Dict[str, Any]] = []

    # Evaluate each reported finding
    for finding in findings:
        if isinstance(finding, dict):
            raw_vt = finding.get("vuln_type") or ""
            raw_ep = finding.get("endpoint") or ""
            title = finding.get("title") or ""
            f_dict = finding
        else:
            raw_vt = getattr(finding, "vuln_type", "") or ""
            raw_ep = getattr(finding, "endpoint", "") or ""
            title = getattr(finding, "title", "") or ""
            f_dict = {
                "id": getattr(finding, "id", ""),
                "vuln_type": raw_vt,
                "endpoint": raw_ep,
                "title": title,
                "param": getattr(finding, "param", None),
            }

        norm_vt = normalize_vuln_type(raw_vt)
        norm_ep = normalize_benchmark_endpoint(raw_ep)

        # Match finding against truth items by (vuln_type, endpoint)
        matched_items: List[GroundTruthItem] = []
        for item in truth_obj.items:
            item_vt = normalize_vuln_type(item.vuln_type)
            if item_vt != norm_vt:
                continue
            item_ep = normalize_benchmark_endpoint(item.endpoint)
            if endpoint_matches(norm_ep, item_ep):
                matched_items.append(item)

        if matched_items:
            # Check classification of matched items
            for m_item in matched_items:
                if m_item.classification == "decoy":
                    matched_decoy_ids.add(m_item.id)
                    false_positive_findings.append({**f_dict, "reason": f"Matched decoy item {m_item.id}"})
                else:
                    matched_real_ids.add(m_item.id)
        else:
            # Finding not in truth file: check informational list
            if _matches_informational(norm_vt, norm_ep, truth_obj.informational):
                ignored_findings.append({**f_dict, "reason": "Matched informational list"})
            else:
                false_positive_findings.append({**f_dict, "reason": "Unmatched finding not in informational list"})

    # True positives: number of detectable real items matched
    tp = sum(1 for it in detectable_real_items if it.id in matched_real_ids)
    # False negatives: detectable real items not matched
    fn = sum(1 for it in detectable_real_items if it.id not in matched_real_ids)
    # False positives: count of false positive findings
    fp = len(false_positive_findings)

    # Precision
    if (tp + fp) > 0:
        precision = tp / (tp + fp)
    else:
        precision = 1.0 if len(detectable_real_items) == 0 else 0.0

    # Recall
    if (tp + fn) > 0:
        recall = tp / (tp + fn)
    else:
        recall = 1.0

    # F1 score
    if (precision + recall) > 0:
        f1 = 2 * (precision * recall) / (precision + recall)
    else:
        f1 = 1.0 if (precision == 1.0 and recall == 1.0) else 0.0

    unmatched_item_ids = [it.id for it in detectable_real_items if it.id not in matched_real_ids]

    return {
        "target": truth_obj.target,
        "true_positives": tp,
        "false_positives": fp,
        "false_negatives": fn,
        "total_real": len(detectable_real_items),
        "total_decoys": len(decoy_items),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "duration_seconds": round(duration_seconds, 2),
        "matched_items": sorted(list(matched_real_ids)),
        "unmatched_items": sorted(unmatched_item_ids),
        "false_positive_findings": false_positive_findings,
        "ignored_findings": ignored_findings,
    }
