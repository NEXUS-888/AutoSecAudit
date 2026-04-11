import logging
import re
import time
from typing import List, Optional, Dict, Any

import requests
import config
from core.models import Finding

logger = logging.getLogger(__name__)


class Enricher:
    """Enrich findings with CVE data from external APIs."""

    def __init__(self):
        self.cve_cache: Dict[str, Dict[str, Any]] = {}

    def enrich(self, findings: List[Finding]) -> List[Finding]:
        """Enrich findings with CVE data."""
        cve_findings = [f for f in findings if f.cve_id]
        
        for f in cve_findings:
            cve_data = self._fetch_cve_data(f.cve_id)
            if cve_data:
                f.cvss_score = cve_data.get("cvss_score")
                f.references = cve_data.get("references", [])
                logger.info(f"Enriched {f.cve_id} with CVSS {f.cvss_score}")

        return findings

    def _fetch_cve_data(self, cve_id: str) -> Optional[Dict[str, Any]]:
        if cve_id in self.cve_cache:
            return self.cve_cache[cve_id]

        try:
            cve_data = self._fetch_from_nvd(cve_id)
            if cve_data:
                self.cve_cache[cve_id] = cve_data
                return cve_data
        except Exception as e:
            logger.warning(f"NVD API failed for {cve_id}: {e}")

        try:
            cve_data = self._fetch_from_circl(cve_id)
            if cve_data:
                self.cve_cache[cve_id] = cve_data
                return cve_data
        except Exception as e:
            logger.warning(f"CIRCL API failed for {cve_id}: {e}")

        return None

    def _fetch_from_nvd(self, cve_id: str) -> Optional[Dict[str, Any]]:
        url = f"{config.NVD_API_URL}?cveId={cve_id}"
        headers = {"Accept": "application/json"}
        
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            data = response.json()
            return self._parse_nvd_response(data)
        return None

    def _parse_nvd_response(self, data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        try:
            items = data.get("vulnerabilities", [])
            if not items:
                return None
            
            cve_item = items[0].get("cve", {})
            metrics = cve_item.get("metrics", {})
            
            cvss_score = None
            cvss_vector = None
            
            if "cvssMetricV31" in metrics:
                cvss_data = metrics["cvssMetricV31"][0].get("cvssData", {})
                cvss_score = cvss_data.get("baseScore")
                cvss_vector = cvss_data.get("vectorString")
            elif "cvssMetricV30" in metrics:
                cvss_data = metrics["cvssMetricV30"][0].get("cvssData", {})
                cvss_score = cvss_data.get("baseScore")
                cvss_vector = cvss_data.get("vectorString")
            elif "cvssMetricV2" in metrics:
                cvss_data = metrics["cvssMetricV2"][0].get("cvssData", {})
                cvss_score = cvss_data.get("baseScore")
                cvss_vector = cvss_data.get("vectorString")

            references = []
            for ref in cve_item.get("references", []):
                ref_url = ref.get("url")
                if ref_url:
                    references.append(ref_url)

            return {
                "cvss_score": cvss_score,
                "cvss_vector": cvss_vector,
                "references": references
            }
        except Exception as e:
            logger.error(f"Failed to parse NVD response: {e}")
            return None

    def _fetch_from_circl(self, cve_id: str) -> Optional[Dict[str, Any]]:
        url = f"{config.CIRCL_API_URL}/{cve_id}"
        
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            data = response.json()
            return {
                "cvss_score": data.get("cvss"),
                "references": [data.get("id")] if data.get("id") else []
            }
        return None
