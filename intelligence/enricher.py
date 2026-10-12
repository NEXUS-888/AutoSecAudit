import os
import json
import logging
import re
import time
from typing import List, Optional, Dict, Any

import requests
import config
from core.models import Finding

logger = logging.getLogger(__name__)


DEFAULT_CACHE_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "cve_cache.json"
)


class Enricher:
    """Enrich findings with CVE data from external APIs with disk caching and TTL."""

    def __init__(
        self,
        mock_mode: Optional[bool] = None,
        cache_path: Optional[str] = DEFAULT_CACHE_PATH,
        ttl_days: int = 30,
    ):
        self.cve_cache: Dict[str, Dict[str, Any]] = {}
        self.mock_mode = (
            bool(mock_mode) if mock_mode is not None else bool(getattr(config, "MOCK_MODE", False))
        )
        if cache_path and not os.path.isabs(cache_path):
            self.cache_path = os.path.join(
                os.path.dirname(os.path.dirname(os.path.abspath(__file__))), cache_path
            )
        else:
            self.cache_path = cache_path
        self.ttl_seconds = ttl_days * 86400
        if self.cache_path:
            self._load_disk_cache()

    def _load_disk_cache(self) -> None:
        """Load valid, unexpired CVE entries from disk cache."""
        if not self.cache_path or not os.path.exists(self.cache_path):
            return
        try:
            with open(self.cache_path, "r", encoding="utf-8") as f:
                disk_data = json.load(f)
            now = time.time()
            for cve_id, entry in disk_data.items():
                if isinstance(entry, dict) and "data" in entry:
                    ts = entry.get("timestamp", 0)
                    data = entry.get("data")
                    if now - ts <= self.ttl_seconds and data and (data.get("cvss_score") is not None or data.get("references")):
                        self.cve_cache[cve_id] = data
                elif isinstance(entry, dict) and (entry.get("cvss_score") is not None or entry.get("references")):
                    self.cve_cache[cve_id] = entry
        except Exception as e:
            logger.debug(f"[Enricher] Failed to load disk cache from {self.cache_path}: {e}")

    def _save_disk_cache_entry(self, cve_id: str, cve_data: Dict[str, Any]) -> None:
        """Persist a newly fetched CVE entry to disk cache with current timestamp."""
        if not self.cache_path or not cve_data:
            return
        if cve_data.get("cvss_score") is None and not cve_data.get("references"):
            return
        try:
            cache_dir = os.path.dirname(os.path.abspath(self.cache_path))
            if cache_dir:
                os.makedirs(cache_dir, exist_ok=True)
            disk_data = {}
            if os.path.exists(self.cache_path):
                try:
                    with open(self.cache_path, "r", encoding="utf-8") as f:
                        disk_data = json.load(f)
                except Exception:
                    disk_data = {}
            disk_data[cve_id] = {
                "timestamp": time.time(),
                "data": cve_data,
            }
            with open(self.cache_path, "w", encoding="utf-8") as f:
                json.dump(disk_data, f, indent=2)
        except Exception as e:
            logger.debug(f"[Enricher] Failed to save disk cache to {self.cache_path}: {e}")

    def enrich(self, findings: List[Finding]) -> List[Finding]:
        """Enrich findings with CVE data."""
        cve_findings = [f for f in findings if f.cve_id]
        
        for f in cve_findings:
            cve_data = self._fetch_cve_data(f.cve_id)
            if cve_data:
                if f.cvss_score is None:
                    f.cvss_score = cve_data.get("cvss_score")
                # Merge CVE references with existing references (don't overwrite)
                cve_refs = cve_data.get("references", [])
                if f.references:
                    f.references = f.references + [r for r in cve_refs if r not in f.references]
                else:
                    f.references = cve_refs
                logger.info(f"Enriched {f.cve_id} with CVSS {f.cvss_score}")
            else:
                logger.debug(f"No CVE data found for {f.cve_id}, skipping enrichment")

        return findings

    def _fetch_cve_data(self, cve_id: str) -> Optional[Dict[str, Any]]:
        if cve_id in self.cve_cache:
            return self.cve_cache[cve_id]

        # In mock mode, make zero HTTP calls
        if self.mock_mode:
            return None

        try:
            cve_data = self._fetch_from_nvd(cve_id)
            if cve_data:
                self.cve_cache[cve_id] = cve_data
                return cve_data
        except Exception as e:
            logger.warning(f"NVD API fetch failed for {cve_id}: {e}")

        try:
            cve_data = self._fetch_from_circl(cve_id)
            if cve_data:
                self.cve_cache[cve_id] = cve_data
                return cve_data
        except Exception as e:
            logger.warning(f"CIRCL API fetch failed for {cve_id}: {e}")

        return None

    def _fetch_from_nvd(self, cve_id: str) -> Optional[Dict[str, Any]]:
        url = f"{config.NVD_API_URL}?cveId={cve_id}"
        headers = {"Accept": "application/json"}
        api_key = os.environ.get("NVD_API_KEY") or getattr(config, "NVD_API_KEY", None)
        if api_key:
            headers["apiKey"] = api_key
        
        try:
            response = requests.get(url, headers=headers, timeout=2)
            if response.status_code == 200:
                data = response.json()
                parsed = self._parse_nvd_response(data)
                if parsed:
                    self._save_disk_cache_entry(cve_id, parsed)
                return parsed
            logger.debug(f"NVD API returned HTTP {response.status_code} for {cve_id}")
        except requests.RequestException as e:
            logger.debug(f"NVD API network error for {cve_id}: {e}")
        except json.JSONDecodeError as e:
            logger.warning(f"NVD API response for {cve_id} was not valid JSON: {e}")
        except Exception as e:
            logger.warning(f"Unexpected error fetching NVD data for {cve_id}: {e}")
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

            if cvss_score is None and not references:
                return None

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
        
        try:
            response = requests.get(url, timeout=2)
            if response.status_code == 200:
                data = response.json()
                cvss = data.get("cvss") if isinstance(data, dict) else None
                ref_id = data.get("id") if isinstance(data, dict) else None
                if cvss is None and not ref_id:
                    return None
                parsed = {
                    "cvss_score": cvss,
                    "references": [ref_id] if ref_id else []
                }
                self._save_disk_cache_entry(cve_id, parsed)
                return parsed
            logger.debug(f"CIRCL API returned HTTP {response.status_code} for {cve_id}")
        except requests.RequestException as e:
            logger.debug(f"CIRCL API network error for {cve_id}: {e}")
        except json.JSONDecodeError as e:
            logger.warning(f"CIRCL API response for {cve_id} was not valid JSON: {e}")
        except Exception as e:
            logger.warning(f"Unexpected error fetching CIRCL data for {cve_id}: {e}")
        return None
