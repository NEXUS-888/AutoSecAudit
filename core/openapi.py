import json
import logging
import requests
from typing import Dict, Any, List

logger = logging.getLogger(__name__)


class OpenAPIImporter:
    """Parses OpenAPI 2.0 (Swagger) and 3.0+ specifications into endpoint structures."""

    def __init__(self, source: str, headers: Dict[str, str] = None):
        self.source = source
        self.headers = headers or {}
        self.spec_data: Dict[str, Any] = {}

    def load_spec(self) -> bool:
        """Load spec from local file path or remote URL."""
        if self.source.startswith(("http://", "https://")):
            try:
                resp = requests.get(self.source, headers=self.headers, timeout=10)
                if resp.status_code == 200:
                    self.spec_data = resp.json()
                    return True
                logger.error(f"Failed to fetch OpenAPI spec from {self.source}: HTTP {resp.status_code}")
                return False
            except Exception as e:
                logger.error(f"Error fetching OpenAPI spec from {self.source}: {e}")
                return False
        else:
            try:
                with open(self.source, "r", encoding="utf-8") as f:
                    self.spec_data = json.load(f)
                return True
            except Exception as e:
                logger.error(f"Error reading OpenAPI spec file {self.source}: {e}")
                return False

    def get_endpoints(self) -> List[Dict[str, Any]]:
        """Extract endpoints, HTTP methods, and query/body parameters."""
        if not self.spec_data:
            return []

        endpoints = []
        paths = self.spec_data.get("paths", {})
        base_path = self.spec_data.get("basePath", "")

        for path_str, path_item in paths.items():
            if not isinstance(path_item, dict):
                continue

            full_path = f"{base_path.rstrip('/')}{path_str}"

            for method in ["get", "post", "put", "delete", "patch"]:
                if method not in path_item:
                    continue

                operation = path_item[method]
                params = []

                # Extract parameters
                all_params = path_item.get("parameters", []) + operation.get("parameters", [])
                for param in all_params:
                    if isinstance(param, dict) and "name" in param:
                        params.append({
                            "name": param.get("name"),
                            "in": param.get("in", "query"),
                            "required": param.get("required", False),
                            "type": param.get("type", "string")
                        })

                endpoints.append({
                    "path": full_path,
                    "method": method.upper(),
                    "params": params,
                    "summary": operation.get("summary", ""),
                    "source": "openapi"
                })

        return endpoints
