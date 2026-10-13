import json
import logging
import urllib.parse
from typing import Dict, Any, List, Optional, Union
import requests

try:
    import yaml
except ImportError:
    yaml = None

logger = logging.getLogger(__name__)


class OpenAPIImporter:
    """Parses OpenAPI 2.0 (Swagger) and 3.0+ specifications into endpoint structures."""

    def __init__(
        self,
        source: Optional[Union[str, Dict[str, Any]]] = None,
        headers: Optional[Dict[str, str]] = None,
        spec_data: Optional[Dict[str, Any]] = None,
    ):
        self.source = source
        self.headers = headers or {}
        if isinstance(source, dict):
            self.spec_data = source
        else:
            self.spec_data: Dict[str, Any] = spec_data or {}

    def load_spec(self) -> bool:
        """Load spec from local file path or remote URL (supports JSON and YAML)."""
        if self.spec_data:
            return True

        if not self.source or not isinstance(self.source, str):
            return False

        content_str = None
        if self.source.startswith(("http://", "https://")):
            try:
                resp = requests.get(self.source, headers=self.headers, timeout=10)
                if resp.status_code == 200:
                    content_str = resp.text
                else:
                    logger.error(f"Failed to fetch OpenAPI spec from {self.source}: HTTP {resp.status_code}")
                    return False
            except Exception as e:
                logger.error(f"Error fetching OpenAPI spec from {self.source}: {e}")
                return False
        else:
            try:
                with open(self.source, "r", encoding="utf-8") as f:
                    content_str = f.read()
            except Exception as e:
                logger.error(f"Error reading OpenAPI spec file {self.source}: {e}")
                return False

        if content_str is None:
            return False

        # 1. Try parsing as JSON
        try:
            parsed = json.loads(content_str)
            if isinstance(parsed, dict):
                self.spec_data = parsed
                return True
        except Exception:
            pass

        # 2. Try parsing as YAML
        if yaml is not None:
            try:
                parsed = yaml.safe_load(content_str)
                if isinstance(parsed, dict):
                    self.spec_data = parsed
                    return True
            except Exception as e:
                logger.error(f"Failed to parse OpenAPI spec as YAML: {e}")
        else:
            logger.warning("PyYAML is not available to parse YAML OpenAPI spec.")

        return False

    def _resolve_ref(self, ref_str: str) -> Any:
        """Resolve a local JSON Pointer ref within the spec, e.g. #/components/schemas/User."""
        if not isinstance(ref_str, str) or not ref_str.startswith("#/"):
            return None
        parts = ref_str[2:].split("/")
        curr = self.spec_data
        for part in parts:
            part = part.replace("~1", "/").replace("~0", "~")
            if isinstance(curr, dict) and part in curr:
                curr = curr[part]
            else:
                return None
        return curr

    def _resolve(self, obj: Any) -> Any:
        """Resolve an object if it contains a local $ref."""
        if isinstance(obj, dict) and "$ref" in obj:
            resolved = self._resolve_ref(obj["$ref"])
            if isinstance(resolved, dict):
                merged = dict(resolved)
                for k, v in obj.items():
                    if k != "$ref":
                        merged[k] = v
                return merged
            return resolved if resolved is not None else obj
        return obj

    def get_endpoints(self) -> List[Dict[str, Any]]:
        """
        Extract plugin-shaped {path, param, method} entries:
        - Query parameters
        - OpenAPI 3 requestBody top-level JSON properties
        - Swagger formData and body parameters
        - Resolves local $ref and honors basePath / servers[0].
        """
        if not self.spec_data:
            return []

        endpoints: List[Dict[str, Any]] = []
        seen = set()

        paths = self.spec_data.get("paths", {})
        if not isinstance(paths, dict):
            return []

        # Determine base path from Swagger basePath or OpenAPI 3 servers[0]
        base_path = ""
        if "basePath" in self.spec_data:
            raw_bp = str(self.spec_data.get("basePath") or "")
            parsed_bp = urllib.parse.urlparse(raw_bp)
            base_path = parsed_bp.path if parsed_bp.netloc else raw_bp
        elif "servers" in self.spec_data:
            servers = self.spec_data.get("servers")
            if isinstance(servers, list) and servers and isinstance(servers[0], dict):
                server_url = servers[0].get("url", "")
                parsed = urllib.parse.urlparse(server_url)
                base_path = parsed.path or ""

        base_path = base_path.rstrip("/")

        for path_str, raw_path_item in paths.items():
            path_item = self._resolve(raw_path_item)
            if not isinstance(path_item, dict):
                continue

            full_path = f"{base_path}{path_str}" if base_path else path_str
            parsed_fp = urllib.parse.urlparse(full_path)
            if parsed_fp.netloc or parsed_fp.scheme:
                full_path = parsed_fp.path or "/"
            if not full_path.startswith("/"):
                full_path = "/" + full_path

            common_params = path_item.get("parameters", [])
            if not isinstance(common_params, list):
                common_params = []

            for method_name in ["get", "post", "put", "delete", "patch", "options", "head"]:
                if method_name not in path_item:
                    continue
                operation = self._resolve(path_item[method_name])
                if not isinstance(operation, dict):
                    continue

                method = method_name.upper()
                param_names: List[str] = []

                # Combine common and operation parameters
                op_params = operation.get("parameters", [])
                if not isinstance(op_params, list):
                    op_params = []
                all_raw_params = common_params + op_params

                for raw_param in all_raw_params:
                    param = self._resolve(raw_param)
                    if not isinstance(param, dict):
                        continue

                    param_in = param.get("in")
                    # Query params
                    if param_in == "query":
                        name = param.get("name")
                        if name and name not in param_names:
                            param_names.append(name)
                    # Swagger 2.0 formData params
                    elif param_in == "formData":
                        name = param.get("name")
                        if name and name not in param_names:
                            param_names.append(name)
                    # Swagger 2.0 body params
                    elif param_in == "body":
                        schema = self._resolve(param.get("schema", {}))
                        if isinstance(schema, dict):
                            props = schema.get("properties", {})
                            if isinstance(props, dict):
                                for prop_name in props.keys():
                                    if prop_name not in param_names:
                                        param_names.append(prop_name)
                        if not param_names and param.get("name"):
                            param_names.append(param.get("name"))

                # OpenAPI 3 requestBody top-level JSON properties
                request_body = self._resolve(operation.get("requestBody", {}))
                if isinstance(request_body, dict):
                    content = request_body.get("content", {})
                    if isinstance(content, dict):
                        for media_type, media_obj in content.items():
                            if isinstance(media_obj, dict) and "schema" in media_obj:
                                schema = self._resolve(media_obj["schema"])
                                if isinstance(schema, dict):
                                    props = schema.get("properties", {})
                                    if isinstance(props, dict):
                                        for prop_name in props.keys():
                                            if prop_name not in param_names:
                                                param_names.append(prop_name)
                                    for key in ("allOf", "anyOf", "oneOf"):
                                        sub_list = schema.get(key, [])
                                        if isinstance(sub_list, list):
                                            for sub in sub_list:
                                                resolved_sub = self._resolve(sub)
                                                if isinstance(resolved_sub, dict):
                                                    sub_props = resolved_sub.get("properties", {})
                                                    if isinstance(sub_props, dict):
                                                        for prop_name in sub_props.keys():
                                                            if prop_name not in param_names:
                                                                param_names.append(prop_name)

                if param_names:
                    for p in param_names:
                        key = (method, full_path, p)
                        if key not in seen:
                            seen.add(key)
                            endpoints.append({
                                "path": full_path,
                                "param": p,
                                "method": method,
                            })
                else:
                    key = (method, full_path, "")
                    if key not in seen:
                        seen.add(key)
                        endpoints.append({
                            "path": full_path,
                            "param": "",
                            "method": method,
                        })

        return endpoints
