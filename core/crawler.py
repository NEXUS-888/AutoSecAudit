"""
Web Crawler for AutoSecAudit.

Discovers pages, links, forms, and URL parameters on a target before
the scan plugins run. Feeds discovered endpoints to plugins so they
test real attack surface instead of hardcoded guesses.

Works in both real mode (actually crawls) and mock mode (returns
realistic sample endpoints for demo/testing).
"""

import re
import time
import logging
import urllib.parse
from typing import Dict, Any, List, Optional, Set
from dataclasses import dataclass, field, asdict

import requests
from html.parser import HTMLParser

import config

logger = logging.getLogger(__name__)

HEADERS = {"User-Agent": "AutoSecAudit/2.0 Crawler"}
CRAWL_TIMEOUT = 8


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------
@dataclass
class DiscoveredEndpoint:
    """A single discovered endpoint on the target."""
    path: str
    method: str = "GET"                        # GET or POST
    params: List[str] = field(default_factory=list)  # query/form param names
    endpoint_type: str = "link"                # link, form, api, resource
    source: str = ""                           # page where it was found
    fields: Dict[str, str] = field(default_factory=dict)  # form field name -> default value
    enctype: str = "application/x-www-form-urlencoded"
    form_page: str = ""                        # full URL where form was found
    form_id: str = ""
    form_name: str = ""
    labels: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class CrawlResult:
    """Aggregated results from a crawl session."""
    target: str
    pages_visited: int = 0
    endpoints: List[DiscoveredEndpoint] = field(default_factory=list)
    forms: List[DiscoveredEndpoint] = field(default_factory=list)
    skipped_forms: List[DiscoveredEndpoint] = field(default_factory=list)
    links: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    fetch_failures: int = 0
    start_ok: bool = False

    def _resolve_form_page(self, ep: DiscoveredEndpoint) -> str:
        if ep.form_page:
            return ep.form_page
        src = ep.source or ep.path or "/"
        if src.startswith(("http://", "https://")):
            return src
        if self.target:
            base = self.target if self.target.startswith(("http://", "https://")) else f"http://{self.target}"
            return urllib.parse.urljoin(base.rstrip("/") + "/", src.lstrip("/"))
        return src

    def get_injectable_endpoints(self) -> List[Dict[str, Any]]:
        """Return endpoints formatted for injection plugins (SQLi, XSS, etc.)."""
        results = []
        seen = set()
        for ep in self.endpoints:
            if ep.params:
                is_form_ep = (ep.endpoint_type == "form") or bool(ep.fields)
                for param in ep.params:
                    key = f"{ep.method}:{ep.path}:{param}"
                    if key not in seen:
                        seen.add(key)
                        if is_form_ep:
                            form_fields = dict(ep.fields) if ep.fields else {p: "" for p in ep.params}
                            for p in ep.params:
                                form_fields.setdefault(p, "")
                            item: Dict[str, Any] = {
                                "path": ep.path,
                                "param": param,
                                "method": ep.method,
                                "fields": form_fields,
                                "enctype": ep.enctype or "application/x-www-form-urlencoded",
                                "form_page": self._resolve_form_page(ep),
                                "source": "form",
                            }
                            if ep.form_id:
                                item["form_id"] = ep.form_id
                            if ep.form_name:
                                item["form_name"] = ep.form_name
                            if ep.labels:
                                item["labels"] = list(ep.labels)
                            results.append(item)
                        else:
                            results.append({
                                "path": ep.path,
                                "param": param,
                                "method": ep.method,
                            })

        for ep in self.forms:
            param_names = list(ep.params) if ep.params else list((ep.fields or {}).keys())
            if param_names:
                form_fields = dict(ep.fields) if ep.fields else {p: "" for p in param_names}
                for p in param_names:
                    form_fields.setdefault(p, "")
                form_page = self._resolve_form_page(ep)
                for param in param_names:
                    key = f"{ep.method}:{ep.path}:{param}"
                    if key not in seen:
                        seen.add(key)
                        item = {
                            "path": ep.path,
                            "param": param,
                            "method": ep.method,
                            "fields": dict(form_fields),
                            "enctype": ep.enctype or "application/x-www-form-urlencoded",
                            "form_page": form_page,
                            "source": "form",
                        }
                        if ep.form_id:
                            item["form_id"] = ep.form_id
                        if ep.form_name:
                            item["form_name"] = ep.form_name
                        if ep.labels:
                            item["labels"] = list(ep.labels)
                        results.append(item)
        return results

    def get_login_endpoints(self) -> List[str]:
        """Return paths that look like login/auth forms."""
        login_keywords = {"login", "signin", "sign-in", "auth", "authenticate", "session"}
        results = []
        for ep in self.forms + self.endpoints:
            path_lower = ep.path.lower()
            if any(kw in path_lower for kw in login_keywords):
                if ep.path not in results:
                    results.append(ep.path)
        return results

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "pages_visited": self.pages_visited,
            "endpoints": [e.to_dict() for e in self.endpoints],
            "forms": [f.to_dict() for f in self.forms],
            "links": self.links,
            "errors": self.errors,
            "fetch_failures": self.fetch_failures,
            "start_ok": self.start_ok,
        }


# ---------------------------------------------------------------------------
# HTML parser that extracts links, forms, and script references
# ---------------------------------------------------------------------------
_ON_NAV_PATTERN = re.compile(
    r"""(?:\b(?:window\.)?location(?:\.href)?\s*=\s*|"""
    r"""\b(?:window\.)?location\.(?:assign|replace)\s*\(\s*|"""
    r"""(?:^|[^.\w])(?:window\.)?open\s*\(\s*)"""
    r"""['"`]([^'"`\r\n\t]+)['"`]""",
    re.IGNORECASE,
)


class _LinkFormParser(HTMLParser):
    """Extract links, forms, and their inputs from HTML."""

    def __init__(self):
        super().__init__()
        self.links: List[str] = []
        self.forms: List[Dict[str, Any]] = []
        self.scripts: List[str] = []
        self._current_form: Optional[Dict[str, Any]] = None
        self._current_select_name: Optional[str] = None
        self._in_option: bool = False
        self._current_option_value: Optional[str] = None
        self._current_option_text: List[str] = []
        self._current_option_selected: bool = False
        self._select_has_value: Set[str] = set()
        self._current_textarea_name: Optional[str] = None
        self._current_textarea_text: List[str] = []
        self._in_label: bool = False
        self._current_label_text: List[str] = []

    def handle_starttag(self, tag: str, attrs: list):
        attr_dict = {k.lower(): (v if v is not None else "") for k, v in attrs}

        # AUD-54: Extract same-origin URLs from data-href, data-url, formaction
        for data_attr in ("data-href", "data-url", "formaction"):
            val = attr_dict.get(data_attr, "").strip()
            if val and not val.lower().startswith(("#", "javascript:", "mailto:", "tel:")):
                self.links.append(val)

        # AUD-54: Extract from <meta http-equiv="refresh" content="...">
        if tag == "meta" and attr_dict.get("http-equiv", "").lower() == "refresh":
            content = attr_dict.get("content", "")
            m = re.search(r"""url\s*=\s*['"]?([^\s'";,]+)""", content, re.IGNORECASE)
            if m:
                u = m.group(1).strip()
                if u and not u.lower().startswith(("#", "javascript:", "mailto:", "tel:")):
                    self.links.append(u)

        # AUD-54: Extract navigation targets from on* inline event handler attributes
        for k, v in attrs:
            if k.lower().startswith("on") and v:
                for match in _ON_NAV_PATTERN.finditer(v):
                    nav_url = match.group(1).strip()
                    if nav_url and not nav_url.lower().startswith(("#", "javascript:", "mailto:", "tel:")):
                        self.links.append(nav_url)

        if tag == "a":
            href = attr_dict.get("href", "")
            if href and not href.startswith(("#", "javascript:", "mailto:", "tel:")):
                self.links.append(href)

        elif tag == "form":
            action = attr_dict.get("action", "")
            method = (attr_dict.get("method") or "GET").upper()
            enctype = (attr_dict.get("enctype") or "application/x-www-form-urlencoded").strip()
            self._select_has_value = set()
            self._current_form = {
                "action": action,
                "method": method,
                "enctype": enctype,
                "inputs": [],
                "fields": {},
                "form_id": attr_dict.get("id", ""),
                "form_name": attr_dict.get("name", ""),
                "labels": [],
            }

        elif tag == "input" and self._current_form is not None:
            name = attr_dict.get("name", "")
            input_type = (attr_dict.get("type") or "text").lower()
            val = attr_dict.get("value", "")
            if name and input_type not in ("submit", "button", "image", "reset"):
                if name not in self._current_form["inputs"]:
                    self._current_form["inputs"].append(name)
                if input_type in ("radio", "checkbox"):
                    if name not in self._current_form["fields"] or "checked" in attr_dict:
                        self._current_form["fields"][name] = val or "on"
                else:
                    self._current_form["fields"][name] = val

        elif tag == "textarea" and self._current_form is not None:
            name = attr_dict.get("name", "")
            if name:
                if name not in self._current_form["inputs"]:
                    self._current_form["inputs"].append(name)
                self._current_form["fields"].setdefault(name, "")
                self._current_textarea_name = name
                self._current_textarea_text = []

        elif tag == "select" and self._current_form is not None:
            name = attr_dict.get("name", "")
            if name:
                if name not in self._current_form["inputs"]:
                    self._current_form["inputs"].append(name)
                self._current_form["fields"].setdefault(name, "")
                self._current_select_name = name

        elif tag == "option" and self._current_form is not None and self._current_select_name is not None:
            self._in_option = True
            raw_keys = {k.lower() for k, _ in attrs}
            self._current_option_value = attr_dict.get("value") if "value" in raw_keys else None
            self._current_option_text = []
            self._current_option_selected = "selected" in raw_keys

        elif tag == "label" and self._current_form is not None:
            self._in_label = True
            self._current_label_text = []

        elif tag == "script":
            src = attr_dict.get("src", "")
            if src:
                self.scripts.append(src)

    def handle_data(self, data: str):
        if self._current_textarea_name is not None:
            self._current_textarea_text.append(data)
        if self._in_option:
            self._current_option_text.append(data)
        if self._in_label:
            self._current_label_text.append(data)

    def handle_endtag(self, tag: str):
        if tag == "textarea" and self._current_form is not None and self._current_textarea_name is not None:
            self._current_form["fields"][self._current_textarea_name] = "".join(self._current_textarea_text)
            self._current_textarea_name = None
            self._current_textarea_text = []
        elif tag == "option" and self._current_form is not None and self._current_select_name is not None and self._in_option:
            opt_val = (
                self._current_option_value
                if self._current_option_value is not None
                else "".join(self._current_option_text).strip()
            )
            sel_name = self._current_select_name
            if sel_name not in self._select_has_value or self._current_option_selected:
                self._current_form["fields"][sel_name] = opt_val
                self._select_has_value.add(sel_name)
            self._in_option = False
            self._current_option_value = None
            self._current_option_text = []
            self._current_option_selected = False
        elif tag == "select":
            self._current_select_name = None
            self._in_option = False
        elif tag == "label" and self._current_form is not None and self._in_label:
            lbl = "".join(self._current_label_text).strip()
            if lbl:
                self._current_form["labels"].append(lbl)
            self._in_label = False
            self._current_label_text = []
        elif tag == "form" and self._current_form is not None:
            self.forms.append(self._current_form)
            self._current_form = None
            self._current_select_name = None
            self._current_textarea_name = None
            self._in_option = False
            self._in_label = False


# ---------------------------------------------------------------------------
# URL utility helpers
# ---------------------------------------------------------------------------
def _normalize_url(base_url: str, href: str) -> Optional[str]:
    """Resolve a relative href against a base URL. Returns None if off-origin."""
    try:
        resolved = urllib.parse.urljoin(base_url, href)
        parsed_base = urllib.parse.urlparse(base_url)
        parsed_resolved = urllib.parse.urlparse(resolved)

        base_port = parsed_base.port or (443 if parsed_base.scheme.lower() == "https" else 80)
        resolved_port = parsed_resolved.port or (443 if parsed_resolved.scheme.lower() == "https" else 80)

        # Stay on the exact same origin (scheme + hostname + port)
        if (
            parsed_resolved.scheme.lower() != parsed_base.scheme.lower()
            or (parsed_resolved.hostname or "").lower() != (parsed_base.hostname or "").lower()
            or resolved_port != base_port
        ):
            return None

        # Strip fragment
        resolved = urllib.parse.urlunparse(parsed_resolved._replace(fragment=""))
        return resolved
    except Exception as e:
        logger.debug(f"[Crawler] URL normalize failed for base={base_url} href={href}: {e}")
        return None


def _extract_path(url: str) -> str:
    """Extract just the path from a full URL."""
    return urllib.parse.urlparse(url).path or "/"


def _extract_query_params(url: str) -> List[str]:
    """Extract query parameter names from a URL."""
    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(parsed.query)
    return list(params.keys())


# ---------------------------------------------------------------------------
# API endpoint patterns detected in JavaScript
# ---------------------------------------------------------------------------
_API_PATTERN = re.compile(
    r"""(?:(fetch|axios|XMLHttpRequest|\.ajax)|\.(get|post|put|delete))\s*\(\s*['"`]([/][^'"`\s\?#]{2,})(?:\?([^'"`\s#]+))?['"`]""",
    re.IGNORECASE,
)

_REST_PATH_PATTERN = re.compile(
    r"""['"`](/(?:api|v[0-9]|rest|graphql|auth|users|products|search|admin|order)[/a-zA-Z0-9_\-\.]+)['"`]""",
    re.IGNORECASE,
)

_HREF_PATTERN = re.compile(
    r"""(?:href|action|src)\s*=\s*['"]([/][^'"]{2,})['"]""",
    re.IGNORECASE,
)


def extract_js_endpoints(text: str, source_path: str = "") -> List[DiscoveredEndpoint]:
    """
    Extract API endpoints and parameter names from raw JavaScript code or HTML scripts.
    Detects implied HTTP methods (.post, .put, .delete, .get, fetch).
    """
    discovered: List[DiscoveredEndpoint] = []
    seen = set()
    seen_paths = set()

    # Match explicit fetch/axios/ajax calls
    for match in _API_PATTERN.finditer(text):
        method_group = match.group(2)
        method = method_group.upper() if method_group else "GET"
        path = match.group(3)
        query = match.group(4) or ""
        params = [p.split("=")[0] for p in query.split("&") if p and "=" in p]
        key = (method, path)
        if key not in seen:
            seen.add(key)
            seen_paths.add(path)
            discovered.append(DiscoveredEndpoint(
                path=path,
                method=method,
                params=params,
                endpoint_type="api",
                source=source_path,
            ))

    # Match implicit REST API path literals (e.g. '/api/users/list')
    for match in _REST_PATH_PATTERN.finditer(text):
        path = match.group(1)
        if path not in seen_paths and not path.endswith((".js", ".css", ".png", ".jpg", ".svg", ".woff", ".ico")):
            seen_paths.add(path)
            discovered.append(DiscoveredEndpoint(
                path=path,
                method="GET",
                endpoint_type="api",
                source=source_path,
            ))

    return discovered


DEFAULT_DENY_PATTERN = r"logout|log-out|signout|sign-out|logoff|delete|remove|destroy"

_HEX_ID_SEGMENT_RE = re.compile(
    r"^(?:[0-9]+|0x[0-9a-f]+|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|[0-9a-f]{6,}|(?=[0-9a-f]*\d)[0-9a-f]{2,})$",
    re.IGNORECASE,
)


def _normalize_path_template(url_or_path: str) -> str:
    """Normalize numeric and hex-id path segments into a template (e.g. /post/1 -> /post/{id})."""
    path = _extract_path(url_or_path)
    parts = path.split("/")
    normalized_parts = []
    for part in parts:
        if not part:
            normalized_parts.append("")
        elif _HEX_ID_SEGMENT_RE.match(part):
            normalized_parts.append("{id}")
        else:
            normalized_parts.append(part)
    result = "/".join(normalized_parts)
    return result if result.startswith("/") else "/" + result


# ---------------------------------------------------------------------------
# Crawler
# ---------------------------------------------------------------------------
class WebCrawler:
    """
    Crawl a target website to discover endpoints, forms, and API paths.

    Usage:
        crawler = WebCrawler(max_pages=100, max_depth=4)
        result = crawler.crawl("http://localhost:3000")
    """

    def __init__(
        self,
        max_pages: Optional[int] = None,
        max_depth: Optional[int] = None,
        max_seconds: Optional[int] = None,
        mock_mode: Optional[bool] = None,
        auth_headers: Optional[Dict[str, str]] = None,
        auth_cookies: Optional[Dict[str, str]] = None,
        deny_pattern: Optional[Any] = None,
        max_pages_per_template: int = 5,
    ):
        self.max_pages = max_pages if max_pages is not None else getattr(config, "CRAWL_MAX_PAGES", 100)
        self.max_depth = max_depth if max_depth is not None else getattr(config, "CRAWL_MAX_DEPTH", 4)
        self.max_seconds = max_seconds if max_seconds is not None else getattr(config, "CRAWL_MAX_SECONDS", 60)
        self.max_pages_per_template = max_pages_per_template
        self.mock_mode = mock_mode if mock_mode is not None else config.MOCK_MODE
        self.auth_headers = auth_headers or {}
        self.auth_cookies = auth_cookies or {}
        if deny_pattern is None:
            self.deny_regex = re.compile(DEFAULT_DENY_PATTERN, re.IGNORECASE)
        elif isinstance(deny_pattern, str):
            self.deny_regex = re.compile(deny_pattern, re.IGNORECASE) if deny_pattern else None
        else:
            self.deny_regex = deny_pattern
        self._visited: Set[str] = set()
        self._session = requests.Session()
        self._session.headers.update(HEADERS)
        if self.auth_headers:
            self._session.headers.update(self.auth_headers)
        if self.auth_cookies:
            self._session.cookies.update(self.auth_cookies)
        self._session.verify = False

    def _is_denied(self, url_or_path: str) -> bool:
        """Check if URL path or query matches the deny pattern (ignoring hostname)."""
        if not self.deny_regex or not url_or_path:
            return False
        try:
            parsed = urllib.parse.urlparse(url_or_path)
            target_str = parsed.path
            if parsed.query:
                target_str += "?" + parsed.query
            if not target_str and not parsed.netloc:
                target_str = url_or_path
            return bool(self.deny_regex.search(target_str))
        except Exception:
            return bool(self.deny_regex.search(url_or_path))

    def crawl(self, target: str) -> CrawlResult:
        """Crawl the target and return discovered endpoints using BFS."""
        if self.mock_mode:
            return self._get_mock_result(target)

        if not target.startswith(("http://", "https://")):
            target = f"http://{target}"

        result = CrawlResult(target=target, start_ok=False)
        logger.info(
            f"[Crawler] Starting crawl on {target} (max {self.max_pages} pages, depth {self.max_depth}, time {self.max_seconds}s)"
        )

        self._visited.clear()
        self._visited_scripts: Set[str] = set()
        template_counts: Dict[str, int] = {}
        start_time = time.monotonic()

        # AUD-56: Retry start URL up to 3 times with 1s then 2s backoff
        start_resp = None
        max_start_retries = 3
        backoff_delays = [1.0, 2.0]

        for attempt in range(max_start_retries):
            if (time.monotonic() - start_time) >= self.max_seconds:
                result.errors.append("Crawl time cap exceeded before start URL completed")
                return result
            try:
                resp = self._session.get(target, timeout=CRAWL_TIMEOUT, allow_redirects=True)
                if resp.status_code >= 500:
                    err_msg = f"HTTP {resp.status_code} on start URL {target}"
                    logger.debug(f"[Crawler] Start URL attempt {attempt + 1} failed: {err_msg}")
                    result.fetch_failures += 1
                    if attempt < max_start_retries - 1:
                        time.sleep(backoff_delays[attempt])
                        continue
                    else:
                        result.errors.append(err_msg)
                        result.start_ok = False
                        return result
                start_resp = resp
                result.start_ok = True
                break
            except Exception as e:
                err_msg = f"Failed to fetch start URL {target}: {e}"
                logger.debug(f"[Crawler] Start URL attempt {attempt + 1} failed: {err_msg}")
                result.fetch_failures += 1
                if attempt < max_start_retries - 1:
                    time.sleep(backoff_delays[attempt])
                else:
                    result.errors.append(err_msg)
                    result.start_ok = False
                    return result

        if not start_resp or not result.start_ok:
            return result

        # Check if redirect left the target origin (scheme + host + port)
        target_parsed = urllib.parse.urlparse(result.target)
        resp_parsed = urllib.parse.urlparse(start_resp.url)
        target_port = target_parsed.port or (443 if target_parsed.scheme.lower() == "https" else 80)
        resp_port = resp_parsed.port or (443 if resp_parsed.scheme.lower() == "https" else 80)
        target_origin = (target_parsed.scheme.lower(), (target_parsed.hostname or "").lower(), target_port)
        resp_origin = (resp_parsed.scheme.lower(), (resp_parsed.hostname or "").lower(), resp_port)
        if target_origin != resp_origin:
            logger.debug(f"[Crawler] Discarding response from off-origin redirect: {start_resp.url}")
            result.errors.append(f"Start URL redirected off-origin: {start_resp.url}")
            result.start_ok = False
            return result

        # Check if final URL or redirect chain hit a denied URL
        if self._is_denied(start_resp.url) or any(self._is_denied(r.url) for r in getattr(start_resp, "history", [])):
            logger.debug(f"[Crawler] Discarding response from denied redirect: {start_resp.url}")
            result.errors.append(f"Start URL redirected to denied URL: {start_resp.url}")
            result.start_ok = False
            return result

        from collections import deque
        queue = deque([(target, 0)])

        while queue and result.pages_visited < self.max_pages:
            if (time.monotonic() - start_time) >= self.max_seconds:
                logger.info(f"[Crawler] Crawl time cap ({self.max_seconds}s) reached; stopping BFS.")
                break

            url, depth = queue.popleft()
            if depth > self.max_depth:
                continue
            if self._is_denied(url):
                logger.debug(f"[Crawler] Skipping denied URL: {url}")
                continue

            normalized = url.split("?")[0].split("#")[0].rstrip("/")
            if normalized in self._visited and depth > 0:
                continue

            tmpl = _normalize_path_template(url)
            if depth > 0 and template_counts.get(tmpl, 0) >= self.max_pages_per_template:
                logger.debug(f"[Crawler] Skipping URL exceeding template cap ({tmpl}): {url}")
                continue

            if depth == 0:
                resp = start_resp
                self._visited.add(normalized)
                effective_norm = resp.url.split("?")[0].split("#")[0].rstrip("/")
                self._visited.add(effective_norm)
                tmpl = _normalize_path_template(resp.url)
                template_counts[tmpl] = template_counts.get(tmpl, 0) + 1
            else:
                self._visited.add(normalized)
                template_counts[tmpl] = template_counts.get(tmpl, 0) + 1
                try:
                    resp = self._session.get(url, timeout=CRAWL_TIMEOUT, allow_redirects=True)
                except Exception as e:
                    logger.debug(f"[Crawler] Failed to fetch {url}: {e}")
                    result.fetch_failures += 1
                    result.errors.append(f"Failed to fetch {url}: {e}")
                    continue

                # Check if redirect left the target origin (scheme + host + port)
                resp_parsed = urllib.parse.urlparse(resp.url)
                resp_port = resp_parsed.port or (443 if resp_parsed.scheme.lower() == "https" else 80)
                resp_origin = (resp_parsed.scheme.lower(), (resp_parsed.hostname or "").lower(), resp_port)
                if target_origin != resp_origin:
                    logger.debug(f"[Crawler] Discarding response from off-origin redirect: {resp.url}")
                    continue

                # Check if final URL or redirect chain hit a denied URL
                if self._is_denied(resp.url) or any(self._is_denied(r.url) for r in getattr(resp, "history", [])):
                    logger.debug(f"[Crawler] Discarding response from denied redirect: {resp.url}")
                    continue

            result.pages_visited += 1
            content_type = resp.headers.get("content-type", "")

            # Only parse HTML
            if "text/html" not in content_type.lower():
                path = _extract_path(resp.url or url)
                params = _extract_query_params(resp.url or url)
                result.endpoints.append(DiscoveredEndpoint(
                    path=path, params=params, endpoint_type="resource", source=url
                ))
                continue

            # Parse HTML for links, forms, and scripts
            parser = _LinkFormParser()
            try:
                parser.feed(resp.text)
            except Exception as e:
                logger.warning(f"[Crawler] HTML parse error on {url}: {e}")

            current_path = _extract_path(resp.url or url)

            # Process discovered forms (exclude off-origin and denied actions; record denied in skipped_forms)
            page_url = getattr(resp, "url", None) if isinstance(getattr(resp, "url", None), str) else url
            if not page_url or not page_url.startswith(("http://", "https://")):
                page_url = url
            for form in parser.forms:
                action = form["action"] or current_path
                resolved = _normalize_url(resp.url or url, action)
                if not resolved:
                    continue
                form_path = _extract_path(resolved)
                ep = DiscoveredEndpoint(
                    path=form_path,
                    method=form["method"],
                    params=list(form["inputs"]),
                    endpoint_type="form",
                    source=current_path,
                    fields=dict(form.get("fields") or {}),
                    enctype=form.get("enctype") or "application/x-www-form-urlencoded",
                    form_page=page_url,
                    form_id=form.get("form_id", ""),
                    form_name=form.get("form_name", ""),
                    labels=list(form.get("labels") or []),
                )
                if self._is_denied(action) or self._is_denied(resolved) or self._is_denied(form_path):
                    result.skipped_forms.append(ep)
                    continue
                result.forms.append(ep)

            # Process links and enqueue for BFS
            for href in parser.links:
                if self._is_denied(href):
                    continue
                resolved = _normalize_url(resp.url or url, href)
                if resolved:
                    if self._is_denied(resolved):
                        continue
                    link_path = _extract_path(resolved)
                    if self._is_denied(link_path):
                        continue
                    result.links.append(resolved)
                    params = _extract_query_params(resolved)
                    result.endpoints.append(DiscoveredEndpoint(
                        path=link_path,
                        method="GET",
                        params=params,
                        endpoint_type="link",
                        source=current_path,
                    ))
                    norm_link = resolved.split("?")[0].split("#")[0].rstrip("/")
                    link_tmpl = _normalize_path_template(resolved)
                    if (
                        norm_link not in self._visited
                        and depth + 1 <= self.max_depth
                        and template_counts.get(link_tmpl, 0) < self.max_pages_per_template
                    ):
                        queue.append((resolved, depth + 1))

            # Fetch same-origin <script src> files (size cap 2 MB, max 10 files)
            for script_src in parser.scripts:
                if len(self._visited_scripts) >= 10:
                    break
                if self._is_denied(script_src):
                    continue
                resolved_script = _normalize_url(resp.url or url, script_src)
                if not resolved_script:
                    continue
                if self._is_denied(resolved_script):
                    continue
                norm_script = resolved_script.split("?")[0].split("#")[0].rstrip("/")
                if norm_script in self._visited_scripts:
                    continue
                self._visited_scripts.add(norm_script)

                script_path = _extract_path(resolved_script)
                s_resp = None
                try:
                    s_resp = self._session.get(
                        resolved_script,
                        timeout=CRAWL_TIMEOUT,
                        allow_redirects=True,
                        stream=True,
                    )

                    # Check if redirect left target origin (scheme + host + port)
                    if _normalize_url(result.target, s_resp.url) is None:
                        logger.debug(f"[Crawler] Discarding script from off-origin redirect: {s_resp.url}")
                        continue

                    # Check Content-Length header if present
                    max_size = 2 * 1024 * 1024
                    cl_str = s_resp.headers.get("Content-Length")
                    if cl_str and str(cl_str).isdigit() and int(cl_str) > max_size:
                        logger.debug(f"[Crawler] Skipping oversized script (Content-Length {cl_str} bytes): {resolved_script}")
                        continue

                    chunks = []
                    total_read = 0
                    oversized = False
                    if hasattr(s_resp, "iter_content") and callable(s_resp.iter_content):
                        for chunk in s_resp.iter_content(chunk_size=65536):
                            if chunk:
                                total_read += len(chunk)
                                if total_read > max_size:
                                    oversized = True
                                    break
                                chunks.append(chunk)

                    # Fallback for mocks providing .content without iter_content chunks
                    if not chunks and not oversized and getattr(s_resp, "content", None):
                        if len(s_resp.content) > max_size:
                            oversized = True
                        else:
                            chunks = [s_resp.content]

                    if oversized:
                        logger.debug(f"[Crawler] Skipping oversized script (> {max_size} bytes): {resolved_script}")
                        continue

                    encoding = getattr(s_resp, "encoding", None) or "utf-8"
                    try:
                        s_text = b"".join(chunks).decode(encoding, errors="replace")
                    except Exception:
                        s_text = b"".join(chunks).decode("utf-8", errors="replace")

                    js_eps = extract_js_endpoints(s_text, script_path)
                    existing_keys = {(ep.method, ep.path) for ep in result.endpoints}
                    for j_ep in js_eps:
                        if self._is_denied(j_ep.path):
                            continue
                        if (j_ep.method, j_ep.path) not in existing_keys:
                            existing_keys.add((j_ep.method, j_ep.path))
                            result.endpoints.append(j_ep)
                except Exception as ex:
                    logger.debug(f"[Crawler] Failed to fetch script {resolved_script}: {ex}")
                finally:
                    if s_resp is not None and hasattr(s_resp, "close") and callable(s_resp.close):
                        s_resp.close()

            # Look for API endpoints and parameters in inline JS
            try:
                js_endpoints = extract_js_endpoints(resp.text, current_path)
                existing_keys = {(ep.method, ep.path) for ep in result.endpoints}
                for j_ep in js_endpoints:
                    if self._is_denied(j_ep.path):
                        continue
                    if (j_ep.method, j_ep.path) not in existing_keys:
                        existing_keys.add((j_ep.method, j_ep.path))
                        result.endpoints.append(j_ep)

                for match in _HREF_PATTERN.findall(resp.text):
                    if self._is_denied(match):
                        continue
                    if ("GET", match) not in existing_keys:
                        existing_keys.add(("GET", match))
                        result.endpoints.append(DiscoveredEndpoint(
                            path=match,
                            method="GET",
                            endpoint_type="link",
                            source=current_path,
                        ))
            except Exception as e:
                logger.debug(f"[Crawler] Error extracting inline endpoints on {url}: {e}")

        # Deduplicate links
        result.links = list(set(result.links))
        logger.info(
            f"[Crawler] Finished — visited {result.pages_visited} pages, "
            f"found {len(result.endpoints)} endpoints, {len(result.forms)} forms"
        )
        self._session.close()
        return result

    # ------------------------------------------------------------------
    # Mock output for demo/testing
    # ------------------------------------------------------------------
    def _get_mock_result(self, target: str) -> CrawlResult:
        """Return realistic mock crawl results for demo mode."""
        result = CrawlResult(target=target, pages_visited=8, start_ok=True)

        # Simulate discovered pages and endpoints
        result.endpoints = [
            DiscoveredEndpoint(path="/", endpoint_type="link", source="/"),
            DiscoveredEndpoint(path="/search", params=["q"], endpoint_type="link", source="/"),
            DiscoveredEndpoint(path="/products", params=["search", "category"], endpoint_type="link", source="/"),
            DiscoveredEndpoint(path="/api/Products", params=["q"], endpoint_type="api", source="/"),
            DiscoveredEndpoint(path="/rest/products/search", params=["q"], endpoint_type="api", source="/"),
            DiscoveredEndpoint(path="/api/users", params=["id"], endpoint_type="api", source="/"),
            DiscoveredEndpoint(path="/profile", params=["id"], endpoint_type="link", source="/"),
            DiscoveredEndpoint(path="/api/Feedbacks", endpoint_type="api", source="/"),
            DiscoveredEndpoint(path="/api/Challenges", endpoint_type="api", source="/"),
            DiscoveredEndpoint(path="/about", endpoint_type="link", source="/"),
            DiscoveredEndpoint(path="/contact", endpoint_type="link", source="/"),
            DiscoveredEndpoint(path="/ftp", endpoint_type="link", source="/"),
        ]

        result.forms = [
            DiscoveredEndpoint(path="/login", method="POST", params=["email", "password"],
                               endpoint_type="form", source="/login"),
            DiscoveredEndpoint(path="/rest/user/login", method="POST", params=["email", "password"],
                               endpoint_type="form", source="/login"),
            DiscoveredEndpoint(path="/api/Users", method="POST", params=["email", "password", "passwordRepeat"],
                               endpoint_type="form", source="/register"),
            DiscoveredEndpoint(path="/contact", method="POST", params=["name", "email", "message"],
                               endpoint_type="form", source="/contact"),
        ]

        result.links = [
            f"{target}/", f"{target}/search", f"{target}/products",
            f"{target}/login", f"{target}/about", f"{target}/contact",
            f"{target}/profile", f"{target}/ftp",
        ]

        logger.info(
            f"[Crawler] Mock crawl — {result.pages_visited} pages, "
            f"{len(result.endpoints)} endpoints, {len(result.forms)} forms"
        )
        return result
