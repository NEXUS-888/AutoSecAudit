"""
Web Crawler for AutoSecAudit.

Discovers pages, links, forms, and URL parameters on a target before
the scan plugins run. Feeds discovered endpoints to plugins so they
test real attack surface instead of hardcoded guesses.

Works in both real mode (actually crawls) and mock mode (returns
realistic sample endpoints for demo/testing).
"""

import re
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

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class CrawlResult:
    """Aggregated results from a crawl session."""
    target: str
    pages_visited: int = 0
    endpoints: List[DiscoveredEndpoint] = field(default_factory=list)
    forms: List[DiscoveredEndpoint] = field(default_factory=list)
    links: List[str] = field(default_factory=list)

    def get_injectable_endpoints(self) -> List[Dict[str, Any]]:
        """Return endpoints formatted for injection plugins (SQLi, XSS)."""
        results = []
        seen = set()
        for ep in self.endpoints + self.forms:
            if ep.params:
                for param in ep.params:
                    key = f"{ep.method}:{ep.path}:{param}"
                    if key not in seen:
                        seen.add(key)
                        results.append({
                            "path": ep.path,
                            "param": param,
                            "method": ep.method,
                        })
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
        }


# ---------------------------------------------------------------------------
# HTML parser that extracts links, forms, and script references
# ---------------------------------------------------------------------------
class _LinkFormParser(HTMLParser):
    """Extract links, forms, and their inputs from HTML."""

    def __init__(self):
        super().__init__()
        self.links: List[str] = []
        self.forms: List[Dict[str, Any]] = []
        self.scripts: List[str] = []
        self._current_form: Optional[Dict[str, Any]] = None

    def handle_starttag(self, tag: str, attrs: list):
        attr_dict = dict(attrs)

        if tag == "a":
            href = attr_dict.get("href", "")
            if href and not href.startswith(("#", "javascript:", "mailto:", "tel:")):
                self.links.append(href)

        elif tag == "form":
            action = attr_dict.get("action", "")
            method = attr_dict.get("method", "GET").upper()
            self._current_form = {"action": action, "method": method, "inputs": []}

        elif tag == "input" and self._current_form is not None:
            name = attr_dict.get("name", "")
            input_type = attr_dict.get("type", "text").lower()
            if name and input_type not in ("submit", "button", "hidden", "image"):
                self._current_form["inputs"].append(name)

        elif tag == "textarea" and self._current_form is not None:
            name = attr_dict.get("name", "")
            if name:
                self._current_form["inputs"].append(name)

        elif tag == "select" and self._current_form is not None:
            name = attr_dict.get("name", "")
            if name:
                self._current_form["inputs"].append(name)

        elif tag == "script":
            src = attr_dict.get("src", "")
            if src:
                self.scripts.append(src)

    def handle_endtag(self, tag: str):
        if tag == "form" and self._current_form is not None:
            self.forms.append(self._current_form)
            self._current_form = None


# ---------------------------------------------------------------------------
# URL utility helpers
# ---------------------------------------------------------------------------
def _normalize_url(base_url: str, href: str) -> Optional[str]:
    """Resolve a relative href against a base URL. Returns None if off-domain."""
    try:
        resolved = urllib.parse.urljoin(base_url, href)
        parsed_base = urllib.parse.urlparse(base_url)
        parsed_resolved = urllib.parse.urlparse(resolved)

        # Stay on the same host
        if parsed_resolved.hostname != parsed_base.hostname:
            return None

        # Strip fragment
        resolved = urllib.parse.urlunparse(parsed_resolved._replace(fragment=""))
        return resolved
    except Exception:
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
    r"""(?:fetch|axios|\.get|\.post|\.put|\.delete|XMLHttpRequest)\s*\(\s*['"`]([/][^'"`\s]{2,})['"`]""",
    re.IGNORECASE,
)

_HREF_PATTERN = re.compile(
    r"""(?:href|action|src)\s*=\s*['"]([/][^'"]{2,})['"]""",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Crawler
# ---------------------------------------------------------------------------
class WebCrawler:
    """
    Crawl a target website to discover endpoints, forms, and API paths.

    Usage:
        crawler = WebCrawler(max_pages=20, max_depth=3)
        result = crawler.crawl("http://localhost:3000")
    """

    def __init__(
        self,
        max_pages: int = 20,
        max_depth: int = 3,
        mock_mode: Optional[bool] = None,
    ):
        self.max_pages = max_pages
        self.max_depth = max_depth
        self.mock_mode = mock_mode if mock_mode is not None else config.MOCK_MODE
        self._visited: Set[str] = set()
        self._session = requests.Session()
        self._session.headers.update(HEADERS)
        self._session.verify = False

    def crawl(self, target: str) -> CrawlResult:
        """Crawl the target and return discovered endpoints."""
        if self.mock_mode:
            return self._get_mock_result(target)

        if not target.startswith(("http://", "https://")):
            target = f"http://{target}"

        result = CrawlResult(target=target)
        logger.info(f"[Crawler] Starting crawl on {target} (max {self.max_pages} pages, depth {self.max_depth})")

        self._visited.clear()
        self._crawl_page(target, result, depth=0)

        # Deduplicate
        result.links = list(set(result.links))
        logger.info(
            f"[Crawler] Finished — visited {result.pages_visited} pages, "
            f"found {len(result.endpoints)} endpoints, {len(result.forms)} forms"
        )
        return result

    def _crawl_page(self, url: str, result: CrawlResult, depth: int) -> None:
        """Recursively crawl a single page."""
        if depth > self.max_depth:
            return
        if result.pages_visited >= self.max_pages:
            return

        # Normalize and skip if visited
        normalized = url.split("?")[0].split("#")[0].rstrip("/")
        if normalized in self._visited:
            return
        self._visited.add(normalized)

        try:
            resp = self._session.get(url, timeout=CRAWL_TIMEOUT, allow_redirects=True)
        except requests.RequestException as e:
            logger.debug(f"[Crawler] Failed to fetch {url}: {e}")
            return

        result.pages_visited += 1
        content_type = resp.headers.get("content-type", "")

        # Only parse HTML
        if "text/html" not in content_type.lower():
            # Still record as a discovered endpoint
            path = _extract_path(url)
            params = _extract_query_params(url)
            result.endpoints.append(DiscoveredEndpoint(
                path=path, params=params, endpoint_type="resource", source=url
            ))
            return

        # Parse HTML for links and forms
        parser = _LinkFormParser()
        try:
            parser.feed(resp.text)
        except Exception:
            pass

        current_path = _extract_path(url)

        # Process discovered forms
        for form in parser.forms:
            action = form["action"] or current_path
            resolved = _normalize_url(url, action)
            if resolved:
                form_path = _extract_path(resolved)
                result.forms.append(DiscoveredEndpoint(
                    path=form_path,
                    method=form["method"],
                    params=form["inputs"],
                    endpoint_type="form",
                    source=current_path,
                ))

        # Process links
        urls_to_visit = []
        for href in parser.links:
            resolved = _normalize_url(url, href)
            if resolved:
                result.links.append(resolved)
                link_path = _extract_path(resolved)
                params = _extract_query_params(resolved)
                result.endpoints.append(DiscoveredEndpoint(
                    path=link_path,
                    params=params,
                    endpoint_type="link",
                    source=current_path,
                ))
                urls_to_visit.append(resolved)

        # Look for API endpoints in inline/external JS
        for match in _API_PATTERN.findall(resp.text):
            result.endpoints.append(DiscoveredEndpoint(
                path=match,
                endpoint_type="api",
                source=current_path,
            ))

        for match in _HREF_PATTERN.findall(resp.text):
            if match not in [ep.path for ep in result.endpoints]:
                result.endpoints.append(DiscoveredEndpoint(
                    path=match,
                    endpoint_type="link",
                    source=current_path,
                ))

        # Recurse into discovered links
        for next_url in urls_to_visit:
            if result.pages_visited < self.max_pages:
                self._crawl_page(next_url, result, depth + 1)

    # ------------------------------------------------------------------
    # Mock output for demo/testing
    # ------------------------------------------------------------------
    def _get_mock_result(self, target: str) -> CrawlResult:
        """Return realistic mock crawl results for demo mode."""
        result = CrawlResult(target=target, pages_visited=8)

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
