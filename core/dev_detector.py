"""
Development Server Fingerprinting for AutoSecAudit.

Detects when a target is running on a local development server (Vite, Webpack, Next.js HMR)
where open CORS and omitted security headers (HSTS, CSP) are intended for local hot-reloading.
Uses only structural signals (script src / script blocks and Server header).
"""

import logging
import re
from typing import Optional, Dict, Any, Union

logger = logging.getLogger(__name__)

SCRIPT_SRC_PATTERN = re.compile(r"""<script[^>]+src=["']([^"']+)["']""", re.IGNORECASE)
INLINE_HMR_PATTERN = re.compile(r"""<script[^>]*>[\s\S]*?__webpack_hmr[\s\S]*?</script>""", re.IGNORECASE)


def detect_dev_environment(root_html: str, headers: Optional[Dict[str, str]] = None) -> Optional[str]:
    """
    Examine the target's root response body and headers for development-server signatures.
    Inspects ONLY structural signals (<script src>, script tags, Server header).
    Unstructured free-text mentions (e.g. 'turbopack' in page body) are ignored.

    Returns the name of the dev environment (e.g. 'Vite Dev Server') or None if production/unknown.
    """
    # 1. Server header checks
    if headers:
        server = headers.get("Server", "").lower()
        if "vite" in server:
            return "Vite Dev Server"
        if "webpack" in server:
            return "Webpack Dev Server"

    if not root_html:
        return None

    # 2. Structural script src checks
    script_srcs = SCRIPT_SRC_PATTERN.findall(root_html)
    for src in script_srcs:
        if "/@vite/client" in src or "/@react-refresh" in src:
            return "Vite Dev Server"
        if "/_next/static/webpack/" in src:
            return "Next.js Dev Server"
        if "__webpack_hmr" in src or "webpack-dev-server" in src:
            return "Webpack Dev Server"

    # 3. Structural inline script block check (e.g. Webpack HMR bootstrap script)
    if INLINE_HMR_PATTERN.search(root_html):
        return "Webpack Dev Server"

    return None


def tag_dev_artifact_finding(finding: Union[Dict[str, Any], Any], dev_env: str) -> Union[Dict[str, Any], Any]:
    """
    Annotate a finding (such as open CORS or missing HSTS) that is an expected development-mode artifact.
    Preserves original_severity before setting severity = 'Info'.
    """
    note = (
        f"\n\n[Dev Environment Notice]: Target is actively running on {dev_env}. "
        "In development environments, open CORS and omitted transport security headers (HSTS, CSP) "
        "are normal development defaults for Hot Module Reloading (HMR). "
        "Run AutoSecAudit against your production build (e.g. 'vite preview' or deployed staging/prod URL) "
        "to verify live security posture."
    )

    if isinstance(finding, dict):
        title = finding.get("title", "")
        if "[Dev Environment Artifact]" not in title:
            finding["title"] = f"{title} [Dev Environment Artifact]"

        if not finding.get("original_severity"):
            finding["original_severity"] = finding.get("severity", "Medium")

        finding["severity"] = "Info"
        finding["confidence"] = "low"
        finding["description"] = finding.get("description", "") + note
        return finding
    else:
        title = getattr(finding, "title", "")
        if "[Dev Environment Artifact]" not in title:
            finding.title = f"{title} [Dev Environment Artifact]"

        if not getattr(finding, "original_severity", None):
            finding.original_severity = getattr(finding, "severity", "Medium") or "Medium"

        finding.severity = "Info"
        finding.confidence = "low"
        finding.description = (getattr(finding, "description", "") or "") + note
        return finding
