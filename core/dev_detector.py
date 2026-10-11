"""
Development Server Fingerprinting for AutoSecAudit.

Detects when a target is running on a local development server (Vite, Webpack, Next.js HMR)
where open CORS and omitted security headers (HSTS, CSP) are intended for local hot-reloading.
"""

import logging
from typing import Optional, Dict, Any

logger = logging.getLogger(__name__)


def detect_dev_environment(root_html: str, headers: Optional[Dict[str, str]] = None) -> Optional[str]:
    """
    Examine the target's root response body and headers for development-server signatures.

    Returns the name of the dev environment (e.g. 'Vite Dev Server') or None if production/unknown.
    """
    if not root_html:
        root_html = ""

    html_lower = root_html.lower()

    # 1. Vite Dev Server
    if "/@vite/client" in root_html or "/@react-refresh" in root_html or "vite:refresh" in html_lower:
        return "Vite Dev Server"

    # 2. Webpack Dev Server / HMR
    if "webpack-dev-server" in html_lower or "__webpack_hmr" in root_html or "webpackhotupdate" in html_lower:
        return "Webpack Dev Server"

    # 3. Next.js Dev Server (Turbopack / Webpack HMR)
    if "/_next/static/webpack/" in root_html or "__next_dev_client" in html_lower or "turbopack" in html_lower:
        return "Next.js Dev Server"

    # 4. Nuxt Dev Server
    if "__nuxt_devtools__" in html_lower:
        return "Nuxt Dev Server"

    # 5. Header checks
    if headers:
        server = headers.get("Server", "").lower()
        if "vite" in server:
            return "Vite Dev Server"

    return None


def tag_dev_artifact_finding(finding: Dict[str, Any], dev_env: str) -> Dict[str, Any]:
    """
    Annotate a finding (such as open CORS or missing HSTS) that is an expected development-mode artifact.
    """
    title = finding.get("title", "")
    if "[Dev Environment Artifact]" not in title:
        finding["title"] = f"{title} [Dev Environment Artifact]"

    # Mark as Informational to prevent breaking CI/CD gates on local dev runs
    finding["severity"] = "Info"
    finding["confidence"] = "low"

    note = (
        f"\n\n[Dev Environment Notice]: Target is actively running on {dev_env}. "
        "In development environments, open CORS and omitted transport security headers (HSTS, CSP) "
        "are normal development defaults for Hot Module Reloading (HMR). "
        "Run AutoSecAudit against your production build (e.g. 'vite preview' or deployed staging/prod URL) "
        "to verify live security posture."
    )
    finding["description"] = finding.get("description", "") + note
    return finding
