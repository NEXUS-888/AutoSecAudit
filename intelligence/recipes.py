"""
Multi-Framework Code & WAF Fix Recipes for AutoSecAudit.

Generates framework-specific code drop-in patches (Node.js/Express, Python/Flask/Django/FastAPI),
Nginx server hardening blocks, Cloudflare/AWS WAF rule JSON, and 1-click Markdown tickets for Jira/GitHub.
"""

import json
import logging
from typing import Dict, Any

from intelligence.danger_engine import analyze_real_danger

logger = logging.getLogger(__name__)


def get_fix_recipes(finding: Dict[str, Any]) -> Dict[str, str]:
    """
    Generate framework-specific code snippets and WAF defense rules for a finding.
    Returns a dictionary with keys: 'nodejs', 'python', 'nginx', 'waf'.
    """
    title = (finding.get("title") or "").lower()
    tool = (finding.get("tool_name") or finding.get("tool") or "").lower()
    param = finding.get("parameter") or "input"
    url = finding.get("url") or finding.get("endpoint") or "/api/endpoint"

    # Default generic recipes
    nodejs_code = (
        "// 1. Sanitize input & validate types\n"
        "const { body, validationResult } = require('express-validator');\n\n"
        "app.post('/api/endpoint', [\n"
        "  body('data').trim().escape()\n"
        "], (req, res) => {\n"
        "  const errors = validationResult(req);\n"
        "  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });\n"
        "  // Process clean data safely\n"
        "});"
    )

    python_code = (
        "# 1. Validate inputs and enforce strict types (Pydantic / Flask)\n"
        "from pydantic import BaseModel, constr\n\n"
        "class RequestSchema(BaseModel):\n"
        "    data: constr(strip_whitespace=True, max_length=255)\n\n"
        "@app.post('/api/endpoint')\n"
        "def handler(payload: RequestSchema):\n"
        "    # Payload is automatically validated and sanitized\n"
        "    return {'status': 'ok'}"
    )

    nginx_code = (
        "# Nginx Security Hardening Block\n"
        "server {\n"
        "    # Block common malicious probes\n"
        "    location ~* (\\.git|\\.env|\\.bak|\\.sql) {\n"
        "        deny all;\n"
        "        return 404;\n"
        "    }\n"
        "}"
    )

    waf_rule = {
        "rule_name": f"AutoSec_Block_{finding.get('id', 'VULN')}",
        "action": "BLOCK",
        "description": f"Automated virtual patch for {finding.get('title', 'Security Finding')}",
        "expression": f'http.request.uri.path contains "{url}" and (http.request.uri.query contains "\'" or http.request.uri.query contains "--")',
    }

    # 1. SQL Injection Recipes
    if "sql injection" in title or "sqli" in title:
        nodejs_code = (
            "// Node.js (pg / mysql2): Use Parameterized Queries ($1 / ?)\n"
            "// NEVER concatenate strings into SQL queries!\n\n"
            "// Postgres:\n"
            f"const query = 'SELECT * FROM users WHERE {param} = $1;';\n"
            f"const {{ rows }} = await db.query(query, [req.body.{param}]);\n\n"
            "// MySQL / Prisma:\n"
            f"const [rows] = await db.execute('SELECT * FROM users WHERE {param} = ?', [req.body.{param}]);"
        )
        python_code = (
            "# Python (SQLAlchemy / psycopg2 / Django ORM)\n"
            "# NEVER use f-strings or % formatting in SQL!\n\n"
            "# SQLAlchemy Core:\n"
            "stmt = select(User).where(User.username == bindparam('user_param'))\n"
            "result = session.execute(stmt, {'user_param': user_input})\n\n"
            "# Django ORM (Safe by default):\n"
            f"user = User.objects.filter({param}=user_input).first()"
        )
        nginx_code = (
            "# Nginx: Drop SQL Injection signatures at reverse proxy\n"
            "if ($query_string ~* \"(union.*select|select.*from|insert.*into|delete.*from|benchmark|sleep\\()\") {\n"
            "    return 403;\n"
            "}"
        )
        waf_rule = {
            "rule_name": "AutoSec_Block_SQLi",
            "action": "BLOCK",
            "description": "Block SQL injection payloads targeting database parameters",
            "expression": '(http.request.uri.query contains "UNION" or http.request.uri.query contains "SELECT" or http.request.uri.query contains "\' OR \'")',
        }

    # 2. CORS Wildcard Recipes
    elif "cors" in title:
        nodejs_code = (
            "// Node.js Express: Strict CORS Whitelist Configuration\n"
            "const cors = require('cors');\n\n"
            "const whitelist = ['https://yourdomain.com', 'https://app.yourdomain.com'];\n"
            "const corsOptions = {\n"
            "  origin: (origin, callback) => {\n"
            "    if (!origin || whitelist.indexOf(origin) !== -1) {\n"
            "      callback(null, true);\n"
            "    } else {\n"
            "      callback(new Error('Blocked by CORS policy'));\n"
            "    }\n"
            "  },\n"
            "  credentials: true,\n"
            "  methods: ['GET', 'POST', 'PUT', 'DELETE'],\n"
            "  allowedHeaders: ['Content-Type', 'Authorization']\n"
            "};\n"
            "app.use(cors(corsOptions));"
        )
        python_code = (
            "# Python FastAPI / Flask CORS Whitelist\n\n"
            "# FastAPI:\n"
            "from fastapi.middleware.cors import CORSMiddleware\n\n"
            "app.add_middleware(\n"
            "    CORSMiddleware,\n"
            "    allow_origins=['https://yourdomain.com'],\n"
            "    allow_credentials=True,\n"
            "    allow_methods=['GET', 'POST', 'PUT', 'DELETE'],\n"
            "    allow_headers=['Content-Type', 'Authorization'],\n"
            ")\n\n"
            "# Flask-CORS:\n"
            "from flask_cors import CORS\n"
            "CORS(app, origins=['https://yourdomain.com'], supports_credentials=True)"
        )
        nginx_code = (
            "# Nginx: Enforce Explicit Origin instead of wildcard *\n"
            "set $cors_origin \"\";\n"
            "if ($http_origin ~* \"^https?://(yourdomain\\.com|app\\.yourdomain\\.com)$\") {\n"
            "    set $cors_origin $http_origin;\n"
            "}\n"
            "add_header 'Access-Control-Allow-Origin' $cors_origin always;\n"
            "add_header 'Access-Control-Allow-Credentials' 'true' always;"
        )
        waf_rule = {
            "rule_name": "AutoSec_Enforce_CORS",
            "action": "BLOCK",
            "description": "Block cross-origin requests with unapproved origin headers",
            "expression": '(http.request.method == "OPTIONS" and not http.request.headers["origin"][0] in {"https://yourdomain.com"})',
        }

    # 3. Missing Security Headers / CSP / Clickjacking
    elif "header" in title or "csp" in title or "frame" in title or "clickjacking" in title or "hsts" in title:
        nodejs_code = (
            "// Node.js Express: 1-Line Helmet Middleware Injection\n"
            "// Install: npm install helmet\n"
            "const helmet = require('helmet');\n\n"
            "app.use(helmet({\n"
            "  contentSecurityPolicy: {\n"
            "    directives: {\n"
            "      defaultSrc: [\"'self'\"],\n"
            "      scriptSrc: [\"'self'\", \"https://trusted.cdn.com\"],\n"
            "      frameAncestors: [\"'none'\"], // Prevents Clickjacking\n"
            "    }\n"
            "  },\n"
            "  hsts: { maxAge: 31536000, includeSubDomains: true, preload: true },\n"
            "  xFrameOptions: { action: 'deny' },\n"
            "  noSniff: true\n"
            "}));"
        )
        python_code = (
            "# Python Flask / FastAPI Security Headers\n\n"
            "# Flask (Flask-Talisman):\n"
            "# Install: pip install flask-talisman\n"
            "from flask_talisman import Talisman\n\n"
            "csp = {\n"
            "    'default-src': \"'self'\",\n"
            "    'frame-ancestors': \"'none'\"\n"
            "}\n"
            "Talisman(app, content_security_policy=csp, force_https=True)\n\n"
            "# FastAPI Middleware:\n"
            "@app.middleware('http')\n"
            "async def add_security_headers(request, call_next):\n"
            "    response = await call_next(request)\n"
            "    response.headers['X-Frame-Options'] = 'DENY'\n"
            "    response.headers['X-Content-Type-Options'] = 'nosniff'\n"
            "    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'\n"
            "    return response"
        )
        nginx_code = (
            "# Nginx: Drop-in Security Headers configuration\n"
            "add_header X-Frame-Options \"DENY\" always;\n"
            "add_header X-Content-Type-Options \"nosniff\" always;\n"
            "add_header Referrer-Policy \"strict-origin-when-cross-origin\" always;\n"
            "add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\" always;\n"
            "add_header Content-Security-Policy \"default-src 'self'; frame-ancestors 'none';\" always;"
        )
        waf_rule = {
            "rule_name": "AutoSec_Inject_Security_Headers",
            "action": "TRANSFORM_RESPONSE",
            "description": "Cloudflare / CDN Response Header Injection",
            "headers": {
                "X-Frame-Options": "DENY",
                "X-Content-Type-Options": "nosniff",
                "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            },
        }

    # 4. Sensitive Path / Directory Listing Exposure
    elif "directory listing" in title or "dirbrute" in title or ".git" in title or ".env" in title:
        nodejs_code = (
            "// Node.js Express: Disable dotfiles and directory listing\n"
            "const express = require('express');\n\n"
            "app.use(express.static('public', {\n"
            "  dotfiles: 'ignore', // Blocks .git, .env, etc.\n"
            "  index: false,\n"
            "  fallthrough: false\n"
            "}));"
        )
        python_code = (
            "# Python: Prevent serving private files\n"
            "import os\n"
            "from flask import abort\n\n"
            "@app.route('/<path:filename>')\n"
            "def safe_file_serve(filename):\n"
            "    if filename.startswith('.') or '..' in filename or filename.endswith(('.env', '.git', '.sql', '.bak')):\n"
            "        abort(404)\n"
            "    return send_from_directory('static', filename)"
        )
        nginx_code = (
            "# Nginx: Disable directory autoindex and block hidden/config files\n"
            "autoindex off;\n\n"
            "location ~ /\\.(?!well-known) {\n"
            "    deny all;\n"
            "    return 404;\n"
            "}\n\n"
            "location ~* \\.(bak|config|sql|fla|psd|ini|log|sh|env|git)$ {\n"
            "    deny all;\n"
            "    return 404;\n"
            "}"
        )
        waf_rule = {
            "rule_name": "AutoSec_Block_Hidden_Paths",
            "action": "BLOCK",
            "description": "Block requests attempting to access .git, .env, and backup archives",
            "expression": '(http.request.uri.path contains "/.git" or http.request.uri.path contains "/.env" or http.request.uri.path contains ".sql" or http.request.uri.path contains ".bak")',
        }

    return {
        "nodejs": nodejs_code,
        "python": python_code,
        "nginx": nginx_code,
        "waf": json.dumps(waf_rule, indent=2),
    }


def generate_dev_ticket_markdown(finding: Dict[str, Any], target_url: str = "") -> str:
    """Generate a clean, copy-paste Markdown issue ticket for Jira / GitHub / Linear / Slack."""
    title = finding.get("title", "Security Vulnerability")
    severity = (finding.get("severity") or "High").upper()
    danger = analyze_real_danger(finding)
    recipes = get_fix_recipes(finding)
    url = finding.get("url") or target_url or "Target Web App"
    param = finding.get("parameter") or "N/A"

    ticket = f"""### 🛡️ [SECURITY] {title} ({severity})

**Affected Target:** `{url}`  
**Parameter / Component:** `{param}`  
**Severity:** `{severity}`  
**Business Risk Category:** {danger['category_icon']} **{danger['category_title']}**

---

#### 🚨 Executive / Plain-English Summary
* **What is Broken:** {danger['what_is_broken']}
* **Real Danger:** {danger['what_attacker_can_do']}
* **Business Impact:** {danger['business_impact']}
* **Estimated Fix Time:** `{danger['estimated_fix_time']}`

---

#### 🛠️ Recommended Code Fix

```javascript
// Node.js / Express Fix:
{recipes['nodejs']}
```

```python
# Python / Flask / FastAPI Fix:
{recipes['python']}
```

```nginx
# Nginx / Reverse Proxy Hardening:
{recipes['nginx']}
```

---

#### 🔍 Verification Instructions
After applying the code or configuration patch, verify the fix using AutoSecAudit:
`python main.py scan {url}`
"""
    return ticket.strip()
