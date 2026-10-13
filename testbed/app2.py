"""
AutoSecAudit Regression Testbed Sandbox Application 2 (app2).

A lightweight, self-contained vulnerable application reproducing gaps seen on external targets,
including form-based POST injection vectors, CSRF-gated authentication, bare 500 error status
differential detection, OpenAPI endpoint discovery, and client-side JavaScript button navigation.

Ground-Truth Vulnerability Matrix:
| Endpoint | Method | Parameter | Classification | Description / Impact | Expected Detector |
| :--- | :--- | :--- | :--- | :--- | :--- |
| /labs/sqli | POST | query | Real Vulnerability | Simulated SQL syntax error leak in form submission | SQLiScanner |
| /labs/xss | POST | comment | Real Vulnerability | Reflected Cross-Site Scripting via unescaped POST body | XSSScanner |
| /labs/rce | POST | domain | Real Vulnerability | Simulated OS command injection with token markers | CommandInjectionScanner |
| /labs/ssti | POST | name | Real Vulnerability | Server-Side Template Injection via render_template_string | SSTIScanner |
| /labs/sqli_bare500 | POST | id | Real Vulnerability | Bare 500 error status differential on lone quote "'" | SQLiScanner |
| /login | POST | session_token | Real Vulnerability | Session cookie missing HttpOnly and SameSite flags | MisconfigScanner / CSRFScanner |
| /openapi.json | GET | - | Real Vulnerability | Exposed OpenAPI specification enumerating API routes | DirBruteScanner / APIAbuseScanner |
| /api/v1/_debug | GET | - | Real Vulnerability | Unauthenticated debug route exposing user database records | OpenAPIImporter / AuthScanner |
| /go | GET | next | Decoy | Same-site slash redirect (/go -> /go/?next=...) | OpenRedirectScanner (Suppressed) |
| /login | GET | csrf_token | Decoy | Anti-CSRF token protected form (not vulnerable to CSRF) | CSRFScanner (Suppressed) |

Safe Sandbox Principles:
- No real OS commands executed (benign simulated marker replies only).
- No actual file system reads/writes.
- No outbound network fetches.
- Safe for automated DAST scanning and CI/CD pipelines.

Run with:
    python main.py testbed --app2 --port 8080
    or
    python testbed/app2.py
"""

import argparse
import html
import urllib.parse
from flask import Flask, request, redirect, jsonify, Response, render_template_string

app = Flask(__name__)
app.secret_key = "testbed2_insecure_development_key"

# Fixed CSRF token for the login form
LOGIN_CSRF_TOKEN = "app2_csrf_token_8899aabbcc"
SESSION_COOKIE_NAME = "session_token"
SESSION_COOKIE_VALUE = "app2_authenticated_session_token_xyz987"

USERS_DB = [
    {"id": 1, "username": "admin", "email": "admin@example.local", "role": "superadmin"},
    {"id": 2, "username": "alice", "email": "alice@example.local", "role": "user"},
    {"id": 3, "username": "bob", "email": "bob@example.local", "role": "user"},
]


def is_authenticated() -> bool:
    """Check if the request carries the valid session cookie."""
    return request.cookies.get(SESSION_COOKIE_NAME) == SESSION_COOKIE_VALUE


@app.route("/login", methods=["GET", "POST"])
def login():
    """Login form protected by CSRF token; sets unhardened session cookie on success."""
    if request.method == "POST":
        csrf = request.form.get("csrf_token") or request.form.get("csrf") or request.headers.get("X-CSRF-Token")
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        # Require non-empty credentials and valid CSRF token
        if not csrf or csrf != LOGIN_CSRF_TOKEN:
            return Response("CSRF token verification failed.", status=403, mimetype="text/plain")

        # Accept only admin/admin
        if username == "admin" and password == "admin":
            resp = redirect("/", code=302)
            # Intentionally missing HttpOnly and SameSite flags (AUD-60, AUD-66)
            resp.set_cookie(
                SESSION_COOKIE_NAME,
                SESSION_COOKIE_VALUE,
                httponly=False,
                samesite=None,
                secure=False,
            )
            return resp

        return Response("Invalid credentials. <a href='/login'>Try again</a>", status=401, mimetype="text/html")

    # GET: return form with anti-CSRF token (decoy for CSRFScanner)
    form_html = f"""<!DOCTYPE html>
<html lang="en">
<head><title>App2 Login</title></head>
<body>
    <h2>App2 Secure Login Portal</h2>
    <form action="/login" method="POST">
        <input type="hidden" name="csrf_token" value="{LOGIN_CSRF_TOKEN}" />
        <div><label>Username: <input type="text" name="username" value="" /></label></div>
        <div><label>Password: <input type="password" name="password" value="" /></label></div>
        <button type="submit">Sign In</button>
    </form>
</body>
</html>"""
    return Response(form_html, status=200, mimetype="text/html")


@app.route("/")
def index():
    """Authenticated landing page: navigation to labs only via onclick buttons."""
    if not is_authenticated():
        return redirect("/login", code=302)

    dashboard_html = """<!DOCTYPE html>
<html lang="en">
<head>
    <title>App2 Security Testbed</title>
</head>
<body>
    <h1>App2 Security Laboratories</h1>
    <p>Select a laboratory module below to begin testing:</p>
    <div class="nav-grid">
        <button onclick="window.location.href='/labs/sqli'">SQL Injection Lab</button>
        <button onclick="window.location.href='/labs/xss'">Reflected XSS Lab</button>
        <button onclick="window.location.href='/labs/rce'">Command Execution Lab</button>
        <button onclick="window.location.href='/labs/ssti'">Template Injection Lab</button>
        <button onclick="window.location.href='/labs/sqli_bare500'">Status Differential Lab</button>
        <button onclick="window.location.href='/go'">Redirect Service</button>
    </div>
</body>
</html>"""
    resp = Response(dashboard_html, status=200, mimetype="text/html")
    resp.set_cookie(SESSION_COOKIE_NAME, SESSION_COOKIE_VALUE, httponly=False, samesite=None)
    return resp


@app.route("/labs/sqli", methods=["GET", "POST"])
def lab_sqli():
    """POST form with simulated SQL syntax error leak."""
    if not is_authenticated():
        return redirect("/login", code=302)

    if request.method == "POST":
        q = request.form.get("query", "")
        # Simulated SQL syntax error signature on injection
        if "'" in q or '"' in q or "1=1" in q or "UNION" in q.upper():
            err_msg = "sqlite3.OperationalError: near \"'\": syntax error in SQL query at line 1"
            return Response(err_msg, status=500, mimetype="text/plain")
        return Response(f"Lookup results for {html.escape(q)}: 0 items matched.", status=200, mimetype="text/html")

    return Response("""<!DOCTYPE html>
<html><body>
    <h2>SQL Injection Form Lab</h2>
    <form action="/labs/sqli" method="POST">
        <input type="hidden" name="csrf_token" value="app2_lab_csrf_safe" />
        <input type="text" name="query" value="test" />
        <button type="submit">Execute Query</button>
    </form>
</body></html>""", status=200, mimetype="text/html")


@app.route("/labs/xss", methods=["GET", "POST"])
def lab_xss():
    """POST form with reflected XSS."""
    if not is_authenticated():
        return redirect("/login", code=302)

    if request.method == "POST":
        comment = request.form.get("comment", "")
        # Intentionally unescaped reflection
        return Response(f"<html><body><div id='output'>User Comment: {comment}</div></body></html>", status=200, mimetype="text/html")

    return Response("""<!DOCTYPE html>
<html><body>
    <h2>Reflected XSS Form Lab</h2>
    <form action="/labs/xss" method="POST">
        <input type="hidden" name="csrf_token" value="app2_lab_csrf_safe" />
        <input type="text" name="comment" value="hello" />
        <button type="submit">Submit Feedback</button>
    </form>
</body></html>""", status=200, mimetype="text/html")


@app.route("/labs/rce", methods=["GET", "POST"])
def lab_rce():
    """POST form with simulated OS command execution."""
    if not is_authenticated():
        return redirect("/login", code=302)

    if request.method == "POST":
        domain = request.form.get("domain", "")
        # Benign simulated command execution replies matching AutoSec tokens
        if "AUTOSEC_RCE_TEST" in domain or "AUTOSEC_$((6*7))_RCE" in domain or "AUTOSEC_42_RCE" in domain:
            return Response("PING 127.0.0.1\nAUTOSEC_42_RCE\ncommand output: AUTOSEC_RCE_TEST\n", status=200, mimetype="text/plain")
        return Response(f"Pinging {html.escape(domain)}: 0% packet loss", status=200, mimetype="text/plain")

    return Response("""<!DOCTYPE html>
<html><body>
    <h2>Command Execution Form Lab</h2>
    <form action="/labs/rce" method="POST">
        <input type="hidden" name="csrf_token" value="app2_lab_csrf_safe" />
        <input type="text" name="domain" value="localhost" />
        <button type="submit">Ping Host</button>
    </form>
</body></html>""", status=200, mimetype="text/html")


@app.route("/labs/ssti", methods=["GET", "POST"])
def lab_ssti():
    """POST form with SSTI via render_template_string."""
    if not is_authenticated():
        return redirect("/login", code=302)

    if request.method == "POST":
        name = request.form.get("name", "guest")
        # Template injection rendered via Jinja2 (HTML-escape angle brackets to avoid XSS conflation)
        safe_name = name.replace("<", "&lt;").replace(">", "&gt;")
        return Response(render_template_string(f"<html><body>Hello {safe_name}!</body></html>"), status=200, mimetype="text/html")

    return Response("""<!DOCTYPE html>
<html><body>
    <h2>Template Injection Form Lab</h2>
    <form action="/labs/ssti" method="POST">
        <input type="hidden" name="csrf_token" value="app2_lab_csrf_safe" />
        <input type="text" name="name" value="guest" />
        <button type="submit">Render Greeting</button>
    </form>
</body></html>""", status=200, mimetype="text/html")


@app.route("/labs/sqli_bare500", methods=["GET", "POST"])
def lab_sqli_bare500():
    """Endpoint returning a bare 500 status code only for a lone quote "'"."""
    if not is_authenticated():
        return redirect("/login", code=302)

    val = request.form.get("id") or request.args.get("id") or request.args.get("param") or ""
    # Lone quote -> bare 500 error status differential
    if val == "'":
        return Response("Internal Server Error", status=500, mimetype="text/plain")

    if request.method == "POST" or request.args:
        return Response(f"Record lookup ok: id={html.escape(str(val))}", status=200, mimetype="text/plain")

    return Response("""<!DOCTYPE html>
<html><body>
    <h2>Status Differential Lab</h2>
    <form action="/labs/sqli_bare500" method="POST">
        <input type="hidden" name="csrf_token" value="app2_lab_csrf_safe" />
        <input type="text" name="id" value="1" />
        <button type="submit">Lookup Record</button>
    </form>
</body></html>""", status=200, mimetype="text/html")


@app.route("/go", methods=["GET"])
@app.route("/go/", methods=["GET"])
def slash_redirect():
    """Same-site slash redirect /go -> /go/?next=<echo> (Decoy for Open Redirect)."""
    next_url = request.args.get("next", "")
    if not request.path.endswith("/"):
        qs = f"?next={urllib.parse.quote(next_url)}" if next_url else ""
        return redirect(f"/go/{qs}", code=302)
    return Response(f"Redirect landing destination: {html.escape(next_url)}", status=200, mimetype="text/html")


@app.route("/openapi.json", methods=["GET"])
def openapi_spec():
    """OpenAPI 3.0 specification exposing unauthenticated /api/v1/_debug endpoint."""
    spec = {
        "openapi": "3.0.0",
        "info": {
            "title": "AutoSecAudit Regression Sandbox 2 API",
            "version": "1.0.0",
            "description": "Internal testbed API specification"
        },
        "paths": {
            "/api/v1/_debug": {
                "get": {
                    "summary": "Internal unauthenticated debug user records",
                    "responses": {
                        "200": {
                            "description": "User records array",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "array",
                                        "items": {
                                            "type": "object",
                                            "properties": {
                                                "id": {"type": "integer"},
                                                "username": {"type": "string"},
                                                "email": {"type": "string"},
                                                "role": {"type": "string"}
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    return jsonify(spec)


@app.route("/api/v1/_debug", methods=["GET"])
def api_debug():
    """Unauthenticated debug endpoint returning user records."""
    return jsonify(USERS_DB), 200


def run_testbed(host="127.0.0.1", port=8080):
    print("=" * 60)
    print(f"[TESTBED2] AutoSecAudit Regression Sandbox running at http://{host}:{port}")
    print(f"           Ready for authenticated regression testing")
    print("=" * 60)
    app.run(host=host, port=port, debug=False)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AutoSecAudit Vulnerable Regression Testbed 2")
    parser.add_argument("--port", type=int, default=8080, help="Port to run testbed on (default: 8080)")
    parser.add_argument("--host", type=str, default="127.0.0.1", help="Host address (default: 127.0.0.1)")
    args = parser.parse_args()
    run_testbed(host=args.host, port=args.port)
