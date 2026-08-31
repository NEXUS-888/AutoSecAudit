"""
AutoSecAudit Vulnerable Testbed Sandbox Application.

A lightweight, self-contained educational testing target designed specifically
for validating and demonstrating AutoSecAudit's dynamic vulnerability scanner plugins,
attack simulations, Danger assessments, and MCP autonomous fix recipes in a safe,
isolated local environment.

Run with:
    python main.py testbed --port 8080
    or
    python testbed/app.py
"""

import sys
import os
import argparse
from flask import Flask, request, render_template_string, redirect, jsonify, Response

app = Flask(__name__)
app.secret_key = "testbed_insecure_development_key"

USERS_DB = {
    1: {"id": 1, "username": "alice", "email": "alice@company.local", "role": "user", "balance": "$4,250.00"},
    2: {"id": 2, "username": "bob", "email": "bob@company.local", "role": "user", "balance": "$12,800.50"},
    3: {"id": 3, "username": "admin", "email": "admin@company.local", "role": "superadmin", "balance": "$99,999.00"}
}

INDEX_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>AutoSecAudit Target Sandbox</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0c0d14; color: #f1f5f9; padding: 40px; }
        .container { max-width: 800px; margin: 0 auto; background: #131522; padding: 32px; border-radius: 12px; border: 1px solid rgba(255,255,255,0.1); }
        h1 { color: #38bdf8; margin-top: 0; font-size: 24px; }
        p { color: #94a3b8; font-size: 14px; line-height: 1.6; }
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 16px; margin-top: 24px; }
        .card { background: #1e2238; border: 1px solid rgba(255,255,255,0.06); padding: 16px; border-radius: 8px; }
        .card h3 { margin: 0 0 8px; font-size: 14px; color: #f8fafc; }
        .card a { color: #38bdf8; text-decoration: none; font-size: 13px; font-weight: 500; }
        .card a:hover { text-decoration: underline; }
        .tag { font-size: 11px; padding: 2px 6px; border-radius: 4px; background: rgba(239,68,68,0.2); color: #f87171; float: right; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🎯 AutoSecAudit Target Testbed</h1>
        <p>This is a safe, locally sandboxed web application containing intentional security test vectors. Use it to verify AutoSecAudit's attack simulations, DAST plugins, and autonomous MCP remediation recipes.</p>

        <div class="grid">
            <div class="card">
                <span class="tag">SQLi & XSS</span>
                <h3>Search Endpoint</h3>
                <a href="/search?q=test">Test /search?q=...</a>
            </div>
            <div class="card">
                <span class="tag">CSRF & Auth</span>
                <h3>Login Portal</h3>
                <a href="/login">Test /login</a>
            </div>
            <div class="card">
                <span class="tag">Open Redirect</span>
                <h3>Redirect Gateway</h3>
                <a href="/redirect?next=https://example.com">Test /redirect?next=...</a>
            </div>
            <div class="card">
                <span class="tag">BOLA / IDOR</span>
                <h3>User API Record</h3>
                <a href="/api/users/1">Test /api/users/1</a>
            </div>
            <div class="card">
                <span class="tag">SSRF</span>
                <h3>Webhook Fetcher</h3>
                <a href="/fetch?url=http://127.0.0.1">Test /fetch?url=...</a>
            </div>
            <div class="card">
                <span class="tag">SSTI</span>
                <h3>Template Engine</h3>
                <a href="/template?name={{7*7}}">Test /template?name=...</a>
            </div>
            <div class="card">
                <span class="tag">Path Traversal</span>
                <h3>File Viewer</h3>
                <a href="/view?file=sample.txt">Test /view?file=...</a>
            </div>
            <div class="card">
                <span class="tag">Secret Leak</span>
                <h3>Environment Config</h3>
                <a href="/.env">Test /.env</a>
            </div>
        </div>
    </div>
</body>
</html>
"""


@app.route("/")
def index():
    return render_template_string(INDEX_HTML)


@app.route("/search")
def search():
    q = request.args.get("q", "")
    # Intentional SQL error simulation when quote is injected
    if "'" in q or '"' in q:
        return "<p>OperationalError: syntax error at or near 'SELECT * FROM products WHERE query=' (SQL error signature)</p>", 500
    # Intentional Reflected XSS
    return render_template_string(f"<h2>Search Results for: {q}</h2><p>0 products matched query.</p><a href='/'>Back</a>")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        # Intentional SQLi auth bypass
        if "' or '1'='1" in username.lower() or "' or 1=1" in username.lower() or (username == "admin" and password == "admin"):
            resp = redirect("/dashboard")
            resp.set_cookie("session_id", "simulated_admin_token_12345", httponly=False)  # Missing HttpOnly + SameSite
            return resp
        return "<p>Invalid credentials</p><a href='/login'>Try again</a>", 401

    # Intentional Missing Anti-CSRF Token
    return """
    <h2>Login Portal (Vulnerable to CSRF & SQLi)</h2>
    <form method="POST" action="/login">
        <input type="text" name="username" placeholder="Username" /><br/><br/>
        <input type="password" name="password" placeholder="Password" /><br/><br/>
        <button type="submit">Sign In</button>
    </form>
    """


@app.route("/redirect")
def open_redirect():
    target = request.args.get("next") or request.args.get("url") or request.args.get("redirect") or "/"
    # Intentional unvalidated open redirection
    return redirect(target)


@app.route("/api/users/<int:user_id>")
def get_user_profile(user_id):
    # Intentional BOLA / IDOR (no auth check)
    user = USERS_DB.get(user_id)
    if user:
        return jsonify(user)
    return jsonify({"error": "User not found"}), 404


@app.route("/fetch")
def ssrf_fetch():
    url = request.args.get("url", "")
    # Intentional loopback / SSRF reflection
    if url.startswith("http://127.0.0.1") or url.startswith("http://localhost") or "metadata" in url:
        return jsonify({"status": "fetched", "target": url, "simulated_internal_response": "SSH-2.0-OpenSSH_8.9p1 Ubuntu"}), 200
    return jsonify({"status": "remote_fetch_ok", "url": url}), 200


@app.route("/template")
def ssti_render():
    name = request.args.get("name", "World")
    # Intentional Server-Side Template Injection
    return render_template_string(f"Hello {name}!")


@app.route("/view")
def path_traversal():
    filename = request.args.get("file", "sample.txt")
    if ".." in filename or "etc/passwd" in filename or "win.ini" in filename:
        return "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n", 200
    return f"Displaying content of file: {filename}", 200


@app.route("/.env")
def env_leak():
    return Response(
        "DATABASE_URL=postgres://autosec:prod_db_p@ssw0rd!@10.0.0.5:5432/production\n"
        "JWT_SECRET=super_secret_signing_key_998877\n"
        "PAYMENT_API_KEY=testbed_sample_sandbox_key_99881122\n",
        mimetype="text/plain"
    )


@app.route("/admin")
def admin_panel():
    return "<h1>Admin Control Panel</h1><p>Confidential internal administrative controls.</p>", 200


def run_testbed(host="127.0.0.1", port=8080):
    print("=" * 60)
    print(f"[TESTBED] AutoSecAudit Target Sandbox running at http://{host}:{port}")
    print(f"          Safe sandbox ready for active attack simulation & testing")
    print("=" * 60)
    app.run(host=host, port=port, debug=False)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AutoSecAudit Vulnerable Testbed Sandbox")
    parser.add_argument("--port", type=int, default=8080, help="Port to run testbed on (default: 8080)")
    parser.add_argument("--host", type=str, default="127.0.0.1", help="Host address (default: 127.0.0.1)")
    args = parser.parse_args()
    run_testbed(host=args.host, port=args.port)
