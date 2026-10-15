# AutoSecAudit — Audit Fix Backlog

Source: Claude Code audit, 2026-10-11. This file is the **contract** between the fixer
(Antigravity) and the verifier (Claude Code).

## Rules of the loop

- Work is done **one batch at a time** (2–3 issues). The current batch lives in `audit/STATE.md`.
- The fixer implements each issue's **Required fix** and satisfies **every Acceptance criterion**.
  If the fixer believes a required approach is wrong, it still must not silently deviate: it
  writes the objection under "Deviations" in its handoff and the verifier decides.
- The fixer must **not edit**: this file, `audit/STATE.md` (except the `status:` line),
  `audit/reviews/`, `.claude/`. The fixer does **not commit**.
- Existing tests may not be deleted, skipped, or weakened. New behavior gets new tests
  (write the failing test first). Every acceptance criterion must be covered by a test.
- Only touch files needed for the current batch. Unrelated refactors are rejected.

### Stable API contract (the verifier's checks call these — keep them stable)

`core.utils.is_target_allowed / validate_target` · `core.engine.Engine(mock_mode=…).set_target / run_plugins / _dict_to_findings` ·
`mcp_server.handle_scan / handle_get_findings / handle_verify_fix` · `core.auth.create_user / verify_user / init_user_db / DB_PATH` ·
`ui.app.app / _run_scan_background` · `core.authenticator.AutoAuthenticator(base_url, username, password, login_url=None).authenticate()` ·
`core.crawler.WebCrawler(mock_mode=False).crawl(url)` · `plugins.base_plugin.BaseScanner._safe_request` ·
`core.timing.TimingVerifier.verify_delay` · `intelligence.delta.DeltaAnalyzer.compare` · `intelligence.correlator.Correlator.link_related` ·
`intelligence.danger_engine.calculate_security_posture / classify_threat_category` · `intelligence.compliance.ComplianceMapper.map_findings` ·
`core.dev_detector.detect_dev_environment` · `intelligence.enricher.Enricher.enrich`.
If an issue genuinely requires changing one of these, say so in the handoff.

---

## B01 — Foundation (runs on supported Pythons, deps correct)

### AUD-01 · `Tuple` NameError on Python < 3.14
- **Files:** `core/utils.py` (~line 5, 168), `.github/workflows/ci.yml`
- **Problem:** `check_target_reachable(...) -> Tuple[bool, str]` but `Tuple` is not imported. 3.14 evaluates annotations lazily so it works locally; CI and Docker run 3.10, where *every* entry point crashes on import.
- **Required fix:** import `Tuple` from `typing`. Add a CI matrix running the suite on `3.10` and `3.12` (keep 3.10 as minimum). Scan the rest of the codebase for other annotation names that are used but not imported.
- **Acceptance:** `py -3.11 -c "import core.utils"` succeeds; CI workflow has a `python-version` matrix containing `"3.10"` and `"3.12"`.

### AUD-02 · `requirements.txt` incomplete
- **Files:** `requirements.txt`
- **Problem:** `reportlab` (PDF export) is missing, so PDF download fails in Docker. `urllib3` is used directly but only installed transitively.
- **Required fix:** add `reportlab` and `urllib3` with minimum versions. Keep `pyyaml` (it will be used by AUD-31).
- **Acceptance:** `requirements.txt` lists `reportlab` and `urllib3`; `pip install -r requirements.txt` in a clean venv succeeds.

### AUD-03 · `.gitignore` ignores every `*.json`
- **Files:** `.gitignore`
- **Problem:** global `*.json` / `*.html` rules hide fixtures, specs and audit files.
- **Required fix:** remove the global `*.json` and `*.html` rules; scope ignores to generated output (`data/`, which already covers reports).
- **Acceptance:** `git check-ignore audit/fixture.json` → not ignored; `git check-ignore data/reports/x.json` → ignored.

---

## B02 — Target scope enforcement

### AUD-04 · Allowlist matches hostname strings, not IPs
- **Files:** `core/utils.py` `is_target_allowed` (~lines 120–165)
- **Problem:** `hostname.startswith(("10.", "192.168.", ...))` lets `10.example.com`, `192.168.attacker.net`, `127.evil.org` through. Name-suffix matching (`-dvwa`, `.localhost`) is also string-based.
- **Required fix:** parse the hostname; if it is an IP literal use `ipaddress`; otherwise resolve with `socket.getaddrinfo`. Allow **only if every resolved address** is `is_private` or `is_loopback` (IPv4 and IPv6). Unresolvable → reject with a clear reason. Drop the name-based allowlist (docker/VPN practice targets resolve to private IPs and pass naturally).
- **Acceptance:** `10.example.com`, `192.168.attacker.net`, `127.evil.org`, `8.8.8.8`, `example.com` → not allowed. `localhost`, `127.0.0.1`, `192.168.1.5`, `10.0.0.2`, `http://[::1]:8080` → allowed. Unit tests cover all of these.

### AUD-05 · Allowlist enforced only at some entry points
- **Files:** `core/engine.py` `set_target`, `mcp_server.py` `handle_scan`
- **Problem:** the CLI and UI call `is_target_allowed`; MCP and direct `Engine` use never do.
- **Required fix:** enforce `is_target_allowed` inside `Engine.set_target` (a single choke point, also in mock mode). Entry points may keep their early check for nicer UX.
- **Acceptance:** `Engine(mock_mode=True).set_target("http://10.example.com")` → `False`; `set_target("http://127.0.0.1:8080")` → `True`.

### AUD-06 · `validate_target` rejects single-label hosts
- **Files:** `core/utils.py` `validate_target`
- **Problem:** the regex requires a dot, so `http://juice-shop:3000` and `http://dvwa` (the docker-compose targets) are invalid.
- **Required fix:** replace the regexes with `urllib.parse` validation: scheme `http`/`https` (or none → assume http), hostname present, port (if any) 1–65535, IPv6 literals supported.
- **Acceptance:** valid: `http://juice-shop:3000`, `dvwa`, `localhost:8080`, `10.0.0.2`, `http://[::1]:80`. Invalid: `""`, `http://`, `ftp://x`, `http://host:99999`, `not a url`.

---

## B03 — MCP server correctness

### AUD-07 · `autosec_get_findings` reads the wrong key
- **Files:** `mcp_server.py` `handle_get_findings` (~line 200)
- **Problem:** reads `data["findings"]`, but reports store `all_findings` → always 0 findings, grade A+. It also reads fields that `Finding` doesn't have (`url`, `parameter`, `cwe`, `evidence`).
- **Required fix:** read `all_findings` (fall back to `findings` for old files). Map to real `Finding` fields (`cwe_id`, `raw_output`, `confidence`, `id`, `description`). Validate `report_id` against `^[\w-]+$`.
- **Acceptance:** for a report with N findings, `findings_count == N`, and the grade is computed from them. A test covers this.

### AUD-08 · `autosec_verify_fix` always reports RESOLVED
- **Files:** `mcp_server.py` `handle_verify_fix` (~lines 273–291)
- **Problem:** hardcoded `mock_mode=True`, wrong key, `"verified": True` unconditionally, and title-substring matching (`"sqli"` never matches "SQL Injection").
- **Required fix:** run in real mode (accept an optional `mock` argument, default `False`). Run only the plugins relevant to `vulnerability_type` via an explicit `type → plugin class names` map. Match remaining findings by plugin/tool, not title substring. Check target scope and reachability first. If the scan errors or the target is unreachable, return `status: "ERROR"` with `verified: false` — never `RESOLVED`.
- **Acceptance:** an unreachable local target (closed port) → status is not `RESOLVED`. With a stubbed scan returning an SQLi finding, `vulnerability_type="sqli"` → `STILL_VULNERABLE`. Tests cover both.

### AUD-09 · `autosec_scan` returns success for disallowed targets
- **Files:** `mcp_server.py` `handle_scan`
- **Problem:** no scope check; an undocumented `skip_reachability` argument; errors surface as raw exceptions.
- **Required fix:** call `is_target_allowed` first and return `{"status": "error", "error": reason}`. Either add `skip_reachability` to the tool `inputSchema` or remove it. Catch `ConnectionError`/`ValueError` from the engine and return a structured error.
- **Acceptance:** `handle_scan({"target": "http://10.example.com", "mock": True})["status"] == "error"`.

---

## B04 — Dashboard access control

### AUD-10 · Most routes require no login
- **Files:** `ui/app.py`
- **Problem:** only `/dashboard` checks the session. `/scan`, `/scan/async`, `/scan/progress/*`, `/scan/status/*`, `/report/*`, `/download*`, `/api/report/*` and `/history` are open.
- **Required fix:** add a `login_required` decorator. Apply it to every route except `/`, `/landing`, `/login`, `/register`, `/logout`, `/api/auth/status` and static files. HTML routes redirect to `/login?next=…`; JSON/SSE routes return 401.
- **Acceptance:** unauthenticated `GET /history`, `GET /report/latest`, `GET /download/x`, `GET /api/report/x/waf-rules` and `POST /scan/async` never return 200.

### AUD-11 · Hardcoded default admin password
- **Files:** `core/auth.py` `init_user_db` (~lines 48–66)
- **Problem:** seeds `admin / AutoSec@2026` and logs the password.
- **Required fix:** if no users exist, create `admin` with the password from env `AUTOSEC_ADMIN_PASSWORD`; if that is unset, generate `secrets.token_urlsafe(16)` and print it **once to stderr** (never to the log). Never log passwords.
- **Acceptance:** on a fresh DB with the env var unset, `verify_user("admin", "AutoSec@2026")` fails. No password appears in log output.

### AUD-12 · Open self-registration + SQLite connection leak
- **Files:** `core/auth.py`, `ui/app.py` `/register`
- **Problem:** anyone can register, so the login wall means nothing. Separately, `with sqlite3.connect()` commits but never closes the connection.
- **Required fix:** registration disabled unless `AUTOSEC_ALLOW_REGISTRATION=true`; when enabled, role is always `developer`. Wrap connections with `contextlib.closing` (or close explicitly) in every function.
- **Acceptance:** with the env var unset, `POST /register` does not create a user. A test confirms connections are closed (e.g. the DB file can be deleted right after the call on Windows).

---

## B05 — Dashboard web hardening

### AUD-13 · No CSRF protection
- **Files:** `ui/app.py`, templates/JS that POST, `requirements.txt`
- **Required fix:** CSRF protection on all state-changing POSTs (`/login`, `/register`, `/scan`, `/scan/async`). Flask-WTF `CSRFProtect` is preferred; the front-end sends the token (hidden field / `X-CSRFToken` header). It must be disableable in tests via `app.config["WTF_CSRF_ENABLED"] = False`.
- **Acceptance:** with CSRF enabled, `POST /login` without a token → 400. The existing UI flows still work (tests updated to disable CSRF or send the token).

### AUD-14 · Open redirect through `next`
- **Files:** `ui/app.py` `/login`, `/register`
- **Required fix:** accept `next` only if it is a relative path starting with a single `/` (reject `//`, `/\`, schemes, and backslashes); otherwise fall back to `/dashboard`.
- **Acceptance:** a successful login with `next=https://evil.example`, `//evil.example` or `/\evil.example` redirects to a local path.

### AUD-15 · Unsafe server defaults
- **Files:** `main.py`, `ui/app.py`, `config.py`
- **Problem:** binds `0.0.0.0`; `SECRET_KEY` is regenerated on every restart; no login throttling.
- **Required fix:** default host `127.0.0.1`, overridable with `AUTOSEC_HOST` (log a warning when it isn't loopback). When `AUTOSEC_SECRET_KEY` is unset, generate a key once and persist it to `data/.secret_key`. Throttle login: at most 5 failures per IP per 5 minutes (in-memory), then 429.
- **Acceptance:** no literal `host="0.0.0.0"` in the code; two fresh processes see the same `config.SECRET_KEY`; the 6th bad login within 5 minutes → 429.

---

## B06 — Dashboard bugs

### AUD-16 · `save_json` NameError in JSON download
- **Files:** `ui/app.py` `download_report` (~line 2893)
- **Required fix:** don't write files during a GET. Serve the resolved report data directly (`Response(json.dumps(...), mimetype="application/json")` with the download headers). This also removes the need for `save_json`.
- **Acceptance:** downloading a report found via any naming scheme returns 200 JSON; the route writes no files.

### AUD-17 · "Skip reachability" silently switches to demo mode
- **Files:** `ui/app.py` `/scan/async`, `/scan` (`is_demo = ... or skip_reachability`)
- **Required fix:** `skip_reachability` only skips the pre-flight check; the mode comes from `mode`/`mock_mode` alone.
- **Acceptance:** `POST /scan/async` with `mode=real&skip_reachability=true` → response `mode == "real"`.

### AUD-18 · Report lookup returns the wrong report
- **Files:** `ui/app.py` `_resolve_report_data`, `export_dev_ticket`
- **Problem:** the fallback matches with `clean_id in timestamp` (so `"2"` matches anything with a 2, and an empty timestamp matches everything) and loads every report on every request. An unknown finding ID in `dev-ticket` returns `findings[0]`.
- **Required fix:** exact matches only (the known filename patterns); delete the substring fallback. `dev-ticket` returns 404 for an unknown finding.
- **Acceptance:** with only `scan_20990101_000001.json` present, `GET /report/2` → 404; `GET /api/report/<id>/dev-ticket/NOPE` → 404.

---

## B07 — Scan job management

### AUD-19 · Unbounded concurrent scans; stuck jobs never cleaned
- **Files:** `ui/app.py`
- **Required fix:** a bounded executor (`AUTOSEC_MAX_CONCURRENT_SCANS`, default 2). Return 429 when full. TTL cleanup removes any job older than TTL; jobs `running` longer than `2 × SCAN_TIMEOUT` are marked `error`.
- **Acceptance:** with the cap at 1 and one job running, a second `POST /scan/async` → 429. Covered by a test.

### AUD-20 · SSE clients steal each other's events
- **Files:** `ui/app.py` `scan_progress`, `_run_scan_background`
- **Problem:** events go into one `queue.Queue`, so two tabs on the same scan each see only part of the stream.
- **Required fix:** keep an append-only event list per job plus a `threading.Condition`. Each SSE client keeps its own cursor (and honors `Last-Event-ID`), and events carry an `id:`.
- **Acceptance:** a test with two concurrent subscribers to one job shows both receive the `done` event. `test_sse.py` becomes a real `unittest.TestCase` with no module-level side effects (today it runs a scan at import time with a 30 s deadline and fails intermittently).

### AUD-21 · Synchronous `/scan` duplicates the pipeline in the request thread
- **Files:** `ui/app.py` `/scan`
- **Required fix:** remove the synchronous scan route. If any template still posts to it, point the template at the async flow (or make `/scan` create an async job and redirect to a progress page). Update its tests.
- **Acceptance:** no full scan runs inside a request handler.

---

## B08 — Auto-login & crawler safety

### AUD-22 · Auto-login reports success on failed logins
- **Files:** `core/authenticator.py` `_evaluate_auth_response` (~lines 374–452)
- **Problem:** cookies set by the login page **GET** count as a session, so "any cookie + 200" is treated as success. Failure strings are only checked on 400/401/403. Juice Shop's `{"authentication": {"token": ...}}` isn't recognised.
- **Required fix:**
  - Snapshot the cookie jar before the POST; only cookies **new or changed by the login response** count.
  - Check failure indicators regardless of status code.
  - Extract tokens from nested shapes, including `authentication.token`.
  - Add a post-login verification step: request a verify URL (default: the target root) with the new credentials and require it to differ from the pre-login result (e.g. 401/redirect-to-login before → 200 after, or a logout link / username now present). A response token alone is enough only if a request with the token succeeds where the anonymous one did not.
- **Acceptance:** a server whose GET sets a cookie and whose POST returns `200 "Invalid email or password"` → `success == False`. A Juice-Shop-shaped server (token in `authentication.token`, root returns 401 without the token and 200 with it) → `success == True`, with the token captured.

### AUD-23 · Credential spraying across 14 paths → account lockout
- **Files:** `core/authenticator.py`
- **Required fix:** submit credentials only to an endpoint that looks like a login (a form with a password field, or a JSON endpoint answering 400/401/422 to an empty POST). Hard-cap total credential submissions at 6 per `authenticate()` call; stop at the first endpoint that clearly rejects the credentials.
- **Acceptance:** against a server where every path returns 200 HTML without a form, at most 6 credential POSTs are sent.

### AUD-24 · Crawler follows logout/destructive links and leaves scope on redirect
- **Files:** `core/crawler.py`
- **Required fix:** a configurable deny pattern (default: `logout|log-out|signout|sign-out|logoff|delete|remove|destroy`) applied to links and form actions before any request. After each response, discard it if `resp.url` left the origin (scheme + host + port).
- **Acceptance:** for a page linking `/logout` and `/delete?id=1`, neither is ever requested.

---

## B09 — Shared HTTP client

### AUD-25 · No shared, scope-aware HTTP layer
- **Files:** new `core/http_client.py`, `plugins/base_plugin.py`, `core/engine.py`, `core/politeness.py`
- **Problem:** about 40 direct `requests.*` calls; no auth, no scope check on redirects, a separate rate limiter per plugin, and a random rotating User-Agent that adds noise to response comparisons.
- **Required fix:** `ScanHttpClient`, owned by the `Engine` and injected into plugins:
  - one `requests.Session` carrying auth headers and cookies;
  - a stable User-Agent `AutoSecAudit/2.0` (remove UA rotation);
  - a thread-safe global rate limiter shared by all plugins;
  - default timeouts;
  - redirects followed manually, with a scope check (same origin + `is_target_allowed`) on **every hop**.
  
  `BaseScanner._safe_request` and `_get_baseline` delegate to it.
- **Acceptance:** a redirect to an out-of-scope host is not followed (test with a local server). The UA is constant across requests. The `_safe_request` signature is unchanged.

### AUD-26 · 429/503 responses are fed into detection logic
- **Files:** `core/politeness.py`, `core/http_client.py`
- **Problem:** the client sleeps on a 429 and then returns the 429 response, which baseline comparison treats as a high-confidence change. `max_retries_on_429` is never used.
- **Required fix:** retry with exponential backoff up to `max_retries`, honoring `Retry-After`. If still throttled, return `None` (and count it for the report). Never return a 429/503 to plugin logic.
- **Acceptance:** a server returning 429 once then 200 → `_safe_request` returns the 200. An always-429 server → `None`.

---

## B10 — Plugin migration

### AUD-27 · Plugins bypass auth/scope/politeness
- **Files:** all `plugins/*_plugin.py`
- **Required fix:** replace every direct `requests.get/post/...` and `requests.Session()` in plugins with the shared client (`self._safe_request` or `self.http`). Do not change detection logic in this batch.
- **Acceptance:** `grep -rnE "requests\.(get|post|put|delete|head|options|request|Session)\(" plugins/` matches nothing outside `base_plugin.py`. A test confirms a plugin request carries the `Authorization` header passed via `set_auth`. All existing plugin tests pass.

### AUD-28 · Duplicated helpers in plugins
- **Files:** plugins defining `_parse_url` / `_parse_target`
- **Required fix:** remove the per-plugin copies and use `BaseScanner._parse_target`.
- **Acceptance:** only `base_plugin.py` defines `_parse_target`/`_parse_url`.

---

## B11 — Engine correctness

### AUD-29 · `SCAN_TIMEOUT` never applies
- **Files:** `core/engine.py` `run_plugins` (~lines 200–250)
- **Problem:** `future.result(timeout=...)` inside `as_completed` is a no-op, so one hung plugin blocks the whole scan.
- **Required fix:** use `concurrent.futures.wait(..., timeout=SCAN_TIMEOUT)` for the whole plugin phase. Record unfinished plugins as `status="timeout"`, call `shutdown(wait=False, cancel_futures=True)`, and give the HTTP client a deadline so lingering threads stop making requests.
- **Acceptance:** with `SCAN_TIMEOUT=2` and a plugin that sleeps 6 s, `run_plugins` returns within about 4 s and that plugin's result has `status == "timeout"`.

### AUD-30 · Finding fields dropped on conversion
- **Files:** `core/engine.py` `_dict_to_findings`
- **Required fix:** build `Finding` from all dict keys that are dataclass fields (`dataclasses.fields`), with defaults for `host` and `confidence`.
- **Acceptance:** `cwe_id` and `pci_dss` survive the conversion.

### AUD-31 · OpenAPI import is wired to nothing
- **Files:** `core/openapi.py`, `core/engine.py`, `main.py`, `ui/app.py`
- **Problem:** `engine.crawler_data` is written and never read, and the endpoint format doesn't match what plugins expect.
- **Required fix:** `OpenAPIImporter.get_endpoints()` returns plugin-shaped `{path, param, method}` entries (query params + OpenAPI 3 `requestBody` top-level JSON properties + Swagger `formData`/`body` params; resolve local `$ref`; honor `basePath`/`servers[0]`). Support YAML specs. Add `Engine.add_endpoints()`, which merges imported endpoints with crawler endpoints (dedupe on method+path+param). Remove `crawler_data`.
- **Acceptance:** a test with a small OpenAPI 3 spec (one GET with a query param, one POST with a body) shows plugins receiving those endpoints.

---

## B12 — False-positive control

### AUD-32 · Baseline comparison is too weak
- **Files:** `plugins/base_plugin.py` `_get_baseline`, `_verify_against_baseline`
- **Problem:** a single sample; "length changed > 20 %" counts as verified; baselines are fetched without auth while probes are authenticated; reflected input changes the length by itself.
- **Required fix:**
  - At least 2 baseline samples (through the shared client, so with auth).
  - Record natural variance (status stability and length spread).
  - Add a control request with a benign random value.
  - Treat a change as significant only if it exceeds the observed variance and differs from the control.
  - Discount the length of the submitted value when it is reflected.
  - Use a similarity ratio (e.g. `difflib.SequenceMatcher` on a bounded prefix) rather than raw length alone.
- **Acceptance:** unit tests show that a response varying naturally by ±30 % (dynamic token) is not verified, that pure reflection of the input is not verified, and that a 200→500 change is verified.

### AUD-33 · Timing verification isn't statistical
- **Files:** `core/timing.py`, `core/engine.py`
- **Problem:** `std_dev` is computed but unused; when the control probe is also slow it still returns `(True, "medium")`; timing runs while other plugins load the target.
- **Required fix:**
  - Threshold = `mean + max(k·std_dev, ratio·expected)`.
  - If the control probe is also slow → **not verified**.
  - Require the delay to reproduce on a second delay probe.
  - The engine runs timing-based checks in a serialized phase after the parallel phase (e.g. plugins register timing checks, or an engine-level lock that pauses other traffic).
- **Acceptance:** unit tests with fake probe functions: slow control → `False`; jittery baseline raises the threshold; a reproduced delay with a fast control → `True`.

---

## B13 — Finding identity

### AUD-34 · Findings lack structured identity
- **Files:** `core/models.py`, all plugins' `parse_output`
- **Required fix:** add `vuln_type` (string from a documented enum in `core/models.py`), `endpoint`, `param`, `method`, `evidence` and `fingerprint` to `Finding`. Compute `fingerprint` = sha256 of `tool|vuln_type|method|endpoint|param`, falling back to `tool|title` when the structured fields are absent. Every plugin populates `vuln_type` and `endpoint`/`param` where applicable. Old report JSON still loads.
- **Acceptance:** `Finding` has these fields; every plugin's mock output sets `vuln_type`; loading an old report works.

### AUD-35 · Delta compares per-scan counters
- **Files:** `intelligence/delta.py`
- **Problem:** IDs like `SQLI-001` are list positions, so different findings at different endpoints look "unchanged".
- **Required fix:** compare by `fingerprint`, computing it for old reports on load.
- **Acceptance:** two findings with the same `id` but different titles/endpoints → 1 new, 1 fixed, 0 unchanged.

### AUD-36 · Correlator links everything; no dedupe
- **Files:** `intelligence/correlator.py`
- **Problem:** every finding in a single-target scan shares host:port, so all of them are "related". Running it twice appends the references twice.
- **Required fix:** `link_related` deduplicates by fingerprint (merging evidence/references) and groups by `(endpoint, param)`. It must be idempotent.
- **Acceptance:** two identical findings → one; running `link_related` twice yields the same references as running it once.

---

## B14 — Classification & grading

### AUD-37 · Four keyword classifiers disagree and overwrite plugin data
- **Files:** `intelligence/compliance.py`, `intelligence/danger_engine.py`, `intelligence/remediation.py`, `intelligence/recipes.py`
- **Problem:** first-match substring matching gives wrong results: "Login **Bypass**" → A01; `"env"` matches "Dev **Env**ironment"; `"auth"` matches "OAuth". `ComplianceMapper` overwrites the plugin's own OWASP tag, and remediation parses `"Type:"` out of free text.
- **Required fix:** one `vuln_type → {owasp, cwe, pci, danger_category, remediation_key, recipe_key}` table, used by all four modules. Keyword matching survives only as a fallback when `vuln_type` is missing, with word-boundary regexes. Never overwrite a plugin-provided `owasp_tag`/`cwe_id`.
- **Acceptance:** an SQLi login-bypass finding tagged `A03:2021` stays A03. A header finding marked "[Dev Environment Artifact]" is not `customer_data_theft`. A title containing "OAuth" is not classified by the `"auth"` keyword alone.

### AUD-38 · Grade ignores confidence
- **Files:** `intelligence/danger_engine.py` `calculate_security_posture`
- **Required fix:** weight by confidence (high 1.0 / medium 0.6 / low 0.25) over findings deduplicated by fingerprint. A finding forces an automatic F only if it is Critical **and** at least medium confidence.
- **Acceptance:** a single low-confidence Critical → not F; a single high-confidence Critical → F.

### AUD-39 · Dev-environment detection is based on free text
- **Files:** `core/dev_detector.py`
- **Problem:** the word "turbopack" anywhere in the page downgrades every header/CORS finding to Info, so a false match lets the CI gate pass.
- **Required fix:** use only structural signals (`<script src>` containing `/@vite/client`, `/@react-refresh`, `/_next/static/webpack/`, `__webpack_hmr`; the `Server` header). When downgrading, keep the original value in `original_severity`; `--fail-on` evaluates `original_severity` unless `--treat-dev-artifacts-as-info` is passed.
- **Acceptance:** `<p>We moved to turbopack</p>` → `None`; `<script type="module" src="/@vite/client">` → `"Vite Dev Server"`.

---

## B15 — One pipeline

### AUD-40 · The scan pipeline is implemented four times
- **Files:** new `core/pipeline.py`; `main.py`, `ui/app.py`, `mcp_server.py`
- **Problem:** CLI, async UI, sync UI and MCP each run a different subset of delta / correlate / enrich / compliance / remediation steps.
- **Required fix:** `run_scan_pipeline(request) -> (Report, paths)` performs: scope check → load plugins → set target → auth → OpenAPI → plugins → report → delta → correlate → enrich → compliance → remediation → summary → save JSON+HTML. It takes an optional progress callback (used by SSE). All three entry points call it.
- **Acceptance:** `Correlator(` is instantiated in exactly one non-test module. An MCP scan result's findings include `cwe_id`.

### AUD-41 · CLI defects
- **Files:** `main.py`
- **Required fix:** honor `--html`. Keep `--real`/`--mock` only on the subcommands (remove the global duplicates, which get overridden). Read the password from `AUTOSEC_LOGIN_PASS` or prompt with `getpass` when `--login-user` is given without `--login-pass` (keep `--login-pass` but warn that it is visible in the process list). Fix the stale menu text (plugin/test counts computed, not hardcoded).
- **Acceptance:** `main.py scan ... --mock --html out.html` writes `out.html`.

### AUD-42 · Report ID collisions / mismatch
- **Files:** `core/engine.py` `save_report`, `reports/generator.py` `generate_report`
- **Problem:** JSON and HTML each take their own second-resolution timestamp, so names can differ and concurrent scans can overwrite each other.
- **Required fix:** one `report_id = <YYYYmmdd_HHMMSS>_<6 hex>` generated once per scan and used for JSON, HTML and PDF.
- **Acceptance:** JSON and HTML of a scan share the same `report_id`; two scans in the same second get different IDs.

---

## B16 — Discovery quality

### AUD-43 · Crawler is a DFS that never reads JS bundles
- **Files:** `core/crawler.py`
- **Required fix:**
  - BFS with a queue (depth/page limits kept).
  - Same-origin check on scheme + host + port.
  - Fetch same-origin `<script src>` files (size cap, e.g. 2 MB, max 10 files) and run `extract_js_endpoints` on them.
  - Record the HTTP method implied by `.post(`/`.put(`/`.delete(` calls.
- **Acceptance:** a root page with `<script src="/app.js">`, where `app.js` contains `fetch('/api/items?id=1')`, yields `/api/items` with param `id`.

### AUD-44 · SPA soft-404 detection
- **Files:** `core/spa_detector.py`, `plugins/base_plugin.py`, `core/engine.py`
- **Problem:** a single probe; any page with the same `<title>` counts as a soft-404 (so server-rendered sites lose real findings); calibration doesn't follow redirects but plugins do; every plugin calibrates separately.
- **Required fix:** calibrate once in the engine and share the result. Use 2–3 random probes (one with a file extension) and the same redirect policy as the plugins. Title equality only counts together with length/similarity tolerance.
- **Acceptance:** a site with a shared title whose real page differs by more than 30 % in content is not flagged as a soft-404.

### AUD-45 · Enricher hits the network in mock mode
- **Files:** `intelligence/enricher.py`
- **Required fix:** no network calls in mock mode. Add a disk cache with TTL (`data/cve_cache.json`) and optional `NVD_API_KEY` support.
- **Acceptance:** with mock mode on, enriching a finding that has a `cve_id` makes zero HTTP calls.

---

## B17 — Test & runtime hygiene

### AUD-46 · Tests write into the real `data/` directory
- **Files:** `config.py`, `run_tests.py`, `core/auth.py`
- **Problem:** 418 report files have built up in `data/reports`; `core/auth` creates the DB on import.
- **Required fix:** `DATA_DIR`/`REPORTS_DIR` are overridable via `AUTOSEC_DATA_DIR`; `run_tests.py` points it at a temp directory; the DB is initialized lazily (first use or app factory), not on import.
- **Acceptance:** running the full suite leaves the file count of `data/reports` unchanged.

### AUD-47 · Library modules configure logging
- **Files:** `core/utils.py`, `ui/app.py`, others calling `logging.basicConfig`
- **Required fix:** only entry points (`main.py`, `mcp_server.py`) configure logging. In MCP mode nothing except protocol messages is written to stdout.
- **Acceptance:** no `logging.basicConfig` call in `core/`, `plugins/`, `intelligence/`, `reports/` or `ui/`.

---

## B18 — Detection accuracy (from a real scan of `testbed/app.py`, 2026-10-11)

Ground truth: the testbed's planted vulnerabilities (see comments in `testbed/app.py`).
The 2026-10-11 real full-profile scan produced 39 findings, about 25 of them unique true positives.

### AUD-48 · Reflection reported as command execution (4 Critical false positives)
- **Files:** `plugins/command_injection_plugin.py`
- **Problem:** `/search`, `/fetch`, `/template` and `/view` were reported as Critical, high-confidence OS command injection. These endpoints only *reflect* input, so the marker text comes back unchanged and is mistaken for command output.
- **Required fix:** report execution only when the response contains evidence that the reflected input alone cannot produce: compare against a control request whose reflection would be identical but which cannot execute anything. A marker that also appears in the control is reflection, not execution. Keep the timing path behind AUD-33's verifier.
- **Acceptance:** against the testbed, `/api/exec` is still reported and `/search`, `/fetch`, `/template` and `/view` are not. A unit test with a server that echoes its input yields no command-injection finding.

### AUD-49 · Content-type-blind detections and a missed login injection
- **Files:** `plugins/xss_plugin.py`, `plugins/ssrf_plugin.py`, `plugins/sqli_plugin.py`
- **Problem:** reflected XSS is reported on `/fetch`, which returns `application/json` (not rendered as HTML). SSRF is reported on `/view` (a file-path endpoint). The testbed's planted login injection on `/login` (a form-encoded POST) is **missed**, because login testing only sends JSON bodies.
- **Required fix:** XSS reflection counts only for HTML-rendered responses (`text/html` or no explicit non-HTML type). SSRF requires evidence tied to the fetched URL, not mere reflection of the parameter. Login testing also submits form-encoded bodies, using the form fields the crawler discovered.
- **Acceptance:** against the testbed, there is no XSS finding on `/fetch` and no SSRF finding on `/view`, and `/login` is reported. Unit tests cover the JSON-response and form-login cases.

### AUD-50 · Same issue reported several times across plugins
- **Files:** `intelligence/correlator.py`, `core/models.py`
- **Problem:** `/.env` is reported 3× (3 plugins), `/admin` 2×, `/api/exec` 2×, IDOR 2× (one per user ID), and three security headers by two plugins with **different severities** (Low vs Medium).
- **Required fix:** after AUD-34/36, add a canonical key `vuln_type|method|normalized_endpoint|param` (numeric path segments normalized to `{id}`) that ignores which tool reported the finding. Merge findings that share it: keep the highest-confidence evidence, list every reporting tool, and use one severity per `vuln_type` from the AUD-37 table.
- **Acceptance:** a real testbed scan reports `/.env`, `/admin`, `/api/exec`, the IDOR, and each missing header exactly once. A unit test covers cross-tool merging.

---

## B19 — Review regressions and scanner robustness (independent review of commit 428c2cd, 2026-10-13)

Evidence comes from adversarial tests run on a clean checkout, not from reading code. Each issue below was reproduced.

### AUD-62 · The open-redirect false-positive fix now misses real evasion forms (regression)
- **Files:** `plugins/open_redirect_plugin.py` (`_redirects_to_external_host`)
- **Problem:** the check resolves the `Location` header with `urljoin` and compares the host. `urljoin` does not treat these as external, but browsers do, and the old substring match caught all of them: `/\example.com`, `\\example.com`, `///example.com`, `https:example.com`. The plugin's own payload list contains the backslash form.
- **Required fix:** normalize the `Location` value before resolving: convert `\` to `/`, collapse a leading run of three or more `/` to `//`, and accept `scheme:host` (no slashes) and `scheme:/host`. Flag only when the resolved host is `example.com` or a subdomain. Keep the same-site echo case (`/login/?next=https%3A%2F%2Fexample.com`) unflagged.
- **Acceptance:** with `request_url="http://127.0.0.1:5103/redirect?next=PAYLOAD"`: flagged → `https://example.com`, `//example.com/x`, `/\example.com`, `\\example.com`, `///example.com`, `HTTPS://EXAMPLE.COM`, `https:example.com`, `http://127.0.0.1@example.com/`, `https://attacker.example.com/`. Not flagged → `/login/?next=https%3A%2F%2Fexample.com`, `https://example.com.evil.net/`, `https://notexample.com/`, empty string. A unit test covers every row.

### AUD-63 · Nmap: IPv6 targets scan nothing, and option-like hosts reach the nmap command line
- **Files:** `plugins/nmap_plugin.py`
- **Problem:** `http://[::1]:9000` (allowed by the scope check) runs `nmap … ::1` without `-6`; nmap answers "you have to use the -6 option" and scans 0 hosts, silently. A host value such as `--script=x`, `--version` or an empty string is passed to nmap as an option or as no target at all. The scope check normally rejects those first, but the plugin must not rely on that.
- **Required fix:** add `-6` when the host is an IPv6 literal; if the host is empty or starts with `-`, do not run nmap and log a warning; put `--` immediately before the host in the command.
- **Acceptance:** `_build_command()` for `http://[::1]:9000/x` contains `-6`, `-p 9000`, `--`, and ends with `::1`. For `http://--script=evil` and for an empty target, `run()` never calls `subprocess.run` (assert with a patch) and logs a warning. IPv4 and hostname targets are unchanged apart from the added `--`.

### AUD-64 · No response-size or total-time limit on requests to the target
- **Files:** `core/http_client.py`, `config.py`
- **Problem:** the client reads whole bodies into memory and applies only per-read timeouts. Verified against a local hostile fixture: a 300 MB response was held entirely in memory in 0.8 s, and a response dripping 10 bytes per second kept one request open for 40 s although the read timeout was 5 s. A malicious or broken target can exhaust memory or pin plugin threads until the engine deadline.
- **Required fix:** send with `stream=True`; read in chunks up to `config.MAX_RESPONSE_BYTES` (default 5 MiB, env `AUTOSEC_MAX_RESPONSE_BYTES`, valid range 64 KiB–100 MiB, invalid → default with a logged warning) and stop at `config.MAX_REQUEST_SECONDS` of total wall time per request (default 30, env `AUTOSEC_MAX_REQUEST_SECONDS`, range 1–300). On either limit, return the response with the body read so far, set `resp.truncated = True` (and `False` otherwise), and increment thread-safe counters `responses_truncated` and `requests_timed_out` on the client (AUD-59 will report them). `.text`, `.content` and `.json()` must keep working on the truncated body.
- **Acceptance:** a fixture streaming 50 MB → returned content ≤ the cap, `truncated` True, finished in a few seconds; a fixture dripping 10 bytes/s for 60 s with the cap set to 3 s → returns within about 4 s with `truncated` True; a normal small response is unchanged and `truncated` is False; the counters are exact under 50 concurrent calls; the existing http-client tests pass.

---

## B20 — Dashboard ownership and session hardening

### AUD-65 · Any logged-in user can read every other user's reports and scan progress
- **Files:** `ui/app.py`, `core/auth.py` (if needed), report writing in `core/pipeline.py`
- **Problem:** verified with two users: user B receives HTTP 200 for user A's `/report/<id>`, `/download/<id>`, `/download_pdf/<id>`, `/api/report/<id>/waf-rules`, `/history`, `/scan/status/<scan_id>` and `/scan/progress/<scan_id>`. Reports contain vulnerability details of the scanned systems.
- **Required fix:** store the owner's user id in each report (`owner`) and in each scan job. Serve a report, its downloads, its derived endpoints, and a scan's status/progress only to its owner or to a user with role `admin`; everyone else gets 404 (not 403). `/history` lists only the caller's reports (admin: all). Reports without an `owner` (created before this change) are visible to admins only.
- **Acceptance:** two users A and B and an admin: B gets 404 on every route above for A's report and scan; B's `/history` does not list A's report; A and the admin get 200; an old owner-less report is 404 for A and 200 for the admin. Existing tests are updated only where they relied on cross-user access, with the reason stated in the handoff.

### AUD-66 · Session and small correctness items found in review
- **Files:** `ui/app.py`, `config.py`, `testbed/app.py`, `intelligence/remediation.py`, templates that link to `/logout`
- **Problem:** (1) the dashboard's own session cookie is set without `SameSite` and without `Secure` (`SESSION_COOKIE_SAMESITE=None`). (2) `/logout` is a plain GET, so any page can log a user out with an image tag. (3) a session cookie without a `sid` (any cookie issued before AUD-session-revocation shipped, or forged in tests) is still accepted, so those cookies can never be revoked. (4) `testbed/app.py:207` calls `time.sleep` without importing `time`, so `/api/exec` with a `sleep` payload returns 500. (5) `intelligence/remediation.py` defines the key `"auth_scanner:idor"` twice (lines ~160 and ~212); the second silently replaces the first.
- **Required fix:** (1) set `SESSION_COOKIE_SAMESITE="Lax"` and `SESSION_COOKIE_SECURE` from a `config` flag that defaults to true when the request is HTTPS (`AUTOSEC_COOKIE_SECURE` env override). (2) make logout `POST` with the CSRF token (keep `GET /logout` as a harmless 405 or a confirmation page that posts); update every link or button that used GET. (3) reject sessions that have a `user_id` but no `sid` (treated as logged out) and set `PERMANENT_SESSION_LIFETIME` to 12 hours with `session.permanent = True` at login; update existing tests that forge sessions to add a `sid` through one shared helper. (4) import `time`. (5) merge the two entries into one that keeps the more specific text.
- **Acceptance:** `Set-Cookie` on login contains `SameSite=Lax` and `HttpOnly`; `GET /logout` does not log the user out; `POST /logout` with a token does; a forged session without `sid` gets 302 to login; the testbed `/api/exec?command=sleep` returns 200 after about 2 s; a unit test asserts `intelligence/remediation.py` has no duplicate dictionary keys (parse with `ast`).

---

## B21 — Deployment and documentation

### AUD-67 · Docker deployment is unreachable since the dashboard binds 127.0.0.1 by default
- **Files:** `Dockerfile`, `docker-compose.yml`, `README.md`
- **Problem:** the container runs `python main.py server`, which now binds `127.0.0.1` inside the container, so the published port `5000:5000` cannot be reached from the host. Neither file sets `AUTOSEC_HOST`. Also: the image runs as root, nikto is cloned from an unpinned branch, the Juice Shop image uses `:latest`, and no admin password is provided on first start.
- **Required fix:** `ENV AUTOSEC_HOST=0.0.0.0` in the Dockerfile (inside the container only); in compose publish `127.0.0.1:5000:5000` (host loopback only) and require `AUTOSEC_ADMIN_PASSWORD` with `${AUTOSEC_ADMIN_PASSWORD:?set AUTOSEC_ADMIN_PASSWORD}`; add a non-root `USER`; pin nikto to a tag or commit and the Juice Shop image to a version; keep `config.py`'s non-loopback warning.
- **Acceptance:** a test that parses the two files: `AUTOSEC_HOST=0.0.0.0` present for the server image, the published port is bound to `127.0.0.1`, a non-root `USER` exists, no `:latest` tag and no unpinned git clone remain, and `AUTOSEC_ADMIN_PASSWORD` is required in compose.

### AUD-68 · README does not document configuration or the authentication behavior
- **Files:** `README.md`
- **Problem:** the code reads about 20 `AUTOSEC_*` environment variables and the README documents none of them. It also does not explain that the dashboard now requires login, how the first admin password is chosen, how to enable registration, or how to run an authenticated scan (`--login-user`, `--login-pass`, `--login-url`), including the Git Bash path-conversion pitfall (`MSYS_NO_PATHCONV=1` or `//login/`).
- **Required fix:** add a configuration table (name, default, purpose) covering every `AUTOSEC_*` variable the code reads, a first-run section (`AUTOSEC_ADMIN_PASSWORD` or the password printed to stderr, `AUTOSEC_ALLOW_REGISTRATION`), an authenticated-scanning section, and correct any stale statement (test counts, default credentials).
- **Acceptance:** a test collects every `AUTOSEC_[A-Z_]+` name that appears in `config.py`, `core/`, `ui/`, `plugins/`, `main.py` and `mcp_server.py`, and asserts each one appears in `README.md`; the README mentions `--login-user` and `MSYS_NO_PATHCONV`.

---

## B22 — Form-aware injection testing (from external-testbed scans, 2026-10-13)

Evidence: scanning pygoat (Django) while logged in discovered 37 forms and 69 injectable endpoints yet reported **no** SQLi,
command injection, SSRF, SSTI or IDOR. All of those labs are POST forms. The injection plugins only exercise URL query
parameters, JSON bodies and a fixed list of login paths.

### Safety rules for active form testing (apply to B22, B23, B24; the verifier checks them)
- Same origin only: never submit to a form whose resolved action is on another origin. `is_target_allowed()` is never bypassed.
- Never submit a form whose action path, form id/name, or any field name/label matches `core.crawler.DEFAULT_DENY_PATTERN`
  (`logout|log-out|signout|sign-out|logoff|delete|remove|destroy`) or `reset|drop|purge|unsubscribe|deactivate|close-account|password`.
  Such forms are reported as discovered but are not probed.
- Payloads: reuse the existing benign payload sets. Add no destructive payloads (no `DROP`, `DELETE`, `UPDATE`, `rm`, shutdown, etc.).
- Request caps: per plugin per scan, probe at most 8 forms and 6 fields per form (named constants in `config.py`), most promising first
  (password/search/id/name/query/url/file/command-like field names).
- Tests start local fixture apps on `127.0.0.1` with `werkzeug.serving.make_server("127.0.0.1", 0, app)` in a thread and never contact any other host.
  Shared fixture helpers go in a new `testsupport.py` (not named `test_*.py`). Fixture apps must **simulate** command execution, SSRF and file
  reads (return canned output when a marker is present); they must never run a shell, fetch a URL, or read a file.

### AUD-51 · Discovered forms lose everything except field names
- **Files:** `core/crawler.py` (`_LinkFormParser`, `DiscoveredEndpoint`, `CrawlResult.get_injectable_endpoints`), `plugins/base_plugin.py`
- **Problem:** a form becomes `{"path", "param", "method"}` per input. Hidden fields (Django `csrfmiddlewaretoken`), default values, `<select>` options, `enctype` and the page the form was found on are dropped. A POST rebuilt from that is rejected (403/400) or exercises a different code path than a real submission.
- **Required fix:** extend the injectable-endpoint dicts with `fields` (name → default value, including hidden inputs and the first `<option>` of each select), `enctype`, `form_page` (URL where the form was found) and `source: "form"`. Keep the existing keys (`path`, `param`, `method`) unchanged. Add `BaseScanner.submit_form_probe(endpoint, param, value)` that builds the request from `fields` with only `param` replaced, encodes per `enctype` (urlencoded or multipart), re-fetches `form_page` first when a CSRF-like hidden field is present (names in `core.authenticator.CSRF_TOKEN_NAMES`) and uses the fresh token, sends through `_safe_request`, and refuses (returns `None`, sends nothing) when the action is cross-origin or matches the deny rules above.
- **Acceptance:** with a local fixture app (CSRF-protected POST form with a hidden token, a select and a text input): (1) crawler output contains `fields` including the hidden token and the select default; (2) `submit_form_probe` with a benign value gets HTTP 200 on the CSRF-protected form (not 400/403); (3) a form whose action is on another origin → `None`, no request sent; (4) a form at `/account/delete` and a form whose field is named in the deny list → not probed (`None`); (5) existing tests still pass unchanged.

### AUD-52 · SQLi and XSS plugins skip POST form fields
- **Files:** `plugins/sqli_plugin.py`, `plugins/xss_plugin.py`, `config.py`
- **Problem:** `<form method=post action=/sql_lab><input name=name><input name=pass>` is never injected. Only GET query parameters, JSON bodies and the fixed login list are tested.
- **Required fix:** for every discovered endpoint with `method == "POST"` (and form-sourced GET endpoints) use `submit_form_probe`, keeping the existing control-vs-payload verification (SQL error signature absent from the control; XSS reflection counted only in HTML-rendered responses, per AUD-49). Apply the caps and safety rules above; add the cap constants to `config.py`.
- **Acceptance:** fixture app with (a) a POST form that leaks a SQL error signature on a quote, (b) a POST form that reflects input unescaped as `text/html`, (c) a POST form that echoes input HTML-escaped, (d) a POST form that handles quotes safely. The scan reports (a) and (b) exactly once each with the form path and field, and reports nothing for (c) and (d). A fixture with 20 forms receives no more probe requests than the caps allow (assert on a server-side request counter).

### AUD-53 · Command injection, SSTI, SSRF and path traversal skip POST form fields
- **Files:** `plugins/command_injection_plugin.py`, `plugins/ssti_plugin.py`, `plugins/ssrf_plugin.py`, `plugins/path_traversal_plugin.py`
- **Problem:** same gap as AUD-52. pygoat's `cmd_lab`, `ssti/lab`, `ssrf_lab` and similar POST forms produced nothing.
- **Required fix:** use `submit_form_probe` for POST/form-sourced endpoints in all four plugins. Keep the evidence rules from AUD-48/49 (control comparison; SSRF needs evidence tied to the fetched URL, not mere reflection). Apply the caps and safety rules.
- **Acceptance:** fixture POST forms that *simulate* (a) command execution (returns a unique marker only when the payload contains the echo-marker command), (b) SSTI (`render_template_string(f"Hello {name}")`), (c) SSRF (returns a canned internal banner only for loopback URLs), (d) path traversal (returns canned passwd text for `..` input). Each is reported exactly once. A form that merely echoes its input yields none of the four. Existing GET/JSON detections are unchanged.

---

## B23 — Crawler coverage (from the pygoat and vulpy scans)

Evidence: pygoat links its labs only through `<button onclick="window.location.href='/xssL'">`; the crawl cap of 20 pages was spent on intro pages before any lab was reached; vulpy once crawled 0 pages (13 s, no retry) and another run crawled 7. The form safety rules from B22 apply.

### AUD-54 · Navigation in inline event handlers is invisible to the crawler
- **Files:** `core/crawler.py`
- **Problem:** only `href`, `src` and `action` attributes are followed. Pages reached through `onclick` navigation are never visited.
- **Required fix:** extract same-origin URLs from `on*` attributes (`location`, `location.href`, `window.location(.href)`, `location.assign()/replace()`, `window.open()`), `data-href`/`data-url`, `formaction`, and `<meta http-equiv="refresh">`, and treat them as links. Use regex over attribute values only; never execute JS. `javascript:` and cross-origin URLs are ignored. The existing deny pattern applies.
- **Acceptance:** a fixture page using each of the patterns above → each target path is discovered. `javascript:void(0)`, `https://other.example/x` and `onclick="location.href='/logout'"` → not followed. Existing crawler tests pass.

### AUD-55 · Crawl budget hard-coded to 20 pages / depth 3
- **Files:** `core/crawler.py` (`WebCrawler(max_pages=20, max_depth=3)` in the module helper), `core/engine.py`, `config.py`
- **Problem:** pygoat has ~90 reachable pages; the budget ran out on intro pages. Raising it manually took the crawl from 0 to 37 forms and 69 injectable endpoints.
- **Required fix:** `config.CRAWL_MAX_PAGES` (default 100), `CRAWL_MAX_DEPTH` (default 4), `CRAWL_MAX_SECONDS` (default 60), each overridable by `AUTOSEC_CRAWL_MAX_PAGES/DEPTH/SECONDS`; invalid or out-of-range values (pages 1–500, depth 1–8, seconds 5–600) fall back to the default with a logged warning. The BFS must not let repeated URL templates eat the budget: after 5 pages with the same path template (numeric or hex-id segments normalized, e.g. `/post/1` … `/post/40`), further matches are skipped. Stop at the time cap.
- **Acceptance:** fixture of 30 intro pages each linking to one distinct lab page, plus 40 `/post/<n>` pages → with defaults all 30 labs are visited and at most 5 `/post/<n>` pages; env overrides are honored and invalid values fall back; a slow fixture server stops the crawl at the time cap (use a patched clock or a tiny cap, not a real 60 s wait).

### AUD-56 · The crawler gives up silently
- **Files:** `core/crawler.py`
- **Problem:** a scan of vulpy logged "visited 0 pages, found 0 endpoints" with no retry and no indication in the report; another run of the same app visited 7 pages.
- **Required fix:** retry the start URL up to 3 times with 1 s then 2 s backoff, following redirects from it (e.g. `/` → `/posts`) so the redirect target counts as page 1. Add `CrawlResult.errors` (list of short strings), `CrawlResult.fetch_failures` (int) and `CrawlResult.start_ok` (bool). Never raise to the caller.
- **Acceptance:** a server failing the first 2 requests then succeeding → `start_ok` True and pages visited > 0; a server that always fails → `start_ok` False, `errors` non-empty, no exception; a `/` that redirects to `/posts` → `/posts` is visited and its links followed. Tests must patch the sleep so they run in well under a second.

---

## B24 — API discovery and detection recall

Evidence: VAmPI serves `/openapi.json`; the scanner reported "API documentation exposed" but tested none of the 17 documented endpoints without `--openapi`. vulpy returns a bare HTTP 500 for a quote in the login field and the SQLi plugin only recognises DB error text. One VAmPI scan hit the 300 s engine deadline ("Request skipped: scan deadline exceeded") and still reported success; under machine load another run lost 4 findings silently.

### AUD-57 · An exposed OpenAPI/Swagger spec is reported but never used
- **Files:** `core/engine.py`, `core/openapi.py`, `plugins/api_abuse_plugin.py`
- **Problem:** endpoints are imported from a spec only when the user passes `--openapi`.
- **Required fix:** when no spec was supplied, probe `/openapi.json`, `/swagger.json`, `/v2/api-docs`, `/v3/api-docs`, `/api-docs`, `/openapi.yaml` on the target origin through the shared client. If a valid spec is found, import it with the existing `OpenAPIImporter` and merge the endpoints into the discovered endpoints (deduplicated with the crawler's). Only the target origin is ever requested: ignore `servers:` entries that point elsewhere. An explicit `--openapi` wins and the auto-probe is skipped.
- **Acceptance:** fixture serving `/openapi.json` with 3 paths → the injection plugins receive those 3 endpoints; a spec whose `servers` lists `http://evil.example` → every request still goes to the fixture origin; invalid JSON → ignored without error; explicit spec supplied → the probe makes no spec requests.

### AUD-58 · SQL injection missed when the server answers with a bare 500
- **Files:** `plugins/sqli_plugin.py`
- **Problem:** a quote in vulpy's login username returns HTTP 500 with a generic page. The plugin only reports when a database error signature appears in the body.
- **Required fix:** add a paired differential check for GET params, JSON fields and form fields (via `submit_form_probe`): control value → normal response; value with a lone `'` → 5xx; value with a doubled `''` (a valid SQL string) → normal response again. All three must hold. Report as medium confidence "Possible SQL injection (error status differential)". Signature-based detection stays as is.
- **Acceptance:** fixture endpoints: (a) 500 on `'` and 200 on `''` → reported at medium confidence; (b) always 500 → not reported; (c) 500 on any special character including `''` → not reported; (d) the existing signature-based detections still pass.

### AUD-59 · Coverage loss is silent
- **Files:** `core/engine.py`, `core/http_client.py`, `core/models.py` (`Report`), `core/pipeline.py`, `reports/` templates, `main.py`, `config.py`
- **Problem:** hitting the engine deadline, plugin timeouts, or failed requests do not appear anywhere in the result; a degraded scan looks identical to a complete one.
- **Required fix:** add `Report.coverage` (dict, included in `to_dict`/`from_dict`; old reports without it must still load) with: `requests_total`, `requests_failed` (network/timeout), `requests_skipped_deadline`, `plugins_timed_out`, `plugins_skipped`, `crawl` (pages_visited, forms, fetch_failures, start_ok), `duration_seconds`, `per_plugin_seconds`, and `degraded` (true if the deadline was hit, any plugin timed out, or failed+skipped requests exceed 5% of total). Counters come from `ScanHttpClient` and must be thread-safe. The CLI prints a visible warning line when degraded; the HTML report shows a banner; the JSON carries the dict. Make the engine deadline configurable via `config.SCAN_DEADLINE_SECONDS` / `AUTOSEC_SCAN_DEADLINE_SECONDS` (default 300, range 30–3600, invalid → default with a warning).
- **Acceptance:** a fake slow plugin that exceeds a tiny deadline → `degraded` true and the CLI warning is printed; a clean mock scan → `degraded` false; counters stay exact under 100 concurrent threads; `Report` round-trips with and without `coverage`; the HTML report contains the banner text only when degraded.

---

## B25 — Regression testbed and a CLI argument check

### AUD-60 · Second built-in testbed that reproduces the gaps seen on external apps
- **Files:** `testbed/app2.py` (new), `main.py` (testbed subcommand option to select it), `test_b22_regression_testbed.py` (new)
- **Problem:** every end-to-end regression check uses `testbed/app.py`, which is GET/JSON based. The external apps showed bugs it cannot reproduce, so the same regressions can come back unnoticed.
- **Required fix:** add `testbed/app2.py`, a Flask app bound to `127.0.0.1` by default, with: a login form (CSRF token) gating the lab pages; navigation to the labs only through `onclick="window.location.href=..."` buttons; POST forms with (1) a simulated SQL error leak, (2) reflected XSS, (3) simulated command execution, (4) SSTI via `render_template_string`; an endpoint returning a bare 500 only for a lone `'`; a same-site slash redirect `/go` → `/go/?next=<echo>` (a decoy, must NOT be reported); `/openapi.json` documenting an unauthenticated `/api/v1/_debug` that returns user records; a session cookie set without HttpOnly/SameSite. Put a ground-truth table (real vs decoy) in the module docstring. No real command execution, file access, or network fetches.
- **Acceptance:** the test starts `app2` on a free loopback port, runs a real full-profile pipeline scan **with login credentials** (restrict plugins or profile so the test finishes in under 90 s and does not require nmap/nikto), and asserts: each planted vulnerability is reported exactly once; the decoys produce no findings; `coverage.degraded` is false; no request is made to any host other than the fixture.

### AUD-61 · A mangled `--login-url` fails silently
- **Files:** `core/authenticator.py`, `main.py`
- **Problem:** passing `--login-url /login/` from Git Bash on Windows reaches the scanner as `C:/Program Files/Git/login/`. The authenticator probes that string and logs only "GET probe failed"; the scan continues unauthenticated with no clear error.
- **Required fix:** validate `login_url` before use: it must be a path starting with `/` or an absolute `http(s)` URL on the target origin. A drive-letter path (`C:/...`), a backslash path, or an off-origin URL → a clear error naming the offending value and, for the drive-letter case, a hint that the shell rewrote it (use `MSYS_NO_PATHCONV=1` or `//login/`). The CLI prints the error and exits non-zero; library callers get `AuthResult(success=False, message=...)`.
- **Acceptance:** `C:/Program Files/Git/login/`, `..\login`, and `http://other.example/login` are rejected with messages containing the value; `/login/` and `http://127.0.0.1:5103/login/` (target origin) are accepted; the CLI exit code is non-zero on a rejected value.

---

## B26 — Benchmark harness (measure precision and recall, 2026-10-15)

Goal: replace "it seems to work" with numbers that can be re-run after every change and quoted in the paper.

### AUD-69 · Reproducible precision/recall benchmark against the built-in testbeds
- **Files:** `benchmark/__init__.py`, `benchmark/run_benchmark.py`, `benchmark/metrics.py`, `benchmark/ground_truth/testbed1.json`, `benchmark/ground_truth/testbed2.json`, `benchmark/README.md`, `main.py` (only if a subcommand is wanted; `python -m benchmark.run_benchmark` is enough)
- **Problem:** there is no single command that scans the known-vulnerable apps and reports how many planted vulnerabilities were found and how many reported findings were false. Numbers quoted so far came from ad-hoc runs.
- **Required fix:** add a benchmark package. A ground-truth file lists, per target, every planted item as `{"id", "vuln_type", "endpoint", "classification": "real" | "decoy"}` (derive testbed1 from the comments in `testbed/app.py`, testbed2 from the matrix in the `testbed/app2.py` docstring). `metrics.py` matches reported findings to truth items by `(vuln_type, normalized endpoint)` (query strings stripped; `{id}`-style placeholders and numeric path segments normalized the same way `core/models.py` does) and computes: true positives (real items matched), false negatives (real items not matched), false positives (findings that match a `decoy` item **or** match nothing in the truth file and are not in the file's `informational` list of accepted extra findings, e.g. missing security headers, open ports), precision, recall, F1, and per-target scan duration. `run_benchmark.py` starts the requested built-in testbed on a free loopback port in a thread or subprocess (never any non-loopback host; `is_target_allowed` is not bypassed), runs a real scan through `core.pipeline.run_scan_pipeline` (full profile, nmap and nikto excluded so the run does not need them), and writes `benchmark/results/<UTC date>.json` plus a markdown table to stdout. testbed2 is scanned with its login credentials. Results files are git-ignored except a committed `benchmark/RESULTS.md` that the runner can regenerate with `--write-markdown`.
- **Acceptance:** unit tests for `metrics.py` with synthetic findings cover: a true positive; a decoy hit counted as a false positive; an unmatched non-informational finding counted as a false positive; an informational finding ignored; endpoint normalization (`/api/users/1` vs `/api/users/{id}`); precision/recall/F1 values, including the empty-findings and empty-truth edge cases (no division by zero). A test starts testbed1 and testbed2, runs the benchmark, and asserts: zero false positives, recall at least 0.85 on each, and a results JSON containing `precision`, `recall`, `f1`, `duration_seconds` per target. The runner exits non-zero when a target is not loopback.

### AUD-70 · Ground truth and runner support for external intentionally-vulnerable apps
- **Files:** `benchmark/ground_truth/pygoat.json`, `benchmark/ground_truth/vampi.json`, `benchmark/ground_truth/vulpy.json`, `benchmark/run_benchmark.py`, `benchmark/README.md`
- **Problem:** the external apps used for manual testing (pygoat, VAmPI, vulpy) have no recorded ground truth, so their results cannot be compared between runs.
- **Required fix:** add ground-truth files for the three apps (real items as documented by each project; mark items the scanner cannot reasonably detect, such as logic flaws behind multi-step flows, with `"detectable": false` so they are listed but excluded from recall). Extend the runner with `--url URL --truth NAME [--login-user U --login-pass P --login-url PATH]` to benchmark an already-running local instance, with the same loopback-only rule. Document in `benchmark/README.md` how to start each app locally and the exact command; the apps themselves are not vendored.
- **Acceptance:** a schema test validates every ground-truth file (required keys, allowed `classification` values, no duplicate ids, endpoints start with `/`). The runner rejects a non-loopback `--url` with a clear message and non-zero exit, and reports a clear error (not a traceback) when the URL is unreachable. A test runs `--url` against a locally started testbed1 with `--truth testbed1` and gets the same metrics as the built-in mode.

---

## B27 — Remove known limitations

### AUD-71 · Login-form SQL injection probes are fragile against apps that answer unexpectedly
- **Files:** `plugins/sqli_plugin.py` (`_test_login_endpoints`)
- **Problem:** against vulpy (`/user/login`), a single fresh-client probe sees the SQL status differential (normal → 200, lone `'` → 500, `''` → 200), but the plugin's full login-probe sequence does not report it: its many rapid POSTs to several candidate field pairs and encodings meet spurious 404/empty responses, and the differential is evaluated on those. Findings must not depend on how many other probes ran first.
- **Required fix:** make the differential robust: (1) run the status-differential check for the discovered form's real field names **before** the bypass-payload loop and before trying the hard-coded alternative pairs (`email`, `user`/`pass`); (2) if a control or probe response is `None`, 404, 429 or 5xx *for the control value*, re-fetch the form with a GET and retry that probe once before giving up; (3) evaluate each differential on three probes made back to back with the form warmed up, never mixing responses from different sequences; (4) cap total login-endpoint requests per scan with a named constant in `config.py` so the sequence stays small.
- **Acceptance:** a fixture app that (a) answers POST only with 404 unless the form was fetched within the last 2 seconds in the same session, (b) returns 429 for the 6th POST in any 3-second window, and (c) otherwise returns 500 for an odd number of `'` in any field and 200 otherwise, is detected: exactly one login-form SQLi finding is reported on the real field. A fixture whose login always returns 500 is not reported, and one that returns 500 for every special character including `''` is not reported. The total number of POSTs the login testing sends to the fixture is at most the new cap. Existing SQLi tests pass unchanged.

### AUD-72 · The heaviest end-to-end test is timing-sensitive
- **Files:** `test_b25_regression_testbed.py`, `testbed/app2.py` (only if needed), `config.py` constants only if needed
- **Problem:** `test_app2_full_scan_with_credentials` takes 70 to 300 seconds depending on machine load and has needed a retry in about half of the recent parallel runs. When it runs slowly, request budgets and per-plugin timeouts trip and findings are missed.
- **Required fix:** find which timeouts, deadlines or pacing delays dominate this test (instrument rather than guess) and make the test deterministic: patch the configuration constants it depends on (request pacing, per-request and scan deadlines, crawler time cap) to values that cannot trip on a slow machine, restrict the scan to the plugins the assertions need, and remove any wall-clock assertion. It must keep every existing assertion (each planted vulnerability exactly once, decoys absent, no off-origin requests, `coverage.degraded` false).
- **Acceptance:** the module runs in under 60 seconds when run alone on an idle machine; it contains no assertion on elapsed wall-clock time; a short script `tools/stress_test_module.py MODULE N` (added in this issue) runs a unittest module N times while four busy-loop worker processes load the CPU and prints the pass count, and `python tools/stress_test_module.py test_b25_regression_testbed 5` reports 5 of 5 passes (the handoff must include that output).

---

## B28 — CI/CD output and authenticated dashboard scans

### AUD-73 · SARIF and JUnit output for CI pipelines
- **Files:** `reports/sarif.py` (new), `reports/junit.py` (new), `main.py` (`scan` options `--sarif PATH` and `--junit PATH`), `.github/workflows/autosec-scan.example.yml` (new, an example workflow; the real CI file is untouched), `README.md`
- **Problem:** the CLI can fail a build with `--fail-on` but produces only JSON and HTML, so findings cannot appear in GitHub code scanning or in a CI test report.
- **Required fix:** `--sarif PATH` writes a SARIF 2.1.0 file: one `run` with `tool.driver.name` `AutoSecAudit`, a `rules` entry per distinct `vuln_type` (id, short description, CWE in `properties` when known), and one `result` per finding with `ruleId`, `level` (Critical/High → `error`, Medium → `warning`, Low/Info → `note`), `message.text`, and a `locations` entry whose `artifactLocation.uri` is the finding's endpoint and `properties` carrying severity and confidence. `--junit PATH` writes JUnit XML: one `testcase` per finding, with a `failure` element for findings at or above the `--fail-on` threshold (all findings when no threshold is set) and a passing testcase otherwise. Neither file may contain scan credentials, cookies or response bodies beyond the existing finding evidence limit. The example workflow starts the app under test from a service container or step, runs the scan against it on loopback or a private address, uploads the SARIF file, and fails on the chosen threshold; the README documents both options with a short example.
- **Acceptance:** tests build findings of every severity and assert: SARIF has `version` `2.1.0`, a `$schema`, exactly one run, rule ids unique, every result's `ruleId` exists in `rules`, level mapping as specified, and parses as valid JSON; the JUnit file is well-formed XML (parse with `xml.etree`), `tests` equals the finding count and `failures` equals the number at or above the threshold; an authenticated scan's password and session cookie values do not appear in either file; running the CLI with both options on a mock scan writes both files and the existing JSON/HTML outputs are unchanged.

### AUD-74 · Harden the dashboard's existing authenticated-scan fields
- **Files:** `ui/app.py` (the "Authenticated Deep Scan (Auto-Login)" section of the scan form and `/scan/async`), `core/authenticator.py` (`validate_login_url`, read only), report generation if a credential could reach it
- **Problem:** the scan form already has optional `login_user`, `login_pass` and `login_url` fields and `/scan/async` passes them to the pipeline, but: (1) the three inputs have no `<label>` or `aria-label` (screen readers announce them as unnamed, found by an accessibility check); (2) `login_url` is not validated with `validate_login_url`, so a drive-letter, backslash or off-origin value is accepted and the scan silently continues unauthenticated; (3) nothing proves the password never reaches the job record, the `/scan/status` and `/scan/progress` payloads, saved reports (JSON, HTML, PDF) or logs.
- **Required fix:** give each input a visible or `aria-label` name and `autocomplete="off"` on the password; validate `login_url` against the target origin with `core.authenticator.validate_login_url` and return HTTP 400 with a JSON error that names the offending value; make sure the password is used for that job only and is never stored or logged: not in the scan job dict, status/progress payloads, saved report JSON/HTML/PDF, error messages or any log level. A failed login must be visible to the user as an auth-failure status in the report (`auth_status`), not a silent unauthenticated scan. The section stays optional, and its fields are ignored in demo mode.
- **Acceptance:** tests with a loopback fixture app that has a CSRF-protected form login and one page visible only when logged in: an authenticated dashboard scan reports a finding on the protected page that an unauthenticated scan does not; a wrong password completes with an auth-failure status shown in the report; an off-origin or drive-letter `login_url` is rejected with HTTP 400 and the value in the message; a distinctive password string appears in none of: the job record, the status and progress responses, the report JSON, the report HTML, the PDF text, and captured log output; the rendered form has a label or `aria-label` on every one of the three inputs.

---

## B29 — GraphQL coverage

### AUD-75 · A GraphQL scanner plugin (read-only)
- **Files:** `plugins/graphql_plugin.py` (new), `plugins/api_abuse_plugin.py` (move the existing introspection check into the new plugin or leave it and avoid duplicate findings), `core/engine.py`/plugin loading as needed, every place that states the plugin count (search for `19 plugins`, `19 PLUGINS`, `19 scanner`, `19 dynamic` in `README.md`, `CLAUDE.md`, `ui/app.py`, tests and docs, and update them to the new count), `config.py` for profile membership if profiles list plugins by name
- **Problem:** GraphQL APIs are common and the scanner has only a single introspection check inside the API-abuse plugin. It never probes the arguments of GraphQL queries for injection.
- **Required fix:** add `GraphQLScanner(BaseScanner)` implementing the standard plugin methods (including `_get_mock_output`). It finds a GraphQL endpoint by sending `{"query":"{__typename}"}` as a POST to `/graphql`, `/api/graphql`, `/graphiql`, `/query`, `/v1/graphql` and any discovered endpoint whose path contains `graphql`; reports introspection enabled (once, deduplicated with any existing finding); and, when introspection is available, extracts **query-type** fields that take String/ID arguments and probes each such argument with the existing benign SQLi error-signature and paired status-differential checks and the XSS reflection check, using the same baseline-comparison verification as the other plugins. Safety rules: only `query` operations are ever sent, never `mutation` or `subscription`; requests go to the target origin only; a cap of 20 arguments and 6 payloads per argument; no depth, alias or batching abuse requests. Register the plugin in the profiles that include API testing and update the stated plugin counts everywhere they appear.
- **Acceptance:** a fixture GraphQL-style server (a Flask route that accepts JSON `{query, variables}`, answers `__typename` and a canned introspection result, and implements two query fields in plain Python with no GraphQL library): one field with a SQL-error leak on a quote, one that reflects its argument unescaped inside an HTML-typed string, one that echoes the argument safely. The scan reports the SQLi on the first and the XSS on the second exactly once each, and nothing for the safe field. A server-side log shows that no request contained the word `mutation` or `subscription` operations and that every request went to the fixture origin. A target with no GraphQL endpoint produces no findings and at most 6 endpoint-discovery requests. Introspection disabled → a single "GraphQL endpoint found" informational finding and no argument probing. The stated plugin count matches the number of plugin classes loaded by the engine (add a test that asserts the README, CLAUDE.md and UI badge numbers equal that count).

---

## Deferred (not in the loop — do after B29)
- Move the ~2,000 lines of inline HTML in `ui/app.py` into `ui/templates/`.
- Replace per-plugin `_get_mock_output` with a recorded-fixture replay layer.
- Move scan jobs to a proper worker/task queue behind a WSGI server.
