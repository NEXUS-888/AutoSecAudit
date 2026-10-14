# AutoSecAudit 2.0 — Assistant Guidelines & Project Manual

## Project Overview
AutoSecAudit is an automated Dynamic Application Security Testing (DAST) framework, attack simulator, and AI remediation platform built with Python. It features 19 dynamic vulnerability scanners, a web crawler, statistical timing verification, plain-English executive danger analysis, multi-framework code remediation recipes, an interactive Flask dashboard with SSE progress streaming, and a Model Context Protocol (MCP) server.

## Tech Stack
- **Language**: Python 3.10+ (type annotations, dataclasses)
- **Web Dashboard**: Flask, Werkzeug, Jinja2
- **Networking & HTTP**: `requests`, `urllib3`
- **Concurrency**: `concurrent.futures.ThreadPoolExecutor`, `threading`, `queue.Queue`
- **Reporting**: Jinja2 (HTML), ReportLab (PDF), JSON
- **Intelligence & Compliance**: OWASP Top 10 2021, CWE, PCI-DSS v4.0, NIST NVD / CIRCL CVE APIs
- **Protocol**: Model Context Protocol (MCP) server over STDIO (JSON-RPC 2.0)

## Core Architecture & Key Directories
- `main.py`: CLI and interactive console entry point.
- `config.py`: Centralized configuration, timeouts, environment variables, scan profiles.
- `mcp_server.py`: STDIO MCP server for AI coding assistants (Cursor, Claude Code, Antigravity).
- `core/`: Scanning engine, crawler, and core runtime utilities.
  - `engine.py`: Plugin loader, multi-threaded scanner dispatch, report aggregator.
  - `crawler.py`: Target web crawler discovering links, forms, JS endpoints.
  - `models.py`: Data contracts (`Finding`, `ScanResult`, `Report`).
  - `politeness.py`: Adaptive request pacing, jitter, exponential backoff (429/503).
  - `timing.py`: Statistical latency calibration and 2-phase timing verification.
  - `fuzzer.py`: Deep recursive JSON body leaf mutator.
  - `utils.py`: Target safety allowlist (RFC 1918, localhost, practice targets only).
  - `openapi.py`: Swagger / OpenAPI 2.0 and 3.0+ endpoint importer.
- `intelligence/`: Enrichment and decision engines.
  - `danger_engine.py`: Plain-English real-world danger translation and letter grading (A+ to F).
  - `recipes.py`: Code fix generation (Node.js, Python, Nginx, WAF rules, Markdown dev tickets).
  - `compliance.py`: OWASP Top 10, CWE, and PCI-DSS compliance mapper.
  - `correlator.py`: Finding deduplication and host:port clustering.
  - `enricher.py`: CVE / CVSS enrichment via external APIs.
  - `delta.py`: Differential scan analysis (New, Fixed, Unchanged).
  - `remediation.py`: Step-by-step remediation advice by vulnerability type.
- `plugins/`: 19 dynamic attack scanner plugins extending `BaseScanner`.
  - `base_plugin.py`: Abstract base class with baseline verification and safe request methods.
- `reports/`: HTML and PDF report generator (`generator.py`) and Jinja2 templates.
- `ui/`: Flask web application (`app.py`), static assets, and SSE event streaming.
- `testbed/`: Isolated vulnerable testbed sandbox application (`app.py`).
- `data/reports/`: Saved JSON, HTML, and PDF scan artifacts.

## Development & Testing Commands
- **Run Full Test Suite** (~490 tests; runs test modules in parallel, ~2 min):
  ```bash
  python run_tests.py            # parallel (default)
  python run_tests.py --serial   # one process, for debugging
  ```
- **Run Single Test Module**:
  ```bash
  python -m unittest test_engine.py
  python -m unittest test_sse.py
  ```
- **Start Web Dashboard** (Port 5000):
  ```bash
  python main.py server --real   # or --mock for presentation mode
  ```
- **Run CLI Scan**:
  ```bash
  python main.py scan http://localhost:8080 --profile full --mock
  ```
- **Launch Vulnerable Testbed Sandbox** (Port 8080):
  ```bash
  python main.py testbed --port 8080
  ```
- **Start MCP Server**:
  ```bash
  python mcp_server.py
  ```

## Code Style & Conventions
- **Naming**: `snake_case` for functions and variables; `PascalCase` for classes (e.g. `SQLiScanner`, `BaseScanner`).
- **Plugins**: All scanners must inherit from `plugins.base_plugin.BaseScanner` and implement `configure()`, `run()`, `parse_output()`, `_get_tool_name()`, and `_get_mock_output()`.
- **False Positive Resistance**: Scanners must use baseline comparison (`_get_baseline()` / `_verify_against_baseline()`) or statistical timing (`_verify_timing()`) before asserting high confidence.
- **Safety**: Never bypass `is_target_allowed()` checks in `core/utils.py`. Scans must be restricted to authorized private or local testing environments.
- **Git Commits**: Follow Conventional Commits format (e.g., `feat(scanning): ...`, `fix(engine): ...`, `docs: ...`).
