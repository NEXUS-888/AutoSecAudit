# AutoSecAudit Precision & Recall Benchmark Suite

A reproducible evaluation harness that measures vulnerability detection precision, recall, and F1 score against ground-truth vulnerability matrices across both built-in sandboxes and external vulnerable web applications.

---

## 1. Ground Truth Schema

Every benchmark target has a ground-truth definition stored in `benchmark/ground_truth/<target>.json`.

Each file contains:
- `target`: Target identifier (e.g. `testbed1`, `testbed2`, `pygoat`, `vampi`, `vulpy`).
- `description`: Overview of the benchmark target and reference repository.
- `items`: List of planted security vectors with:
  - `id`: Unique identifier (e.g. `tb1-sqli-search`, `vampi-sqli-user`).
  - `vuln_type`: Vulnerability category matching `core.models.VulnType` (e.g. `sqli`, `xss`, `ssti`, `command_injection`, `idor`, `open_redirect`, `path_traversal`, `secret_exposure`, `auth`, `api_abuse`, `insecure_cookie`, `csrf`).
  - `endpoint`: Path starting with `/` (path placeholders normalized to `{id}` or `{placeholder}`).
  - `classification`: Either `"real"` (genuine vulnerability) or `"decoy"` (safe pattern designed to test suppression of false alarms).
  - `source`: Upstream source reference (route definition or file citation).
  - `detectable` (optional, default `true`): If `false`, marks vulnerabilities that standard DAST tools cannot reasonably detect without human business logic or multi-step account recovery flows. These items are tracked but excluded from the recall denominator.
- `informational`: List of accepted extra findings (e.g. `misconfig` for missing HTTP security headers or server banner disclosure, `port_scan`, `ssl_tls`) that do not count as false positives.

---

## 2. Running Built-in Benchmarks

To run the automated benchmark against the built-in testbed sandboxes (`testbed1` and `testbed2`):

```bash
# Run both testbeds and print markdown results
python -m benchmark.run_benchmark

# Run a single built-in testbed
python -m benchmark.run_benchmark --target testbed1
python -m benchmark.run_benchmark --target testbed2

# Regenerate committed benchmark/RESULTS.md
python -m benchmark.run_benchmark --write-markdown
```

The runner:
1. Starts the built-in testbed on an ephemeral loopback port (`127.0.0.1:0`).
2. Scans the testbed using `core.pipeline.run_scan_pipeline` (`full` profile; Nmap and Nikto excluded to avoid external binary dependencies).
3. Compares findings against the ground truth.
4. Outputs a Markdown summary table to stdout and writes JSON results to `benchmark/results/<UTC-date>.json`.

---

## 3. Benchmarking External Intentionally-Vulnerable Apps

External vulnerable applications are not vendored. To benchmark an external target, start it locally via Docker or native Python, then point the runner to its loopback address using `--url` and `--truth`.

> **Note**: For safety, the benchmark runner strictly enforces loopback-only scanning (`127.0.0.1` or `localhost`). Remote hosts are rejected.

### OWASP PyGoat

1. **Start PyGoat locally**:
   ```bash
   docker run --rm -p 8000:8000 pygoat/pygoat:latest
   ```
2. **Account setup**:
   If unauthenticated, register a user account at `http://127.0.0.1:8000/register` (e.g. username `testuser`, password `testpass123`).
3. **Execute Benchmark**:
   ```bash
   python -m benchmark.run_benchmark --url http://127.0.0.1:8000 --truth pygoat --login-user testuser --login-pass testpass123 --login-url /login/
   ```

### VAmPI (Vulnerable REST API)

1. **Start VAmPI locally**:
   ```bash
   docker run --rm -p 5000:5000 erev0s/vampi:latest
   ```
2. **Execute Benchmark**:
   ```bash
   python -m benchmark.run_benchmark --url http://127.0.0.1:5000 --truth vampi
   ```

### OWASP Vulpy

1. **Start Vulpy locally**:
   ```bash
   docker run --rm -p 5001:5000 fportantier/vulpy
   ```
   *(Or clone https://github.com/fportantier/vulpy and run `python vulpy.py`)*
2. **Account setup**:
   Log in with built-in credentials `user` / `user` (or create an account on `/user/login`).
3. **Execute Benchmark**:
   ```bash
   python -m benchmark.run_benchmark --url http://127.0.0.1:5001 --truth vulpy --login-user user --login-pass user --login-url /user/login
   ```

---

## 4. Metrics Calculation

- **True Positives (TP)**: Number of detectable real truth items matched by at least one reported finding.
- **False Negatives (FN)**: Number of detectable real truth items missed by the scanner.
- **False Positives (FP)**: Reported findings that match a `decoy` item or match nothing in the truth file and are not in `informational`.
- **Precision**: `TP / (TP + FP)` (1.0 if zero findings expected and zero reported).
- **Recall**: `TP / (TP + FN)` (1.0 if zero truth items expected).
- **F1 Score**: Harmonic mean of Precision and Recall (`2 * (P * R) / (P + R)`).
