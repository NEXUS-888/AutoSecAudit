# AutoSecAudit 2.0

An intelligent, extensible security auditing framework that scans web applications, aggregates findings from multiple tools, enriches them with external intelligence, performs correlation and compliance mapping, and generates structured HTML reports.

---

## Features

- **Plugin-Based Architecture** - Easily add new scanners
- **Multi-Tool Support** - Nmap, Nikto, and custom plugins
- **Intelligence Layer** - CVE enrichment, correlation, OWASP mapping
- **Delta Reporting** - Compare scans over time
- **HTML Dashboards** - Professional security reports
- **Web UI** - Flask-based interface
- **Docker Support** - Containerized deployment
- **Mock Mode** - Development without tools

---

## Architecture

```
AutoSecAudit/
├── main.py              # CLI entry point
├── core/
│   ├── engine.py      # Thread-based scanning engine
│   ├── models.py     # Data models
│   └── utils.py      # Utilities
├── plugins/
│   ├── base_plugin.py   # Abstract base class
│   ├── nmap_plugin.py   # Nmap scanner
│   ├── nikto_plugin.py  # Nikto scanner
│   └── mock_plugin.py   # Test plugin
├── intelligence/
│   ├── correlator.py    # Findings correlation
│   ├── enricher.py      # CVE enrichment
│   ├── compliance.py   # OWASP mapping
│   └── delta.py         # Delta analysis
├── reports/
│   ├── generator.py     # HTML generation
│   └── templates/      # Jinja2 templates
└── ui/
    └── app.py          # Flask web interface
```

---

## Quick Start

### Docker (Recommended)

```bash
git clone https://github.com/NEXUS-888/AutoSecAudit.git
cd AutoSecAudit
docker-compose up -d autosec
# Open http://localhost:5000
```

### Python Local

```bash
git clone https://github.com/NEXUS-888/AutoSecAudit.git
cd AutoSecAudit
pip install -r requirements.txt
python main.py scan 192.168.1.1
```

---

## Usage

### CLI Commands

```bash
# Run security scan
python main.py scan 192.168.1.1
python main.py scan example.com
python main.py scan example.com --previous old_report.json

# List plugins
python main.py plugins

# Start web UI
python main.py server
```

### Web Interface

1. Start server: `python main.py server` or `docker-compose up -d autosec`
2. Open http://localhost:5000
3. Enter target URL/IP
4. Optional: Upload previous report for delta comparison
5. View and download reports

---

## Plugin Development

Create a new plugin by extending `BaseScanner`:

```python
from plugins.base_plugin import BaseScanner

class MyScanner(BaseScanner):
    def configure(self, target: str) -> None:
        self.target = target

    def run(self) -> None:
        # Run your scanner tool
        pass

    def parse_output(self) -> dict:
        return {
            "tool_name": "my_scanner",
            "findings": [
                {
                    "id": "MY-001",
                    "title": "Issue Found",
                    "severity": "High",
                    "host": self.target,
                    "port": 80,
                    "description": "Details here",
                    "raw_output": "..."
                }
            ]
        }

    def _get_tool_name(self) -> str:
        return "my_tool"

    def _get_mock_output(self) -> dict:
        return self.parse_output()
```

---

## Configuration

Environment variables (or in `config.py`):

| Variable | Default | Description |
|----------|---------|-------------|
| `AUTOSEC_MOCK_MODE` | `true` | Use mock data |
| `AUTOSEC_LOG_LEVEL` | `INFO` | Logging level |
| `AUTOSEC_THREAD_COUNT` | `4` | Parallel threads |
| `AUTOSEC_NMAP_PATH` | `nmap` | Nmap binary path |
| `AUTOSEC_NIKTO_PATH` | `nikto` | Nikto binary path |

---

## Output Format

### JSON Report
```json
{
  "target": "http://192.168.1.1",
  "timestamp": "2024-01-01 12:00:00",
  "summary": {
    "total": 10,
    "critical": 2,
    "high": 3,
    "medium": 3,
    "low": 2
  },
  "all_findings": [...]
}
```

### CSV Report (coming soon)

---

## Intelligence Features

### CVE Enrichment
- Queries NVD API for CVSS scores
- Queries CIRCL API for additional data
- Caches results for performance

### Correlation
- Groups findings by host:port
- Links related issues across tools

### Compliance Mapping
- Maps to OWASP Top 10 2021
- Auto-tags findings with categories

### Delta Analysis
- Compares current vs previous scan
- Shows new/fixed/unchanged issues

---

## Docker Commands

```bash
# Build image
docker build -t autosecaudit .

# Run web UI
docker run -p 5000:5000 autosecaudit server

# Run CLI scan
docker run -v $(pwd)/data:/app/data autosecaudit scan 192.168.1.1

# Using docker-compose
docker-compose up -d autosec
docker-compose run --rm autosec_cli scan 192.168.1.1
```

---

## Requirements

- Python 3.10+
- flask>=2.3.0
- jinja2>=3.1.0
- requests>=2.28.0
- pyyaml>=6.0

Optional (for real scans):
- nmap
- nikto

---

## License

MIT License

---

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add your plugin/improvement
4. Submit a pull request
