# AutoSecAudit 2.0 - Project Presentation

---

## Slide 1: Languages & Tools Used

### Programming Languages
- **Python 3.10+** - Primary language

### Frameworks & Libraries
| Library | Purpose |
|---------|---------|
| Flask | Web UI framework |
| Jinja2 | HTML template engine |
| Requests | HTTP API calls (CVE enrichment) |
| PyYAML | Configuration |

### Security Tools Integrated
- **Nmap** - Port scanning & service detection
- **Nikto** - Web vulnerability scanning

### External APIs
- **NVD API** - CVE data & CVSS scores
- **CIRCL API** - CVE enrichment

### DevOps Tools
- **Docker** - Containerization
- **Docker Compose** - Multi-service orchestration
- **GitHub** - Version control

---

## Slide 2: Implementation

### Architecture
```
Input Module → Plugin System → Intelligence Layer → Reports
```

### Components Built

| Component | File | Description |
|-----------|------|-------------|
| Base Plugin | `plugins/base_plugin.py` | Abstract scanner class |
| Core Engine | `core/engine.py` | Thread-based parallel execution |
| Nmap Plugin | `plugins/nmap_plugin.py` | XML port scanning |
| Nikto Plugin | `plugins/nikto_plugin.py` | Web vulnerability scan |
| Correlator | `intelligence/correlator.py` | Group related findings |
| Enricher | `intelligence/enricher.py` | CVE data from APIs |
| Compliance | `intelligence/compliance.py` | OWASP Top 10 mapping |
| Delta | `intelligence/delta.py` | Compare scan results |
| Report Gen | `reports/generator.py` | Jinja2 HTML reports |
| Web UI | `ui/app.py` | Flask interface |

### Key Features
- Plugin-based extensible architecture
- Parallel scanning with ThreadPoolExecutor
- Mock mode for development/demo
- Delta comparison between scans
- Automated OWASP compliance mapping

---

## Slide 3: Conclusion

### What Was Delivered
- Modular, plugin-based security auditing framework
- Integration with Nmap & Nikto scanners
- CVE enrichment via NVD/CIRCL APIs
- OWASP Top 10 2021 compliance mapping
- Delta reporting for scan comparison
- Professional HTML dashboard reports
- Flask web interface
- Docker containerization

### Project Structure
```
AutoSecAudit/
├── main.py              # CLI
├── core/                # Engine & models
├── plugins/             # Scanners
├── intelligence/        # Analysis
├── reports/             # Generator
├── ui/                  # Flask app
├── Dockerfile
└── docker-compose.yml
```

### GitHub Repository
**https://github.com/NEXUS-888/AutoSecAudit**

### Usage
```bash
# Docker (Recommended)
docker-compose up -d autosec

# Python Local
pip install -r requirements.txt
python main.py server
```

---

*Thank you!*
