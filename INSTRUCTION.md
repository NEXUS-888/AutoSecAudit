# AutoSecAudit 2.0 - Setup Instructions

## Prerequisites

- Python 3.10+
- Docker & Docker Compose (optional)
- nmap & nikto (for real scans, optional)

---

## Quick Start

### Option 1: Docker (Recommended)

```bash
# 1. Clone the repository
git clone https://github.com/NEXUS-888/AutoSecAudit.git
cd AutoSecAudit

# 2. Build and start the web UI
docker-compose up -d autosec

# 3. Open browser
# http://localhost:5000
```

### Option 2: Python Local

```bash
# 1. Clone and setup
git clone https://github.com/NEXUS-888/AutoSecAudit.git
cd AutoSecAudit

# 2. Install dependencies
pip install -r requirements.txt

# 3. Run CLI
python main.py scan 192.168.1.1

# 4. Or start web UI
python main.py server
# Open http://localhost:5000
```

---

## Docker Commands

### Web Interface
```bash
# Build
docker-compose build

# Run web UI
docker-compose up -d autosec

# View logs
docker-compose logs -f autosec

# Stop
docker-compose down
```

### CLI Scan
```bash
# Run scan
docker-compose run --rm autosec_cli scan 192.168.1.1

# With previous report for delta
docker-compose run --rm autosec_cli scan example.com --previous /app/data/reports/scan_20240101.json
```

### Manual Docker
```bash
# Build image
docker build -t autosecaudit .

# Run web UI
docker run -p 5000:5000 autosecaudit server

# Run CLI scan
docker run -v $(pwd)/data:/app/data autosecaudit scan 192.168.1.1
```

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `AUTOSEC_MOCK_MODE` | `true` | Use mock data (set `false` for real scans) |
| `AUTOSEC_LOG_LEVEL` | `INFO` | Logging level |
| `AUTOSEC_THREAD_COUNT` | `4` | Parallel plugin threads |

---

## Troubleshooting

### Port 5000 already in use
```bash
# Change port in docker-compose.yml
ports:
  - "5001:5000"
```

### nmap/nikto not found
- These tools are optional in Docker (pre-installed in Dockerfile)
- For local Python, install manually: `nmap`, `nikto`
- Or use MOCK_MODE (enabled by default)

### Permission denied on data folder
```bash
sudo chown -R $USER:$USER data/
```

---

## Files Generated

- `data/reports/scan_*.json` - JSON scan results
- `data/reports/report_*.html` - HTML reports