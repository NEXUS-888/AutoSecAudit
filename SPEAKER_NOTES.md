# Speaker Notes - AutoSecAudit 2.0 Presentation

---

## Slide 1: Languages & Tools Used

### Opening (30 seconds)
"Good morning/afternoon. Today I'll present AutoSecAudit 2.0, an intelligent security auditing framework I built."

### Languages & Tools (1 minute)
"This project uses Python 3.10 as the primary language. I chose Python because of its rich ecosystem for security tools and easy integration with external APIs.

For the web interface, I used Flask - it's lightweight and perfect for this kind of tool. Jinja2 handles the HTML report templating.

We integrate with two security tools: Nmap for port scanning and service detection, and Nikto for web vulnerability scanning.

For intelligence, we query the NVD (National Vulnerability Database) and CIRCL APIs to get CVE details and CVSS scores.

Finally, Docker containerizes everything for easy deployment anywhere."

**Key point to emphasize:** "Everything runs in Docker, so no installation headaches."

---

## Slide 2: Implementation

### Architecture Overview (1 minute)
> "Let me walk you through how the system works. It has 4 main stages."

```
User Input → Plugin System → Intelligence → Reports
```

**Say:** "The user provides a target URL or IP. The engine loads all plugins, runs them in parallel, collects results, applies intelligence, and generates reports."

### Component 1: Plugin System (1.5 minutes)
> "I created an abstract BaseScanner class. Any scanner must inherit from it and implement 3 methods:
- configure() - set the target
- run() - execute the scanner
- parse_output() - return findings in standard format"

**Demo point:** "This makes it easy to add new scanners - just create a new class that inherits from BaseScanner."

### Component 2: Core Engine (1 minute)
> "The Engine is the brain. It:
- Loads plugins dynamically from the plugins folder
- Uses ThreadPoolExecutor to run plugins in parallel
- Collects standardized JSON from each plugin"

**Key point:** "Parallel execution makes scanning faster."

### Component 3: Plugins (1 minute)
> "We built 3 plugins:
- NmapPlugin - runs nmap, parses XML output, extracts ports and services
- NiktoPlugin - runs nikto, parses text output, extracts vulnerabilities
- MockPlugin - for testing without real tools"

**Say:** "In mock mode, we can demo without installing nmap/nikto."

### Component 4: Intelligence Layer (2 minutes)
> "After scanning, we process findings through 4 intelligence modules:

1. **Correlator** - Groups findings by host:port. If Nmap finds port 80 AND Nikto finds Apache vulnerability, we link them.

2. **Enricher** - Queries NVD API. If a finding has a CVE ID, we fetch the CVSS score and references.

3. **Compliance Mapper** - Maps each finding to OWASP Top 10 2021. For example, XSS maps to A03:2021 Injection.

4. **Delta Analyzer** - Compares current scan with previous scan to show what was fixed or is new."

**Key point:** "This transforms raw scanner output into actionable intelligence."

### Component 5: Reports (1 minute)
> "Finally, Jinja2 templates generate professional HTML dashboards with:
- Executive summary (counts by severity)
- Delta analysis (new/fixed issues)
- Detailed findings with CVE, CVSS, OWASP tags
- Raw output for technical details"

---

## Slide 3: Conclusion

### What Was Delivered (1 minute)
> "In summary, I built:
- A modular, plugin-based architecture
- Integration with Nmap and Nikto
- Automated CVE enrichment and OWASP mapping
- Delta comparison between scans
- Professional HTML reports
- Docker containerization"

### Project Stats (30 seconds)
- 10 Python modules
- 25 files total
- ~1800 lines of code

### How to Use (1 minute)
> "To run this project:

With Docker:
  docker-compose up -d autosec

Or locally:
  pip install -r requirements.txt
  python main.py scan 192.168.1.1"

**Demo if time allows:** Show the web UI or run a quick scan.

### Closing (30 seconds)
> "The full source code is on GitHub. Thank you for your time. Any questions?"

---

## Tips for Delivery

1. **Practice the flow** - Know the order: Input → Plugins → Intelligence → Reports

2. **Demo beats slides** - If possible, show a quick scan running live

3. **Emphasize modularity** - "Adding a new scanner only requires creating a new plugin class"

4. **Show the output** - Have a sample report ready to show

5. **Keep it simple** - Don't get lost in technical details; focus on what it does

---

## Possible Q&A Answers

**Q: How do you add a new scanner?**
A: "Create a class that inherits from BaseScanner, implement the 3 methods, and it automatically works with the engine."

**Q: What if nmap/nikto aren't installed?**
A: "The system has a mock mode that generates sample data - great for demos and development."

**Q: How does delta comparison work?**
A: "We load the previous JSON report, compare finding IDs, and categorize them as new, fixed, or unchanged."

**Q: Is this for production use?**
A: "It's a framework - you'd add your own scanners, tune rules, and integrate with your workflows."