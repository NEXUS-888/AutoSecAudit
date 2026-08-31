# AutoSecAudit 2.0 - Phase 3 Presentation Guide

**Project Title:** AutoSecAudit: An Extensible Multi-Scanner Orchestration Engine with Automated Compliance Mapping and Delta Auditing for DevSecOps  
**Institution:** Don Bosco Institute of Technology, Bengaluru (Autonomous under VTU, Accredited by NBA & NAAC with 'A' Grade)  
**Department:** Department of Computer Science & Engineering  
**Students:** Kodi Vishruth Aithal (1DB23CS104), Thilak N (1DB23CS229), Vinaya Kumar B (1DB23CS244), Vishal Gowda B (1DB23CS246)  
**Faculty Guide:** Ms. Ranjitha R (Assistant Professor, Dept of CSE)  
**Presentation Deck:** `Presentation/AutoSecAudit - Phase 3 Presentation.pptx` (22 Widescreen Slides, Visual Architecture Diagrams, Website Result Photos, 16pt Font Hierarchy, Navy/Neon Green Theme)

---

## Visual & Non-Text Layout Highlights

- **Embedded Phase 2 Diagrams:**
  - **Slide 8:** Embedded with the **Proposed Model & Execution Flowchart diagram** from Phase 2.
  - **Slide 9:** Embedded with the **System Design & Component Architecture diagram** from Phase 2.
- **Dedicated Website Result Photo Showcase:**
  - **Slide 16:** Features a dedicated 2×2 visual grid with screenshot frames for your live website scan results:
    1. *Target Web Configuration & Scan Launch*
    2. *Real-Time SSE Scan Progress & Stage Telemetry*
    3. *Interactive Vulnerability Finding & Evidence Modal*
    4. *Scan Summary Dashboard & Delta Diff Verification*
- **Empirical Visual Plots:**
  - **Slide 19:** Embeds 4 publication-grade benchmark plots (Architecture Diagram, Speedup Latency Curve, Alert Noise Reduction Bar Chart, and Delta Regression Diffing).
- **Clean Single-Column Table of Contents:** Slide 2 is structured as a clear, single-column roadmap.
- **Pure Headings:** All slide titles are clean 25pt bold headers with no cluttered subtitle explanations beneath them.

---

## 22-Slide Breakdown

| Slide | Title | Visual & Content Focus |
| :--- | :--- | :--- |
| **01** | **Title Slide** | Project title, DBIT college credentials, official logos, student names & USNs, guide details. |
| **02** | **Table of Contents** | Clean single-column 12-section roadmap from foundations to implementation and results. |
| **03** | **Abstract** | Executive summary + 3 Stat Callouts (*65% Faster*, *40% Less Noise*, *80/80 Tests Passed*). |
| **04** | **Introduction** | The modern web application landscape, shift-left DevSecOps, and core vulnerability vectors. |
| **05** | **Problem Statement** | 4 critical industry pain points (Tool fragmentation, alert fatigue, no fix advice, statelessness). |
| **06** | **Objectives & Implementation Matrix** | 7-row milestone delivery matrix showing 100% completion. |
| **07** | **Literature Survey** | Comparison table reviewing 5 foundational research papers (2021–2025). |
| **08** | **System Workflow: 4-Stage Automated Pipeline** | **Visual Flowchart + 4-Stage Pipeline**: Surface Discovery $\to$ Scanning $\to$ Intelligence $\to$ Gating. |
| **09** | **System Architecture: 4 Functional Layers** | **Visual Architecture Diagram + 4 Functional Tiers**: UI, Core Engine, 14 Plugins, Intelligence/Delta. |
| **10** | **Technology Stack & Tools Used** | 6-block technology stack (Python 3.10, Flask, 14 Scanners, NIST APIs, SQLite, Docker). |
| **11** | **Implementation: Automatic Target Discovery** | Deep-dive panels on Dynamic BFS Web Crawler and OpenAPI / Swagger Ingestion. |
| **12** | **Implementation: 14 Specialized Scanner Plugins** | 4 technical domains: Recon (Nmap, Nikto), Web Attacks (SQLi, XSS), Auth/JWT, Exploits (SSRF, CmdInj). |
| **13** | **Implementation: Post-Processing Intelligence Layer**| Compound Deduplication (-40% noise), NIST NVD / CIRCL CVE scoring, and actionable code fixes. |
| **14** | **Implementation: Set-Theoretic Delta Scan Auditing**| The 3 Delta partitions: **NEW (Red)**, **FIXED (Green)**, and **UNCHANGED (Gray)** with SHA-256 tracking. |
| **15** | **Implementation: Web Dashboard & Pipeline Gating** | Real-time SSE progress streaming (5% to 100%), modal popups, and automated CI/CD `--fail-on` build blocker. |
| **16** | **Website Scan Results & Live Demonstration** | **Visual Photo Gallery**: 4 screenshot frames showcasing your live website setup, progress bar, finding modal, and delta report. |
| **17** | **Results & Performance Evaluation** | Empirical speedup benchmark table (2.84x faster) + Noise reduction table (40% clutter reduction). |
| **18** | **Implementation Verification & Test Suite** | Full 80/80 automated unit & integration test matrix passing with 100% success in 13.68s. |
| **19** | **System Architecture & Benchmark Visuals** | 4 high-resolution plots: System Architecture, Latency Speedup, Noise Reduction, Delta Regression. |
| **20** | **Conclusion & Project Deliverables** | 4 summary blocks: Unified Platform, Empirical Gains, DevSecOps Readiness, Open-Source Release. |
| **21** | **References** | Peer-reviewed IEEE literature, NIST guidelines, and OWASP standards. |
| **22** | **Thank You & Q&A** | Project repository link, DBIT department credits, team contact, and open floor for defense questions. |
