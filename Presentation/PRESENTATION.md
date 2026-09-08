# AutoSecAudit 2.0 - Phase 3 Presentation Guide

**Project Title:** AutoSecAudit: An Extensible Multi-Scanner Orchestration Engine with Automated Compliance Mapping and Delta Auditing for DevSecOps  
**Institution:** Don Bosco Institute of Technology, Bengaluru (Autonomous under VTU, Accredited by NBA & NAAC with 'A' Grade)  
**Department:** Department of Computer Science & Engineering  
**Students:** Kodi Vishruth Aithal (1DB23CS104), Thilak N (1DB23CS229), Vinaya Kumar B (1DB23CS244), Vishal Gowda B (1DB23CS246)  
**Faculty Guide:** Ms. Ranjitha R (Assistant Professor, Dept of CSE)  
**Presentation Deck:** `Presentation/AutoSecAudit - Phase 3 Presentation.pptx` (21 Widescreen Slides, Visual Flowcharts & Diagrams, 1.45–1.5 Line Spacing, Exact Template Headings, Navy/Neon Green Theme)

---

## Visual Design & Ergonomics

1. **Strict Template Headings:**  
   Directly conforms to the prescribed academic defense table of contents:
   `01 Abstract`, `02 Introduction`, `03 Problem Statement`, `04 Objectives`, `05 Literature Survey`, `06 Proposed Model`, `07 System Design`, `08 Languages & Tools Used`, `09 Implementation` (using `Implementation - [Feature]`), `10 Results` (strictly 2 pages), `11 Conclusion`, `12 References`.
2. **Visceral, Panel-Felt Problem Statement:**  
   Slide 5 articulates the genuine software engineering crisis: the Velocity Bottleneck (shipping daily vs 3-week audits), Alert Tsunami (100+ raw tool alarms with >38% duplicates), Missing Patch (finger-pointing without fix code), Regression Blindspot (zero patch memory), and Real-World Fallout ($4.45M average breach cost).
3. **Consolidated 2-Page Results:**  
   - **Page 1 (`Results - Performance & Concurrency Benchmarks`):** Side-by-side speedup table and latency curve ($k=8$ optimal, 2.84× speedup) + alert noise reduction table and bar chart (-38.2% noise reduction, 76 down to 47 unique findings on OWASP Juice Shop).
   - **Page 2 (`Results - Verification & Delta Regression`):** Full 80/80 automated benchmark test suite table (100% pass rate in 13.68s, 124 full codebase tests) + multi-build delta regression bar chart and lifecycle tracking table.
4. **Single-Column, Overflow-Free Table of Contents:**  
   Matches the uploaded reference template with neon green numbers (`#7DE545`), white text, and generous line spacing. Zero clipping.
5. **Integrated Visual Diagrams & Flowcharts (Native Dark Theme):**
   - **Slide 8:** Proposed Model Execution Flowchart (`slide_08_shape_Picture 36_24.wmf` from Phase 2).
   - **Slide 9:** System Design & Component Architecture Diagram (`slide_09_shape_Picture 43_31.wmf` from Phase 2).
   - **Slide 11:** Attack Surface Discovery Architecture Flowchart (`diagram_discovery_flow.png`).
   - **Slide 12:** 14-Scanner Modular Architecture (`diagram_plugins_matrix.png`).
   - **Slide 13:** Post-Processing Intelligence Pipeline Flowchart (`diagram_intelligence_pipeline.png`).
   - **Slide 14:** Multi-Build Delta Lifecycle Regression Chart (`diagram_delta_tracking.png`).
   - **Slide 15:** CI/CD DevSecOps Policy Gating Flowchart (`diagram_cicd_gating_flow.png`).
   - **Slide 16:** Dedicated frames for website scan results & finding modal screenshots.
   - **Slide 17:** Empirical latency and alert noise reduction plots (`diagram_latency_benchmark.png` & `diagram_noise_reduction.png`).
   - **Slide 18:** Multi-build delta diffing chart (`diagram_delta_tracking.png`).

---

## 21-Slide Structure Breakdown

| Slide | Exact Heading | Visual Asset / Right-Hand Component | Left-Hand Point-Wise Content / Purpose |
| :--- | :--- | :--- | :--- |
| **01** | **Title Slide** | Official DBIT branding & crests | Title, USNs, department, and faculty guide details. |
| **02** | **Table of Contents** | Clean vertical layout (`#7DE545` numbers) | Exact 12-section roadmap from defense template. |
| **03** | **Abstract** | Clean wide typography | Problem, solution, 2.84× speedup, 38.2% noise drop, 80/80 tests. |
| **04** | **Introduction** | Structured point-wise list | Web app critical role, shift-left need, 4 audited threat classes. |
| **05** | **Problem Statement** | High-impact point-wise list | Velocity gap, alert fatigue, lack of fix code, patch regression, $4.45M cost. |
| **06** | **Objectives** | Clean action-oriented list | 5 crisp objectives answering each problem statement directly. |
| **07** | **Literature Survey** | 5-paper baseline research table | Survey of Akinyemi, Daniel, Sonawane, Seara, and Aumpansub. |
| **08** | **Proposed Model** | **Execution Flowchart** (Phase 2 diagram) | 4-stage pipeline: Discovery $\to$ Concurrent Scanning $\to$ Intelligence $\to$ Gating. |
| **09** | **System Design** | **Architecture Diagram** (Phase 2 diagram) | 4 functional layers: UI, Concurrency Engine, 14 Plugins, Storage Tier. |
| **10** | **Languages & Tools Used** | Varied point-wise inventory | Python 3.10+, Flask, SSE, 14 Scanners, NIST NVD, SQLite, Docker. |
| **11** | **Implementation - Attack Surface Discovery** | **Discovery Flowchart** (`diagram_discovery_flow.png`) | Dynamic BFS Crawler (depth limit = 3) + OpenAPI Swagger parser. |
| **12** | **Implementation - 14 Scanner Plugins** | **Plugins Architecture** (`diagram_plugins_matrix.png`) | Recon, Web Injections, Auth/API, and Advanced Exploits domains. |
| **13** | **Implementation - Post-Processing Intelligence Layer** | **Intelligence Flowchart** (`diagram_intelligence_pipeline.png`) | Deduplication (-38.2% noise), live NIST CVSS scoring, and code patches. |
| **14** | **Implementation - Set-Theoretic Delta Scan Auditing** | **Delta Lifecycle Chart** (`diagram_delta_tracking.png`) | Stateful regression diffing: NEW (Red), FIXED (Green), UNCHANGED (Gray). |
| **15** | **Implementation - Web Dashboard & CI/CD Pipeline Gating** | **CI/CD Gating Flowchart** (`diagram_cicd_gating_flow.png`) | Real-time SSE telemetry and automated `--fail-on` build gating. |
| **16** | **Implementation - Website Scan Results & Demonstration** | **Website Screenshot Frames** (2 photo containers) | Target setup, progress bar, finding modal, and delta report placeholders. |
| **17** | **Results - Performance & Concurrency Benchmarks** | Concurrency Table + Latency Graph + Deduplication Table + Noise Graph | Concurrency scaling (184.2s to 64.8s, 2.84× speedup) and alert noise reduction. |
| **18** | **Results - Verification & Delta Regression** | 80/80 Test Table + Delta Graph + Delta Lifecycle Table | 100% pass rate in 13.68s and multi-build patch resolution verification. |
| **19** | **Conclusion** | Clean summary list | Unified platform, proven speedup, noise drop, DevSecOps readiness. |
| **20** | **References** | IEEE numbered citations | Standardized citations (Nmap, NIST NVD, OWASP, PCI-DSS, journals). |
| **21** | **THANK YOU** | Team credentials & contact | Questions & Discussion, GitHub link, team USNs, guide. |
