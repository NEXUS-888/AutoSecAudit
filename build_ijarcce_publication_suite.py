import copy
import json
import os
import statistics
import re
import shutil
import docx
from docx.shared import Inches, Pt, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH, WD_LINE_SPACING
from docx.enum.table import WD_TABLE_ALIGNMENT, WD_ALIGN_VERTICAL
from docx.oxml import OxmlElement, parse_xml
from docx.oxml.ns import qn, nsdecls
import win32com.client

TEMPLATE_PATH = os.path.abspath('paper/IJARCCE-Paper-Format.docx')  # official IJARCCE template
H2_ABSTRACT = 5   # abstractNum behind the template's 'IEEE Heading 2' list (A., B., ...)
CELL_PT = 10      # template: table cell text is 10 pt

def set_cell_margins(cell, top=70, bottom=70, left=90, right=90):
    """Set padding for a table cell in dxa (1 pt = 20 dxa)"""
    tcPr = cell._tc.get_or_add_tcPr()
    tcMar = OxmlElement('w:tcMar')
    for m, val in [('top', top), ('bottom', bottom), ('left', left), ('right', right)]:
        node = OxmlElement(f'w:{m}')
        node.set(qn('w:w'), str(val))
        node.set(qn('w:type'), 'dxa')
        tcMar.append(node)
    tcPr.append(tcMar)

def set_cell_shading(cell, color_hex):
    """Set cell background color"""
    shading = parse_xml(f'<w:shd {nsdecls("w")} w:fill="{color_hex}"/>')
    cell._tc.get_or_add_tcPr().append(shading)

def set_table_borders(table, color="000000", sz="4", val="single"):
    """Full black grid, as in the template's own table."""
    tblPr = table._tbl.tblPr
    sides = "".join(
        f'<w:{n} w:val="{val}" w:sz="{sz}" w:space="0" w:color="{color}"/>'
        for n in ("top", "left", "bottom", "right", "insideH", "insideV")
    )
    tblPr.append(parse_xml(f'<w:tblBorders {nsdecls("w")}>{sides}</w:tblBorders>'))

def build_paper():
    docx_path = os.path.abspath('paper/AutoSecAudit_Research_Paper_IJARCCE.docx')
    pdf_path = os.path.abspath('paper/AutoSecAudit_Research_Paper_IJARCCE.pdf')
    root_docx = os.path.abspath('AutoSecAudit_Research_Paper_IJARCCE.docx')
    root_pdf = os.path.abspath('AutoSecAudit_Research_Paper_IJARCCE.pdf')

    # ---------------------------------------------------------------------------
    # Start from the official IJARCCE template (styles, numbering, header, footer).
    # The template body is discarded; its first section (A4, 0.8" margins, IJARCCE
    # header and footer) becomes the only section of the paper.
    # ---------------------------------------------------------------------------
    doc = docx.Document(TEMPLATE_PATH)
    body = doc.element.body
    first_sect = copy.deepcopy(next(body.iter(qn('w:sectPr'))))
    # No running header: the template's journal header carries placeholders (Vol./Issue/DOI) that
    # the journal fills in, and the template's own rules say headers must not be used.
    for ref in first_sect.findall(qn('w:headerReference')):
        first_sect.remove(ref)
    for child in list(body):
        body.remove(child)
    body.append(first_sect)

    numbering = doc.part.numbering_part.element
    state = {"h2_num": None}

    # Level-1 numerals ("III.") are wider than the template's 0.2" tab, which glued them to the heading
    # text; use a space after the number instead (numbering definition only, style unchanged).
    for abs_num in numbering.findall(qn('w:abstractNum')):
        if abs_num.get(qn('w:abstractNumId')) == '0':
            lvl0 = abs_num.find(qn('w:lvl'))
            if lvl0 is not None and lvl0.find(qn('w:suff')) is None:
                suff = OxmlElement('w:suff')
                suff.set(qn('w:val'), 'space')
                lvl0.find(qn('w:pStyle')).addnext(suff)

    def style_of(name):
        return doc.styles[name]

    def new_h2_list():
        """Create a list instance of the template's level-2 heading numbering that restarts at A."""
        used = [int(n.get(qn('w:numId'))) for n in numbering.findall(qn('w:num'))]
        num_id = max(used) + 1
        num = parse_xml(
            f'<w:num {nsdecls("w")} w:numId="{num_id}"><w:abstractNumId w:val="{H2_ABSTRACT}"/>'
            f'<w:lvlOverride w:ilvl="0"><w:startOverride w:val="1"/></w:lvlOverride></w:num>'
        )
        numbering.append(num)
        return num_id

    def set_num(p, num_id):
        numPr = p._p.get_or_add_pPr().get_or_add_numPr()
        numPr.get_or_add_ilvl().val = 0
        numPr.get_or_add_numId().val = num_id

    def add_field(p, instr, cached, size=None):
        """Simple field (e.g. SEQ) with its cached result, as used by the template captions."""
        fld = OxmlElement('w:fldSimple')
        fld.set(qn('w:instr'), instr)
        r = OxmlElement('w:r')
        rPr = OxmlElement('w:rPr')
        if size:
            sz = OxmlElement('w:sz')
            sz.set(qn('w:val'), str(int(size * 2)))
            rPr.append(sz)
        r.append(rPr)
        t = OxmlElement('w:t')
        t.text = cached
        r.append(t)
        fld.append(r)
        p._p.append(fld)

    def add_title(text):
        p = doc.add_paragraph(style=style_of('IEEE Title'))
        p.add_run(text)
        doc.add_paragraph(style=style_of('IEEE Title'))  # blank line, as in the template
        return p

    def add_author_block():
        p = doc.add_paragraph(style=style_of('IEEE Title'))
        r = p.add_run("Kodi Vishruth Aithal, Thilak N, Vinaya Kumar B, Vishal Gowda B, Ranjitha R*")
        r.font.size = Pt(11)  # template: author name 11 pt Regular

        for line in (
            "Department of Computer Science and Engineering, Don Bosco Institute of Technology, Bangalore, Karnataka, India",
            "Emails: {aithalvishruth, gowdathilakn, bvinaykumar70, vishalgb2005}@gmail.com, *ranjitha.r@dbit.co.in",
            "(*Corresponding Author & Faculty Mentor)",
        ):
            q = doc.add_paragraph(style=style_of('IEEE Author Affiliation'))
            q.add_run(line)
        doc.add_paragraph(style=style_of('Normal'))

    def add_abstract(text, keywords):
        p_abs = doc.add_paragraph(style=style_of('IEEE Abtract'))
        r_h = p_abs.add_run("Abstract")
        r_h.font.size = Pt(10)
        r_h.font.bold = True
        r_c = p_abs.add_run(": ")
        r_c.font.size = Pt(10)
        r_c.font.bold = False
        r_b = p_abs.add_run(text)
        r_b.font.size = Pt(10)
        r_b.font.bold = False

        p_kw = doc.add_paragraph(style=style_of('Normal'))
        p_kw.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
        r_kh = p_kw.add_run("Keywords")
        r_kh.font.size = Pt(10)
        r_kh.font.bold = True
        r_kc = p_kw.add_run(": ")
        r_kc.font.size = Pt(10)
        r_kt = p_kw.add_run(keywords)
        r_kt.font.size = Pt(10)
        doc.add_paragraph(style=style_of('Normal'))

    def add_h1(text):
        """Level-1 heading in the template style. Numbering (I., II., ...) comes from the style."""
        numbered = re.match(r'^[IVX]+\.\s+', text) is not None
        p = doc.add_paragraph(style=style_of('IEEE Heading 1'))
        p.paragraph_format.keep_with_next = True
        run = p.add_run(re.sub(r'^[IVX]+\.\s+', '', text))
        run.font.bold = True
        if numbered:
            state["h2_num"] = new_h2_list()  # level-2 letters restart in every numbered section
        else:
            set_num(p, 0)  # ACKNOWLEDGMENT, REFERENCES, BIOGRAPHY are not numbered
        return p

    def add_h2(text):
        p = doc.add_paragraph(style=style_of('IEEE Heading 2'))
        p.paragraph_format.keep_with_next = True
        set_num(p, state["h2_num"])
        p.add_run(re.sub(r'^[A-H]\.\s+', '', text))
        return p

    def add_p(text, bold_prefix=None, indent=True):
        if "\n" in text:
            parts = text.split("\n")
            first = add_p(parts[0], bold_prefix=bold_prefix, indent=indent)
            for part in parts[1:]:
                q = add_p(part, indent=False)
                q.alignment = WD_ALIGN_PARAGRAPH.LEFT
                q.paragraph_format.left_indent = Inches(0.25)
            return first
        p = doc.add_paragraph(style=style_of('IEEE Paragraph'))
        if not indent:
            p.paragraph_format.first_line_indent = Inches(0)
        if bold_prefix:  # level-3 / run-in heading: italic, ends with a colon (template)
            r_pre = p.add_run(bold_prefix)
            r_pre.font.italic = True
        p.add_run(text)
        return p

    def add_algo_box(title, text):
        p_hdr = doc.add_paragraph(style=style_of('IEEE Paragraph'))
        p_hdr.paragraph_format.space_before = Pt(6)
        p_hdr.paragraph_format.space_after = Pt(2)
        p_hdr.paragraph_format.first_line_indent = Inches(0)
        p_hdr.paragraph_format.keep_with_next = True
        p_hdr.add_run(title).font.bold = True

        p_box = doc.add_paragraph(style=style_of('IEEE Paragraph'))
        p_box.alignment = WD_ALIGN_PARAGRAPH.LEFT
        p_box.paragraph_format.first_line_indent = Inches(0)
        p_box.paragraph_format.left_indent = Inches(0.15)
        p_box.paragraph_format.right_indent = Inches(0.15)
        p_box.paragraph_format.space_after = Pt(6)
        r_b = p_box.add_run(text)
        r_b.font.name = 'Courier New'  # template allows other fonts for special purposes
        r_b.font.size = Pt(8.5)
        p_box.paragraph_format.keep_together = True

    def add_figure(img_path, caption, width_in=5.4):
        if not os.path.exists(img_path):
            return
        p_img = doc.add_paragraph(style=style_of('IEEE Figure'))
        p_img.paragraph_format.space_before = Pt(6)
        p_img.paragraph_format.keep_with_next = True
        p_img.add_run().add_picture(img_path, width=Inches(width_in))

        m = re.match(r'^Fig\.\s+(\d+)\.\s+(.*)$', caption, re.S)
        p_cap = doc.add_paragraph(style=style_of('IEEE Figure Caption Multi-Lines'))
        if len(m.group(2)) < 95:
            p_cap.alignment = WD_ALIGN_PARAGRAPH.CENTER  # template: one-line captions centred
        p_cap.add_run("Fig. ").font.size = Pt(10)
        add_field(p_cap, ' SEQ Fig. \\* ARABIC \\* MERGEFORMAT ', m.group(1), size=10)
        p_cap.add_run(".  " + m.group(2)).font.size = Pt(10)

    def add_table_data(caption, headers, rows, highlight_row=None, highlight_col=None, widths=None):
        m = re.match(r'^TABLE\s+([IVX]+)\s+(.*)$', caption, re.S)
        p_cap = doc.add_paragraph(style=style_of('IEEE Table Caption'))
        p_cap.paragraph_format.keep_with_next = True
        p_cap.add_run("TABLE ").font.size = Pt(10)
        add_field(p_cap, ' SEQ TABLE \\* ROMAN \\* MERGEFORMAT ', m.group(1), size=10)
        p_cap.add_run("   " + m.group(2)).font.size = Pt(10)

        tbl = doc.add_table(rows=len(rows) + 1, cols=len(headers))
        tbl.alignment = WD_TABLE_ALIGNMENT.CENTER
        set_table_borders(tbl)
        for tr in tbl.rows:
            tr._tr.get_or_add_trPr().append(OxmlElement('w:cantSplit'))
        if widths:
            tbl.autofit = False
            for tr in tbl.rows:
                for c_i, w_in in enumerate(widths):
                    tr.cells[c_i].width = Inches(w_in)

        for c_idx, title in enumerate(headers):
            cell = tbl.rows[0].cells[c_idx]
            p_cell = cell.paragraphs[0]
            p_cell.style = style_of('IEEE Table Header Centered')
            p_cell.add_run(title).font.size = Pt(CELL_PT)
            set_cell_margins(cell, top=40, bottom=40, left=70, right=70)

        for r_idx, row_data in enumerate(rows):
            row = tbl.rows[r_idx + 1]
            for c_idx, val in enumerate(row_data):
                cell = row.cells[c_idx]
                p_cell = cell.paragraphs[0]
                p_cell.style = style_of('IEEE Table Cell')
                r_c = p_cell.add_run(str(val))
                r_c.font.size = Pt(CELL_PT)
                set_cell_margins(cell, top=30, bottom=30, left=70, right=70)
                if c_idx > 0 and len(headers) > 3:
                    p_cell.alignment = WD_ALIGN_PARAGRAPH.CENTER
                if highlight_row is not None and r_idx == highlight_row:
                    set_cell_shading(cell, "FEF3C7")
                    r_c.font.bold = True
                elif highlight_col is not None and c_idx == highlight_col:
                    set_cell_shading(cell, "F0FDF4")
                    r_c.font.bold = True

        for tr in tbl.rows[:-1]:
            for cell in tr.cells:
                for para in cell.paragraphs:
                    para.paragraph_format.keep_with_next = True

        p_spacer = doc.add_paragraph(style=style_of('IEEE Paragraph'))
        p_spacer.paragraph_format.first_line_indent = Inches(0)
        p_spacer.paragraph_format.line_spacing_rule = WD_LINE_SPACING.EXACTLY
        p_spacer.paragraph_format.line_spacing = Pt(6)

    # ---------------------------------------------------------------------------
    # DOCUMENT SECTIONS
    # ---------------------------------------------------------------------------

    # ---------------------------------------------------------------------------
    # Measured data: every number in Sec. IV and in the abstract comes from the raw
    # output of `python -m benchmark.paper_experiments all` (benchmark/results/paper).
    # ---------------------------------------------------------------------------
    def _load(name):
        with open(os.path.join('benchmark', 'results', 'paper', name + '.json'), encoding='utf8') as fh:
            return json.load(fh)

    TEST_COUNT = 578
    sc = _load('scaling')
    acc = _load('accuracy')
    dl2 = _load('delta')
    dl1 = _load('delta_run1')
    host = sc['host']

    ks = sorted(int(k) for k in sc['runs'])
    sec = {k: [r['seconds'] for r in sc['runs'][str(k)]] for k in ks}
    cpu = {k: [r['cpu_seconds'] for r in sc['runs'][str(k)]] for k in ks}
    fcount = {k: [r['findings'] for r in sc['runs'][str(k)]] for k in ks}
    n_reps = len(sec[ks[0]])
    all_secs = [x for k in ks for x in sec[k]]
    all_find = [x for k in ks for x in fcount[k]]
    full_find = max(all_find)
    FLOOR = 56.0                                   # scans at or below this are on the ~53 s floor
    n_scans = len(all_secs)
    n_slow = sum(1 for x in all_secs if x > FLOOR)
    n_deadline = sum(1 for x in all_secs if x >= 299)
    n_lost = sum(1 for x in all_find if x < full_find)
    med = {k: statistics.median(sec[k]) for k in ks}
    fastest = min(all_secs)

    accs = acc['runs']
    def _acc_stats(name):
        runs = accs[name]
        tp = [r['tp'] for r in runs]
        total = runs[0]['total_real']
        complete = [r for r in runs if r['tp'] == r['total_real']]
        return {
            'n': len(runs), 'total': total, 'tp': tp, 'fp': sum(r['fp'] for r in runs),
            'prec': statistics.fmean(r['precision'] for r in runs),
            'rec': statistics.fmean(r['recall'] for r in runs),
            'n_complete': len(complete),
            'raw': statistics.fmean(r['raw_alerts'] for r in complete) if complete else 0.0,
            'merged': statistics.fmean(r['raw_findings'] for r in complete) if complete else 0.0,
        }
    A1, A2 = _acc_stats('testbed1'), _acc_stats('testbed2')
    red1 = 100.0 * (A1['raw'] - A1['merged']) / A1['raw']
    red2 = 100.0 * (A2['raw'] - A2['merged']) / A2['raw']

    def _dsum(d, key):
        return d[key]['summary']
    d1a, d1b = _dsum(dl1, 'v1_to_v2'), _dsum(dl1, 'v2_to_v3')
    d2a, d2b = _dsum(dl2, 'v1_to_v2'), _dsum(dl2, 'v2_to_v3')

    # 1. Title
    add_title("AutoSecAudit: An Extensible Multi-Scanner Orchestration Framework with AI-Assisted Remediation Guidance, Precision Fuzzing, and Delta Auditing in DevSecOps")

    # 2. Authors
    add_author_block()

    # 3. Abstract & Keywords
    abstract_text = (
        "Automating security verification in fast-paced continuous integration and continuous deployment (CI/CD) pipelines creates operational friction: studies of developer tool adoption report that noisy output and missing actionable guidance discourage the use of automated analysis tools [13]. "
        "This paper presents AutoSecAudit, an open, extensible dynamic application security testing (DAST) orchestration framework with remediation guidance, designed for CI/CD pipelines and AI developer tooling. "
        "It combines (1) attack-surface discovery through a depth-limited recursive crawler, JavaScript route extraction, OpenAPI import, and a scope guard that checks every resolved address; "
        "(2) concurrent execution of 19 scanner plugins with heuristic false-positive reduction (baseline-response comparison, a two-phase statistical timing check, single-page-application filtering, and adaptive politeness with retry on HTTP 429/503); "
        "(3) an intelligence layer that merges duplicate findings on a canonical key, enriches CVE-tagged findings with CVSS data, maps findings to OWASP Top 10 (2021), CWE, and PCI DSS v4.0 by keyword rules, and assigns plain-English business-risk categories and a five-level posture grade; and "
        "(4) delivery features: predefined multi-framework fix recipes, fingerprint-based delta comparison between scans, severity gating through exit codes, and a Model Context Protocol (MCP) server with four tools for AI coding assistants. "
        "Applying patches is left to the assistant or developer, and closed-loop remediation is not evaluated. "
        f"We evaluate the tool on two purpose-built test applications with {A1['total']} and {A2['total']} planted vulnerabilities, using {n_reps} repetitions per setting on one Windows machine. "
        f"Testbed 2 was fully detected with no false positive in all {A2['n']} runs, whereas testbed 1 was fully detected in {A1['n_complete']} of {A1['n']} runs (mean recall {100*A1['rec']:.0f}%) because some scans reached the 300 s scan deadline. None of these measured runs reported a false positive, but one further testbed 2 run inside the test suite did (a missing-SameSite cookie finding that matched no planted item). "
        f"Merging reduced raw plugin alerts by {red1:.0f}% and {red2:.0f}% on complete scans. "
        f"Increasing worker threads from 1 to 16 did not shorten scans (median {med[1]:.0f} s at k=1 and {med[16]:.0f} s at k=16), so an earlier speedup claim is withdrawn, and {n_slow} of {n_scans} scans ran longer than the {FLOOR:.0f} s floor. "
        "Delta comparison was exact on two complete scans but produced spurious changes when scans were incomplete. "
        "These results come from one machine and small applications written alongside the tool; they say nothing about performance on production applications."
    )
    keywords_text = "Vulnerability Assessment, DevSecOps, Scanner Orchestration, Model Context Protocol (MCP), AI-Assisted Remediation, Statistical Timing Verification, Compliance Mapping, Delta Auditing, Web Security, API Security."
    add_abstract(abstract_text, keywords_text)

    # 4. Section I: INTRODUCTION
    add_h1("I.  INTRODUCTION")
    add_p(
        "Modern web applications, cloud-native services, and microservice architectures represent heterogeneous software systems that undergo continuous integration and automated deployment multiple times daily [9]. Ensuring reliable software security within these accelerated delivery cadences motivates 'shift-left' verification, wherein security analysis is executed during automated build and pull-request gating steps [9]. Dynamic Application Security Testing (DAST) evaluates target web services from an external attacker perspective without requiring underlying source code, validating whether identified vulnerabilities are exploitable over active transport protocols."
    )
    add_p(
        "Embedding DAST in automated build pipelines can be difficult in practice. Johnson et al. [13] report that false positives and poor integration deter developers from using static analysis tools, and Bau et al. [10] found that commercial black-box scanners differ widely in coverage and accuracy. We treat similar friction as a plausible risk for DAST in CI/CD pipelines; this paper does not itself measure developer behavior. We identify five operational challenges that motivate the design:"
    )
    add_p(
        "A thorough security audit requires executing multiple specialized utilities—such as port discovery tools (Nmap [1]), web server misconfiguration checkers (Nikto [2]), and API parameter fuzzers. Each utility outputs disparate formats (XML, unstructured console text, non-uniform JSON), forcing engineering teams to write and maintain fragile parsing wrappers.",
        bold_prefix="1) Heterogeneous Tool Fragmentation and Format Sprawl: "
    )
    add_p(
        "Independent scanner modules frequently flag the exact same root vulnerability on an endpoint under slightly varied diagnostic titles. Without cross-plugin deduplication, engineers may triage several notifications for a single bug, which contributes to alert fatigue (cf. [13] for static analysis tools).",
        bold_prefix="2) Duplicate Alert Sprawl and Developer Fatigue: "
    )
    add_p(
        "Scanner output is typically expressed as Common Vulnerabilities and Exposures (CVE) identifiers, Common Vulnerability Scoring System (CVSS) vectors, and raw request traces. These technical representations can be hard for executives and product owners to translate into business impact.",
        bold_prefix="3) Executive Communication Gap: "
    )
    add_p(
        "Scanners often report what is broken but leave developers to write framework-specific patches, input sanitization routines, or Web Application Firewall (WAF) virtual patching rules themselves. Furthermore, developers increasingly work inside AI-assisted environments (Cursor, Claude Code, Antigravity). Most established scanners were designed around CLI, GUI, or REST interfaces rather than an agent protocol, although Model Context Protocol (MCP) [14] integrations are now emerging for some tools [17], [18].",
        bold_prefix="4) Missing Code Fixes and AI Workflow Disconnection: "
    )
    add_p(
        "Release gating benefits from knowing what changed between builds. A single scan does not by itself distinguish newly introduced vulnerabilities from previously known ones or show whether a committed patch resolved an open issue; findings-management platforms [19] and scan-comparison features address this in different ways.",
        bold_prefix="5) Stateless Scans Lacking Regression Awareness: "
    )
    add_p(
        "To address these challenges, we present AutoSecAudit, an extensible multi-scanner security orchestration framework with remediation guidance for AI-assisted workflows. AutoSecAudit combines automated attack surface discovery, concurrent execution of 19 scanner plugins, false-positive reduction mechanisms, plain-English business danger translation, predefined multi-framework fix recipes, fingerprint-based delta comparison between scans, and an MCP tool server in one DevSecOps engine. The contributions are the integrated design and its open implementation; the evaluation in Section IV is small-scale, uses two built-in test applications, and is reproducible from the repository."
    )

    # 5. Section II: RELATED WORK
    add_h1("II.  RELATED WORK AND COMPARATIVE ANALYSIS")
    add_p(
        "Security testing tools generally fit into four architectural paradigms: standalone point scanners, interactive DAST proxies, template-driven matchers, and centralized vulnerability management platforms. Table I summarizes built-in capabilities as described in each tool's public documentation (accessed October 2026) and compares them with AutoSecAudit. Capabilities available only through add-ons, integrations, or configuration are noted as such, and the table is not a head-to-head benchmark."
    )
    add_h2("A.  Point Scanners and Specialized Utilities")
    add_p(
        "Network scanners like Nmap [1] handle port discovery and service fingerprinting, while web server checkers like Nikto [2] scan for server misconfigurations and outdated defaults. Template-driven scanners like Nuclei [3] run YAML-defined checks over HTTP and other protocols. These tools are focused scanners: each runs as a standalone binary with its own output format, and none of them by itself correlates results across tools, compares scans across builds, or translates findings into business risk. Nuclei templates do carry severity and classification metadata, and all three tools can emit machine-readable output that external pipelines consume."
    )
    add_h2("B.  Stateful DAST Proxies and API Fuzzers")
    add_p(
        "State-aware scanners, explored by Doupé et al. [11], track application navigation states to uncover deeper injection points. In API fuzzing, Atlidakis et al. [12] demonstrated with RESTler that effective testing requires parsing OpenAPI structures. Intercepting proxies and scanners such as OWASP ZAP [4] and PortSwigger Burp Suite provide broad coverage and are considerably more mature than AutoSecAudit. ZAP ships packaged baseline, API, and full scans and an Automation Framework intended for CI use [16]; full active scans with proxy-based tools can be long-running depending on configuration and target, which is why time-boxed or passive modes are common in merge checks. We did not benchmark AutoSecAudit against these tools, so this paper makes no claim of superior coverage or accuracy."
    )
    add_h2("C.  Vulnerability Management Aggregation Platforms")
    add_p(
        "Platforms like OWASP DefectDojo [5] aggregate findings from many third-party scanners, deduplicate them, and track their lifecycle, including re-import workflows that close findings absent from a newer report [19]. DefectDojo does not itself execute scans, so teams still need pipeline jobs that run the individual tools and upload their reports. AutoSecAudit instead bundles execution with a lighter-weight post-processing layer; it does not replace a findings-management platform."
    )
    add_h2("D.  AI Coding Assistants and Agentic Protocols")
    add_p(
        "Recent advances in AI-assisted software engineering have produced agentic developer tools (such as Cursor, Claude Code, and Antigravity). The Model Context Protocol (MCP) [14] standardizes how such agents call external tools over JSON-RPC 2.0, and MCP integrations now exist for other security tools, including a Burp Suite extension [17] and a ZAP MCP integration add-on [18]. AutoSecAudit implements an MCP stdio server that lets an agent initiate scans, inspect findings with business-risk annotations, and retrieve predefined fix recipes. The protocol is not a contribution of this work. The server does not edit source code itself, and the agent-driven loop of patching, re-scanning, and checking for regressions is not evaluated in this paper."
    )

    # Table I
    t1_headers = ["Dimension / Capability", "Nmap / Nikto / Nuclei [1-3]", "OWASP ZAP [4]", "DefectDojo [5]", "AutoSecAudit (Ours)"]
    t1_rows = [
        ["Primary role", "Focused scanners (ports, web server, templates)", "Intercepting proxy and scanner", "Findings-management platform; does not run scans", "Plugin-based DAST orchestrator"],
        ["Parallelism", "Tool-specific", "Configurable scanner threads", "Not applicable", "Plugin-level ThreadPool (default 4, configurable)"],
        ["Surface discovery", "Tool-specific; limited crawling", "Spider; OpenAPI import via add-on [16]", "Not applicable (imports reports)", "Recursive HTML crawl, regex JS routes; OpenAPI import feeds the plugins (see Sec. III-A)"],
        ["Scanner breadth", "Single purpose or template-defined", "Built-in rules plus add-ons", "None built in; imports third-party reports", "19 built-in plugins (compact)"],
        ["False-positive handling", "Tool-specific matchers", "Rule thresholds and alert filters", "Deduplication and triage statuses", "Baseline comparison; 2-phase timing check; SPA filter"],
        ["Vulnerability intelligence", "Template metadata (Nuclei)", "Alert references (CWE, OWASP)", "Stores imported CVE/CWE/CVSS data", "NVD/CIRCL CVSS lookup for CVE-tagged findings"],
        ["Compliance mapping", "Template tags (Nuclei)", "Alert references", "Imported metadata and reports", "Keyword rules to OWASP 2021, CWE, PCI DSS v4.0"],
        ["Business-risk view", "Not provided", "Risk levels only", "Dashboards and metrics", "Plain-English danger categories, 5-level grade (heuristic)"],
        ["Fix guidance", "Tool-specific advice", "Per-alert solution text", "Imported guidance; Jira integration", "Predefined recipes (Node, Python, Nginx, WAF) and Markdown tickets"],
        ["AI-agent interface", "Not assessed", "MCP integration add-on [18]", "REST API", "MCP stdio server, 4 tools"],
        ["Cross-build comparison", "Not built in", "Not assessed", "Re-import closes and reopens findings [19]", "Fingerprint-based delta (Sec. III-C)"],
        ["CI/CD gating", "Exit status or output parsed by pipeline scripts", "Automation Framework exit-status job [16]", "Through API and integrations", "--fail-on severity threshold, exit code 1"]
    ]
    add_table_data("TABLE I   COMPARISON OF BUILT-IN CAPABILITIES ACROSS SECURITY TESTING PARADIGMS", t1_headers, t1_rows, highlight_col=4, widths=[1.15, 1.3, 1.3, 1.3, 1.6])

    # 6. Section III: ARCHITECTURE
    add_h1("III.  SYSTEM ARCHITECTURE AND METHODOLOGY")
    add_p(
        "AutoSecAudit is structured into four decoupled subsystems (Fig. 1): "
        "(1) Input Ingestion, Surface Discovery & Pre-flight Validation; "
        "(2) Concurrent Multi-Scanner Engine & Precision Subsystem; "
        "(3) Post-Processing Intelligence Layer; and "
        "(4) Delivery, CI/CD Gating, and AI-Assistant Integration."
    )

    add_figure('paper/figures/fig1_architecture.png', "Fig. 1.  AutoSecAudit system architecture: four-stage pipeline from surface discovery and concurrent 19-plugin execution through cross-referencing, compliance mapping, danger translation, delta comparison, and MCP integration.", width_in=6.4)

    add_h2("A.  Attack Surface Discovery and Pre-flight Validation")
    add_p(
        "Given a target hostname, IP address, or URL, the surface discovery subsystem seeds an endpoint pool E before initiating active scans. The design is motivated by [11], [12] but does not implement state-aware crawling or RESTler-style stateful fuzzing:"
    )
    add_p(
        "Before a scan starts, is_target_allowed() parses the target host. An IP literal is accepted only if it is private (RFC 1918 / RFC 4193) or loopback; a hostname is resolved through DNS and accepted only if every address it resolves to is private or loopback (IPv4 and IPv6). The check is enforced when the engine sets its target, so the CLI, the dashboard, and the MCP server share it, and a name that merely looks private (for example 10.example.com) is rejected when it resolves to a public address. This is a guardrail against accidental scanning of public systems, not an authorization mechanism: it does not verify that the operator may test the target, and a DNS answer could change between the check and the scan. HTTP redirects are followed manually and only to same-origin, in-scope locations, and each response is bounded in size (5 MiB by default) and in time (30 s per request by default). In real-scan mode, an HTTP reachability probe (HEAD, falling back to GET, with a raw TCP fallback) confirms that the server responds before plugins are scheduled; the probe is skipped in mock mode.",
        bold_prefix="1) Target Scope Guardrail and Pre-Flight Liveness: "
    )
    add_p(
        "The WebCrawler follows same-host links starting from the root URL, recursing depth-first (not breadth-first) up to a depth limit D_max (default 3) and a page budget (default 20). It extracts HTML form structures (<form action method>), input fields, query parameters, and hyperlinks. Regular-expression extractors are applied to the HTML of each visited page, including inline <script> content, to find client-side REST API routes (/api/v1/...) that lack standard HTML links. Externally referenced JavaScript bundles are not fetched or analyzed in the current implementation, so routes that exist only in such bundles are missed.",
        bold_prefix="2) Recursive Web Crawler and Client-Side JS Route Extraction: "
    )
    add_p(
        "For headless REST backends, the OpenAPIImporter reads an OpenAPI 2.0 or 3.x specification supplied as a JSON or YAML file or URL and extracts paths, HTTP methods (GET, POST, PUT, DELETE, PATCH), declared parameters (including path variables), local $ref targets, and top-level JSON request-body properties. The imported endpoints are handed to the scanner plugins, and when no specification is supplied the engine also looks for one at common locations (for example /swagger.json, /v2/api-docs, /v3/api-docs, and /api-docs) and imports it automatically. Remote $ref targets and full request-body schema validation are not handled.",
        bold_prefix="3) OpenAPI / Swagger Ingestion: "
    )
    add_p(
        "To audit authenticated application surfaces, the AutoAuthenticator probes common login paths, tries HTML-form, JSON-API, and blind-form login strategies with user-supplied credentials, extracts anti-CSRF tokens, and captures session cookies and bearer tokens. The engine then passes the captured headers and cookies to the crawler and, through set_auth(), to the plugins; we did not audit how much each plugin uses the session. Authentication runs only in real-scan mode.",
        bold_prefix="4) Automated Multi-Strategy Authenticator: "
    )

    add_algo_box(
        "Algorithm 1: Attack Surface Discovery (as implemented: depth-first, bounded)",
        "Input: Target URL u0, Max Depth D_max, Page Budget P_max, Auth Credentials A (optional)\n"
        "Output: Discovered Endpoint Pool E (forms, links, parameters, JS routes)\n"
        "1: If not IsTargetAllowed(u0) [every resolved address]: Abort('Target not permitted')\n"
        "2: If real mode and not CheckLiveness(u0): Abort('Host unreachable')\n"
        "3: Session S = InitializeSession()\n"
        "4: If A is provided: S = AutoAuthenticate(u0, A)\n"
        "5: Visited Set V = {}, E = {}\n"
        "6: Crawl(u0, 0)\n"
        "7: Procedure Crawl(u, d):\n"
        "8:    If d > D_max or |V| >= P_max or Normalize(u) in V: Return\n"
        "9:    V = V U {Normalize(u)};  Response R = S.GET(u)\n"
        "10:   If R is not HTML: E = E U {ResourceEndpoint(u)}; Return\n"
        "11:   E = E U ParseHTMLForms(R.body) U ExtractJSRoutes(R.body)\n"
        "12:   For each same-host link l in ExtractHyperlinks(R.body):\n"
        "13:      E = E U {LinkEndpoint(l)}  (with query parameters, if any)\n"
        "14:      Crawl(l, d+1)\n"
        "15: Return E\n"
        "Note: endpoints imported from an OpenAPI document (supplied or auto-discovered) are added to E before the plugins run."
    )

    add_h2("B.  Core Engine, 19 Scanner Plugins, and Precision Mechanisms")
    add_p(
        "Each scanner module extends the abstract BaseScanner interface. Standardized findings use the tuple model: "
        "F = <id, title, severity, host, port, description, raw_output, c, M, t, e, m, q>, where c in {low, medium, high} is a heuristic confidence label assigned by the plugin, M holds optional CVE/CVSS, OWASP, CWE, PCI DSS, and remediation fields, and t, e, m, and q are the vulnerability type, normalized endpoint path, HTTP method, and parameter that identify the finding across tools and across scans."
    )
    add_p(
        "AutoSecAudit organizes 19 scanner plugins across four operational domains:\n"
        "• Web Application Injections: SQLiScanner (error-based and tautology payloads, plus time-based blind probes verified by the timing check), XSSScanner (reflected XSS only), CSRFScanner (anti-CSRF tokens and SameSite cookie attributes), OpenRedirectScanner (unvalidated redirect parameters), MisconfigScanner (security headers, cookie flags, exposed files, HTTP methods).\n"
        "• API & Access Control: BOLAIdorScanner (object-identifier manipulation), APIAbuseScanner (excessive data exposure, mass assignment, missing pagination, GraphQL introspection, API versioning, broken authentication), AuthScanner (default credentials, IDOR, weak-password registration, exposed admin panels, user enumeration, login rate limiting), JWTScanner (passive inspection of JWTs observed in responses for alg=none headers and missing or expired exp claims; it does not test weak HMAC secrets or forged-token acceptance), CORSScanner (wildcard origin, origin reflection, null origin).\n"
        "• Advanced Exploit Vectors: CommandInjectionScanner (OS command injection, including timing-verified blind probes), SSRFScanner (internal-URL probes; cloud-metadata probes to 169.254.169.254 are disabled unless AUTOSEC_ENABLE_METADATA_PROBES is set), PathTraversalScanner (local file inclusion, e.g., /etc/passwd), SSTIScanner (arithmetic expression probes such as {{7*7}}, ${7*7}, and <%= 7*7 %>).\n"
        "• Reconnaissance & Infrastructure: SecretExposureScanner (sensitive paths such as /.env and /.git/config), SSLTLSScanner (certificate validity and expiry, HSTS, obsolete TLS versions), DirBruteScanner (a 50-entry curated path list that includes several Juice Shop-specific entries), NiktoPlugin and NmapPlugin (wrappers around the external nikto and nmap executables, which must be installed)."
    )
    add_p(
        "The engine supports four scan profiles, defined in config.py and verified by loading each profile: 'full' (all 19 plugins), 'owasp' (11 plugins: SQLi, XSS, CSRF, SSRF, Auth, Misconfig, CommandInjection, PathTraversal, SSTI, SecretExposure, OpenRedirect), 'api' (7 plugins: BOLAIdor, JWT, CORS, APIAbuse, Auth, SQLi, XSS), and 'recon' (6 plugins: SSLTLS, Misconfig, DirBrute, Nikto, Nmap, SecretExposure). The recon profile is described in the configuration as reconnaissance with low-impact active probing: Nmap performs port scanning, and Nikto, DirBrute, Misconfig, and SecretExposure issue active HTTP requests, so it is non-exploitative but not passive. Plugins run concurrently through a thread pool whose size is set by AUTOSEC_THREAD_COUNT (default 4); the evaluation in Sec. IV sweeps it from 1 to 16.",
        bold_prefix="Scan Profiles: "
    )
    add_p(
        "AutoSecAudit includes four mechanisms intended to reduce false positives and target load. They lower, but do not eliminate, false-positive risk:\n"
        "1) Two-Phase Statistical Timing Check (core/timing.py): Blind time-based probes (for example SLEEP(3) or sleep 2) are prone to false positives from latency spikes. BaseScanner measures m = 2 benign requests to estimate a baseline mean mu_base and sample standard deviation sigma_base. For a probe with injected delay tau, the delay must reach mu_base + max(3*sigma_base, 0.70*tau) on a first probe and again on a second, independent delay probe. If a zero-delay control payload is supplied, phase 2 requires it to return within mu_base + 0.35*tau, and the finding is then graded high confidence; without a control probe a reproduced delay is graded medium, and a slow control probe rejects the finding. With m = 2 the variance estimate is coarse and the check remains a heuristic. Timing probes are serialized across plugins so that concurrent scanning does not contaminate the measurements, and the check is applied by the SQLi and command-injection plugins only.\n"
        "2) Baseline Response Comparison: The SQLi plugin requests a benign baseline response and compares each probe response against it; a change in HTTP status or a response-length change above 20% is treated as evidence, graded high, medium, or low by the magnitude of the change. Other plugins use their own matching logic.\n"
        "3) SPA and Development-Server Filtering (core/spa_detector.py, core/dev_detector.py): Responses that look like single-page-application catch-all pages are filtered to avoid findings caused by soft-404 behavior, and development-server artifacts are tagged.\n"
        "4) Adaptive Politeness (core/politeness.py): Each plugin adds randomized 0-20 ms jitter between requests. All plugins share one HTTP client; on HTTP 429 or 503 it honors Retry-After (capped at 10 s) or backs off exponentially for min(2^(n-1), 8) seconds and retries up to twice, and a response that is still throttled is withheld from detection logic so that a rate-limit page is not reported as evidence. The client also enforces the scope, size, and time limits described in Sec. III-A.\n"
        "A recursive JSON body fuzzer (core/fuzzer.py) enumerates every leaf of a nested JSON request body and replaces one leaf at a time with a payload while preserving the rest of the structure; the SQLi and command-injection plugins use it. Object keys that contain a period are not addressed correctly by its dotted-path scheme, and empty containers have no leaf to mutate.",
        bold_prefix="Precision Mechanisms: "
    )

    add_h2("C.  Post-Processing Intelligence Layer")
    add_p(
        "Following raw scanner execution, the shared pipeline (core/pipeline.py, used by the CLI, the dashboard, and the MCP server) post-processes findings in the steps of Algorithm 2. Findings from different plugins that describe the same weakness are merged on a canonical key <vulnerability type, HTTP method, normalized endpoint, parameter>, in which numeric path segments are replaced by a placeholder and the reporting tool is ignored; the merged finding keeps the highest severity and confidence, the union of the reporting tools, and the combined evidence and references. Remaining findings that share an endpoint and parameter are cross-referenced but not merged. Compliance mapping applies keyword rules to finding titles to assign OWASP Top 10 (2021) categories [6] and uses a built-in table for CWE identifiers and PCI DSS v4.0 requirements [7]; CVSS data are looked up from the NVD [8] or CIRCL for findings that carry a CVE identifier."
    )

    add_algo_box(
        "Algorithm 2: Intelligence Post-Processing and Delta Comparison (as implemented)",
        "Input: Raw Findings F_raw, optional Previous Report S_{t-1}\n"
        "Output: Annotated Report S_t, Delta Partition <Delta_NEW, Delta_FIXED, Delta_UNCHANGED>\n"
        "1: Group F_raw by canonical key k(f) = <f.type, f.method, norm(f.endpoint), f.param>\n"
        "2: For each group g: S_t = S_t U {Merge(g)}   [max severity, max confidence, union of tools and evidence]\n"
        "3: For merged findings with equal <endpoint, param>: append 'Related findings: ids' to f.references\n"
        "4: For each f in S_t: fp(f) = SHA-256(f.tool | f.type | f.method | f.endpoint | f.param)\n"
        "5: For each f in S_t with f.cve_id: query NVD (2 s timeout), fall back to CIRCL;\n"
        "6:    set f.cvss_score if unset and merge references; skip silently on failure\n"
        "7: For each f in S_t: (f.owasp_tag, f.cwe_id, f.pci_dss) = MapCompliance(f)   [keyword rules]\n"
        "8: Danger category/grade and fix recipes are derived from f when a report or MCP response is built\n"
        "9: If S_{t-1} is provided: T = scanners that completed successfully in both scans;\n"
        "10:   keep only findings reported by a scanner in T\n"
        "11:   Delta_NEW = { f in S_t | fp(f) not in fp(S_{t-1}) }\n"
        "12:   Delta_FIXED = { f in S_{t-1} | fp(f) not in fp(S_t) }\n"
        "13:   Delta_UNCHANGED = { f in S_t | fp(f) in fp(S_{t-1}) }\n"
        "14: Return S_t, <Delta_NEW, Delta_FIXED, Delta_UNCHANGED>"
    )

    add_p(
        "The DangerEngine assigns each finding to one of four business threat categories using keyword rules over the finding title and tool name, with an OWASP-tag fallback: "
        "(i) Customer & Database Theft (SQL injection, exposed repositories and environment files, directory listing); "
        "(ii) Account Hijacking & Auth Bypass (authentication, JWT, session, cookie, IDOR, and brute-force findings); "
        "(iii) Phishing, XSS & Brand Defacement (CORS, XSS, security headers, open redirects); and "
        "(iv) Full Server Takeover & RCE (command injection and remote code execution). "
        "Unmatched findings default to category (i). The posture score is 100 - (25*C + 12*H + 5*M + 1*L), where C, H, M, and L are the counts of critical, high, medium, and low findings, clamped to the range [10, 100]; together with count thresholds it yields one of five grades (A+, B, C, D, F). The grade and the plain-English explanations (what is broken, what an attacker can do, business impact, estimated fix time) are rule-based heuristics; their usefulness to non-technical readers was not evaluated.",
        bold_prefix="Plain-English Danger Engine and Executive Posture: "
    )
    add_p(
        "The RecipeEngine returns predefined, static code snippets selected by keywords in the finding title: Node.js/Express (parameterized queries, Helmet, express-validator), Python (SQLAlchemy and Django ORM, Pydantic, Flask/FastAPI middleware, Flask-Talisman), Nginx directives, and a generic WAF rule in JSON form. Recipes exist for seven finding classes (SQL injection, CORS, security headers, directory and secret exposure, CSRF, open redirect, BOLA/IDOR) plus a generic fallback; there are none for XSS, command injection, SSRF, SSTI, JWT, or path traversal. The recipes are templates: they are not generated per codebase, and this paper does not test that applying them removes the corresponding vulnerability. A Markdown ticket template is also provided that can be pasted into issue trackers such as Jira, Linear, or GitHub.",
        bold_prefix="Fix Recipes and Dev Tickets: "
    )
    add_p(
        "The DeltaAnalyzer compares two reports by a content fingerprint: the SHA-256 of the reporting tool, vulnerability type, HTTP method, normalized endpoint, and parameter (Algorithm 2, step 4), so the key does not depend on the order in which a plugin numbers its findings. With fp(S) denoting the set of fingerprints in report S, findings are partitioned into three disjoint sets: Delta_NEW = { f in S_t | fp(f) not in fp(S_{t-1}) }, Delta_FIXED = { f in S_{t-1} | fp(f) not in fp(S_t) }, and Delta_UNCHANGED = { f in S_t | fp(f) in fp(S_{t-1}) }. Only scanners that completed successfully in both scans are compared, so a narrower profile does not report every finding of the missing scanners as fixed. Because the reporting tool is part of the key, a finding that is reported by a different set of plugins in two scans changes fingerprint; Sec. IV-C measures how often this happens.",
        bold_prefix="Fingerprint-Based Delta Comparison: "
    )

    add_h2("D.  AI-Assistant Integration via Model Context Protocol (MCP) and CI/CD Delivery")
    add_p(
        "AutoSecAudit includes a JSON-RPC 2.0 stdio MCP server (mcp_server.py; protocol revision 2024-11-05) that lets AI developer tools such as Cursor, Claude Code, and Antigravity call the scanner [14]. It implements the initialize, tools/list, tools/call, and ping methods and exposes four tools (Table II). We distinguish four levels of remediation support: (a) generating predefined fix recipes, which is implemented; (b) exposing those recipes to an agent through MCP, which is implemented; (c) an agent applying a change to source code, which is performed by the agent's own editing tools and is outside the server; and (d) re-scanning to show that a change fixed the issue, which autosec_verify_fix does against the live target by re-running only the scanners relevant to the vulnerability type; it does not check for regressions elsewhere. Levels (a), (b), and (d) are implemented; none of them is evaluated against agent-applied patches in this paper."
    )

    # Table II
    t2_headers = ["MCP Tool Name", "Arguments", "Behavior as implemented", "Limitation in this release"]
    t2_rows = [
        ["autosec_scan", "target (required), profile, mock", "Runs a scan and returns grade, severity counts, and the threat matrix.", "mock defaults to true, so a call that omits it returns simulated findings; real scans must request mock=false."],
        ["autosec_get_findings", "report_id, view", "Reads a saved scan report and returns findings with business-danger text and fix recipes.", "Reads the saved report key 'all_findings' (an earlier release read 'findings' and returned no findings; fixed and covered by tests)."],
        ["autosec_get_fix_recipe", "finding_title (required), framework", "Returns static recipes (nodejs, python, nginx, waf) and a Markdown ticket for a title keyword.", "Keyword lookup; seven finding classes plus a generic fallback."],
        ["autosec_verify_fix", "target (required), vulnerability_type (required)", "Re-runs only the scanners for the vulnerability type against the target and reports RESOLVED or STILL_VULNERABLE; scan errors or an unreachable target are reported as errors, not as RESOLVED.", "Real by default (mock=false); checks one vulnerability type only and does not detect regressions elsewhere."]
    ]
    add_table_data("TABLE II   AUTOSECAUDIT MCP TOOLS AND THEIR CURRENT LIMITATIONS", t2_headers, t2_rows, widths=[1.6, 1.35, 1.9, 1.8])

    add_p(
        "The server therefore supports recipe delivery, scan access, and targeted re-testing for an AI assistant. It does not edit source files, and this paper does not demonstrate that a recipe or an agent-applied patch removes a vulnerability or avoids regressions; no patch-success rate is reported."
    )
    add_p(
        "For CI pipelines, the command-line scan accepts --fail-on with the values low, medium, high, or critical. If any finding meets or exceeds the threshold, the process returns exit code 1; it also returns 1 when the target is invalid or unreachable, and 0 otherwise. Progress is streamed to the web dashboard over Server-Sent Events (SSE), and reports can be exported as HTML, JSON, and ReportLab-generated PDF files."
    )

    # 7. Section IV: EVALUATION
    add_h1("IV.  EXPERIMENTAL EVALUATION AND RESULTS")
    add_p(
        f"Evaluation setup. All measurements were taken on one machine ({host['platform']}, {host['cpu_count']} logical CPUs, {host['ram_gb']} GB RAM, Python {host['python']}) that was also running ordinary desktop processes, so it was not an isolated or idle host. "
        f"The targets are the two built-in testbeds, started on 127.0.0.1 with an ephemeral port for each scan. Testbed 1 is a Flask application with {A1['total']} planted, detectable vulnerabilities (SQL injection, reflected XSS, SSTI, command injection, SSRF, path traversal, open redirect, IDOR, CSRF, insecure cookie, exposed .env file, and an unauthenticated admin page). "
        f"Testbed 2 requires a login and has {A2['total']} planted vulnerabilities plus two decoys that look vulnerable but are safe. "
        "Each scan used the full profile with the Nmap and Nikto wrappers excluded, so 17 of the 19 plugins ran. The ground truth for each testbed is a JSON file in benchmark/ground_truth; a finding is a true positive when its vulnerability type and normalized endpoint match a planted item, and a finding that matches a decoy or nothing is a false positive, except for informational findings such as missing security headers. "
        "The authors wrote the testbeds, the ground truth, and the plugins, so the accuracy results measure how well known cases are handled, not how the tool generalizes. Earlier versions of this paper reported results on OWASP Juice Shop; those figures had no retained raw data and relied on a consolidation step that the released code did not implement, so they are withdrawn and replaced by the measurements below. "
        "The raw per-run results are stored in benchmark/results/paper and can be regenerated with python -m benchmark.paper_experiments all. The evaluation addresses four research questions: "
        "RQ1 (Latency & Concurrency), RQ2 (Accuracy & Alert Consolidation), RQ3 (Delta Comparison Behavior), and RQ4 (Test Suite and Safety Checks)."
    )
    add_p(
        f"Evidence status. Each setting was run {n_reps} times. We report means, standard deviations, medians, and ranges; with this few runs no confidence interval or significance test is claimed, and the runs were not randomized beyond rotating the thread count within each repetition."
    )

    add_h2("A.  Concurrency and Execution Latency (RQ1)")
    add_p(
        f"Total scan time of testbed 1 was measured for worker thread counts k in {{{', '.join(str(k) for k in ks)}}}, {n_reps} times each (Table III, Fig. 2). "
        f"The median time was {med[1]:.1f} s at k=1 and {med[16]:.1f} s at k=16, and the fastest scan at every k was {min(min(v) for v in sec.values()):.1f} s to {max(min(v) for v in sec.values()):.1f} s, so on this target more threads did not make the scan faster. "
        f"Our earlier report of a 2.84x speedup is therefore not supported and is withdrawn. A plausible reason is that the scan contains a fixed amount of serial work: timing probes are deliberately serialized across plugins (Sec. III-B), and the testbed contains endpoints that sleep on purpose. We did not profile the scan, so this explanation is untested. "
        f"The timing was also unstable: {n_slow} of {n_scans} scans took longer than {FLOOR:.0f} s, {n_deadline} reached the 300 s scan deadline, and {n_lost} returned fewer than the usual {full_find} findings. These slow scans were spread across thread counts, and we did not isolate the cause (candidates are contention on the desktop, the serialized timing probes, and the plugin time limits). "
        "The CPU column reports process CPU time, which includes the in-process test server and is not a utilization percentage."
    )

    # Table III
    t3_headers = ["Worker Threads (k)", "Mean +/- SD (s)", "Median (s)", "Min-Max (s)", "Speedup (median)", "Process CPU (s)"]
    t3_rows = []
    for k in ks:
        t3_rows.append([
            f"{k}" + (" (sequential)" if k == 1 else ""),
            f"{statistics.fmean(sec[k]):.1f} +/- {statistics.stdev(sec[k]):.1f}",
            f"{med[k]:.1f}",
            f"{min(sec[k]):.1f}-{max(sec[k]):.1f}",
            f"{med[1] / med[k]:.2f}x",
            f"{statistics.fmean(cpu[k]):.1f}",
        ])
    add_table_data(f"TABLE III   SCAN TIME OF TESTBED 1 BY WORKER THREADS (n = {n_reps} SCANS PER ROW)", t3_headers, t3_rows, widths=[1.2, 1.2, 0.8, 1.1, 1.0, 1.0])

    add_figure('paper/figures/fig2_latency.png', f"Fig. 2.  Scan time (mean and standard deviation of {n_reps} scans) and speedup of the mean relative to k=1, by worker thread count.", width_in=4.5)

    add_h2("B.  Detection Accuracy and Alert Merging (RQ2)")
    add_p(
        "A true positive (TP) is a planted vulnerability matched by at least one finding, a false positive (FP) is a finding that matches a decoy or nothing in the ground truth, and a false negative (FN) is a planted vulnerability with no matching finding. "
        "Precision = TP/(TP+FP), recall = TP/(TP+FN), and F1 = 2PR/(P+R). Table IV gives the results per testbed. "
        f"Testbed 2 was fully detected in all {A2['n']} runs with no false positive, and both decoys were suppressed. Testbed 1 was fully detected in {A1['n_complete']} of {A1['n']} runs; the other {A1['n'] - A1['n_complete']} runs found {', '.join(str(x) for x in sorted(t for t in A1['tp'] if t < A1['total']))} of {A1['total']} because plugins hit the 300 s scan deadline, which the engine reports as a degraded scan. "
        f"None of the ten measured runs reported a false positive. However, an eleventh run of testbed 2, executed by the benchmark regression test during the test-suite run (Sec. IV-D), reported one: a missing-SameSite finding for the session cookie, labelled as CSRF at the root path, which matched no planted item and failed that test's zero-false-positive assertion. So the false-positive count is not stable at zero even here, and with applications whose planted items and decoys we chose ourselves it should not be read as a false-positive rate for real applications."
    )

    # Table IV
    t4_headers = ["Testbed", "Runs", "Planted", "TP mean (range)", "FP", "Precision", "Recall (mean)", "Raw alerts to merged findings*"]
    t4_rows = []
    for name, A in (("testbed1", A1), ("testbed2 (login, 2 decoys)", A2)):
        t4_rows.append([
            name, str(A['n']), str(A['total']),
            f"{statistics.fmean(A['tp']):.1f} ({min(A['tp'])}-{max(A['tp'])})",
            str(A['fp']), f"{A['prec']:.2f}", f"{A['rec']:.2f}",
            f"{A['raw']:.0f} to {A['merged']:.0f} ({100.0 * (A['raw'] - A['merged']) / A['raw']:.0f}% fewer)",
        ])
    add_table_data("TABLE IV   DETECTION ACCURACY ON THE BUILT-IN TESTBEDS (* COMPLETE SCANS ONLY)", t4_headers, t4_rows, widths=[1.35, 0.45, 0.6, 1.0, 0.35, 0.7, 0.75, 1.5])

    add_p(
        f"Alert merging. The pipeline merges findings that several plugins report for the same weakness on a canonical key (Sec. III-C). On complete scans, the {A1['raw']:.0f} raw plugin alerts of testbed 1 became {A1['merged']:.0f} findings ({red1:.0f}% fewer) and the {A2['raw']:.0f} alerts of testbed 2 became {A2['merged']:.0f} ({red2:.0f}% fewer; Fig. 3). "
        "Because the merge key was designed with these applications in view, the reduction is specific to them, and we did not measure whether any merge hid a distinct vulnerability beyond checking that all planted items remained matched."
    )

    add_figure('paper/figures/fig3_noise_reduction.png', "Fig. 3.  Mean raw plugin alerts and merged findings per scan on complete scans of each testbed.", width_in=4.0)

    add_h2("C.  Delta Comparison Behavior (RQ3)")
    add_p(
        "Delta comparison was tested on three consecutive real scans of testbed 1 whose application build was changed on purpose: build v1 hides the /template route, build v2 is the full application, and build v3 hides the /view route. "
        f"From the ground truth, the expected result of v1 to v2 is {len(dl2['expected_new_items'])} new findings (SSTI and XSS at /template) and none fixed, and of v2 to v3 is {len(dl2['expected_fixed_items'])} fixed findings (path traversal and XSS at /view) and none new. "
        f"The experiment was executed twice. In the second execution all three scans were complete ({dl2['v1_findings']}, {dl2['v2_findings']}, and {dl2['v3_findings']} findings), and the delta was exact: v1 to v2 gave {d2a['new_count']} new, {d2a['fixed_count']} fixed, and {d2a['unchanged_count']} unchanged findings, and v2 to v3 gave {d2b['new_count']} new, {d2b['fixed_count']} fixed, and {d2b['unchanged_count']} unchanged (Fig. 4). "
        f"In the first execution the scans were incomplete (they returned fewer findings than a complete scan; the engine's degraded flag was not logged) and returned {dl1['v1_findings']}, {dl1['v2_findings']}, and {dl1['v3_findings']} findings; the delta then reported {d1a['new_count']} new and {d1a['fixed_count']} fixed findings for v1 to v2 and {d1b['new_count']} new and {d1b['fixed_count']} fixed for v2 to v3, which includes findings that had not changed (the admin page and the exposed .env file each appeared as both new and fixed, and the IDOR finding was absent from one scan). "
        "In the complete scans the fingerprints of identical findings were identical. The first execution did not log fingerprints, so the cause of the paired new/fixed entries is untested; it is consistent with a change in the set of plugins that reported the finding, because the reporting tool is part of the fingerprint (Sec. III-C). "
        "A delta is therefore only as reliable as the scans it compares, and a release gate should refuse to compare scans that the engine marks as degraded or that return fewer findings than expected. "
        "This check covers one application and two build changes and is not a general fidelity figure."
    )

    add_figure('paper/figures/fig4_delta_diff.png', "Fig. 4.  Delta results per build transition in two executions, compared with the expected counts (hatched).", width_in=4.8)

    add_h2("D.  Test Suite and Safety Checks (RQ4)")
    add_p(
        f"The project's runner (run_tests.py) executed {TEST_COUNT} tests in our verification run (parallel worker processes, with timing-sensitive modules re-run alone); {TEST_COUNT - 1} passed and 1 failed. The failure is the benchmark regression test test_benchmark_builtin_testbed1_and_testbed2, which asserts zero false positives and failed because testbed 2 reported the cookie finding described in Sec. IV-B; it failed again when re-run alone, so the suite is not fully green. The tests are isolated from the persistent user database by a per-worker temporary data directory, which fixes the non-idempotent authentication test noted in an earlier version. "
        "They cover plugin behavior, the timing engine, the JSON fuzzer, the danger engine and recipes, MCP message handling, scan profiles, target reachability, report escaping, and the --fail-on exit code, and several run real scans against local fixture servers. "
        "Regression tests also check safety properties: logout and other state-changing paths are never probed (test_probe_safety.py), redirects to out-of-scope hosts are not followed (test_b09_shared_http_client.py), the dashboard rejects POST requests without a CSRF token, throttles repeated failed logins, sets session cookie attributes, requires a POST with a CSRF token to log out, and hides one user's reports from another (test_b05_web_hardening.py and test_b20_dashboard_ownership_and_session.py), and the dashboard binds to 127.0.0.1 by default. "
        "These are regression checks written by the developers, not an independent security assessment, and they do not show that no vulnerability remains in the tool itself."
    )

    # 8. Section V: DISCUSSION
    add_h1("V.  DISCUSSION, LIMITATIONS, AND DEPLOYMENT CONSIDERATIONS")
    add_p(
        "Deployment considerations. (1) Single-page applications: regular-expression extraction finds API routes embedded in the HTML of visited pages, but externally loaded JavaScript bundles are not analyzed; pairing the crawler with a headless browser (for example Playwright) would be needed for full DOM-driven discovery. (2) Offline operation: CVSS enrichment applies only to findings that carry a CVE identifier, uses 2 s network timeouts, and is skipped silently when NVD and CIRCL are unreachable; there is no embedded offline CVE dictionary. The CWE and PCI DSS tables used by the compliance mapper are built in. (3) Enterprise authentication: SAML 2.0 and mTLS flows are not supported by the automatic authenticator; pre-authenticated headers can be supplied with the --headers option. (4) Default mode: the configuration default is mock mode (AUTOSEC_MOCK_MODE=true), and the MCP autosec_scan tool also defaults to mock, so real scans must be requested explicitly. (5) Transport: scanner requests disable TLS certificate verification. (6) Scan completeness: a scan that reaches its deadline is marked degraded, and such a scan should not be used for release gating or delta comparison (Sec. IV-A and IV-C)."
    )
    add_p(
        "Limitations and threats to validity. The evaluation uses two small applications that the authors wrote together with the tool and its ground truth, one machine that was not isolated, and five repetitions per setting, so the accuracy figures describe known cases and not real-world performance, and no statistical inference is made. "
        "The parallel speedup reported in earlier versions is not reproduced: scan time did not fall with more threads, the cause was not profiled, and scans were intermittently slow or truncated by the 300 s deadline. Only 17 of the 19 plugins ran in the evaluation because the Nmap and Nikto wrappers need external binaries. "
        "The merge key and the delta fingerprint were designed with these testbeds in view, delta behavior was checked on one application and two build changes, and the scope guard resolves names once, so a changing DNS answer is not detected. "
        "The JWT plugin inspects tokens passively, and the fix recipes cover seven finding classes and were not applied to a vulnerable application and re-scanned. No head-to-head comparison with ZAP, Burp Suite, Nuclei, or other tools was performed, and the fix recipes and danger grades were not validated with developers or executives."
    )
    add_p(
        "Recommended follow-up work. (a) Profile a scan to find the serial work that sets the 53 s floor and the cause of the intermittent slow and truncated scans, then repeat the thread sweep on an idle machine. (b) Evaluate on independent intentionally vulnerable applications such as VAmPI, PyGoat, Vulpy, and a pinned OWASP Juice Shop image [15], using the ground-truth files and harness in the benchmark directory, with two independent annotators. (c) Make delta comparison refuse, or flag, scans that the engine marks as degraded. (d) Run an agent-in-the-loop study that applies recipes, re-scans, and checks for regressions. (e) Compare against ZAP baseline and API scans on the same targets. (f) Add recipes for the finding classes that have none."
    )

    # 9. Section VI: CONCLUSION
    add_h1("VI.  CONCLUSION AND FUTURE WORK")
    add_p(
        f"AutoSecAudit is an open, extensible DAST orchestration framework that runs 19 scanner plugins concurrently through one shared HTTP client, applies heuristic false-positive reduction, merges duplicate findings, annotates them with compliance and business-risk context, offers predefined fix recipes, and exposes scanning, recipe lookup, and targeted re-testing to AI coding assistants through an MCP server. "
        f"On two small purpose-built applications it found all planted vulnerabilities when its scans completed ({A1['n_complete']} of {A1['n']} runs on testbed 1 and all {A2['n']} on testbed 2), and merging reduced raw alerts by {red1:.0f}% and {red2:.0f}%; false positives were absent in ten measured runs but one appeared in a further run. "
        f"The evaluation also exposed weaknesses: more worker threads did not shorten scans, some scans were slow or reached the scan deadline and lost findings, and delta comparison gave spurious changes when scans were incomplete. "
        "These results are small-scale, come from applications the authors wrote, and replace earlier figures that could not be reproduced. Closed-loop AI remediation, in which an agent applies a patch and a live re-scan confirms the fix without regressions, remains future work. Further work will address the limitations in Sec. V, evaluate independent vulnerable applications, and explore distributed multi-node scanning."
    )

    # 10. ACKNOWLEDGMENT
    add_h1("ACKNOWLEDGMENT")
    add_p(
        "This research was conducted as part of the AutoSec Security Engineering Initiative in the Department of Computer Science and Engineering at Don Bosco Institute of Technology, Bangalore. The authors express sincere gratitude to faculty mentor Ms. Ranjitha R, department leadership, and the open-source security engineering community for foundational tools, benchmark platforms, and ongoing support."
    )

    # 11. REFERENCES
    add_h1("REFERENCES")
    refs = [
        "[1] G. F. Lyon, Nmap Network Scanning: The Official Nmap Project Guide to Network Discovery and Vulnerability Scanning. Insecure.Com LLC, 2009.",
        "[2] C. Sullo, \"Nikto web server scanner,\" open-source software, version 2.6. Available: https://github.com/sullo/nikto (accessed Oct. 2026)",
        "[3] ProjectDiscovery, \"Nuclei: Fast and Customizable Vulnerability Scanner Based on Simple YAML DSL,\" 2024. Available: https://github.com/projectdiscovery/nuclei",
        "[4] OWASP Foundation, \"OWASP Zed Attack Proxy (ZAP),\" 2024. Available: https://www.zaproxy.org/",
        "[5] OWASP Foundation, \"OWASP DefectDojo: Vulnerability Management Orchestration,\" 2024. Available: https://www.defectdojo.org/",
        "[6] OWASP Top 10 Team, \"OWASP Top 10: 2021 The Ten Most Critical Web Application Security Risks,\" OWASP Foundation, 2021. Available: https://owasp.org/Top10/",
        "[7] PCI Security Standards Council, Payment Card Industry Data Security Standard (PCI DSS): Requirements and Testing Procedures, Version 4.0, 2022. Available: https://www.pcisecuritystandards.org/document_library/ (accessed Oct. 2026)",
        "[8] National Institute of Standards and Technology (NIST), \"National Vulnerability Database (NVD) REST API v2.0,\" U.S. Department of Commerce, 2023. Available: https://nvd.nist.gov/developers/vulnerabilities (accessed Oct. 2026)",
        "[9] M. Myrbakken and R. Colomo-Palacios, \"DevSecOps: A Multivocal Literature Review,\" in Communications in Computer and Information Science, vol. 770, Springer, 2017, pp. 17\u201329.",
        "[10] J. Bau, E. Bursztein, D. Gupta, and J. C. Mitchell, \"State of the Art: Automated Black-Box Web Application Vulnerability Testing,\" in Proc. 31st IEEE Symposium on Security and Privacy (S&P '10), 2010, pp. 332\u2013345.",
        "[11] A. Doup\u00e9, M. Cova, and G. Vigna, \"Enemy of the State: A State-Aware Black-Box Web Vulnerability Scanner,\" in Proc. 21st USENIX Security Symposium (USENIX Security '12), 2012, pp. 523\u2013538.",
        "[12] V. Atlidakis, P. Godefroid, and M. Polishchuk, \"RESTler: Stateful REST API Fuzzing,\" in Proc. 41st IEEE/ACM International Conference on Software Engineering (ICSE '19), 2019, pp. 748\u2013758.",
        "[13] B. Johnson, Y. Song, E. Murphy-Hill, and R. Bowdidge, \"Why Don't Software Developers Use Static Analysis Tools to Find Bugs?\" in Proc. 35th IEEE/ACM International Conference on Software Engineering (ICSE '13), 2013, pp. 672\u2013681.",
        "[14] Anthropic, \"Model Context Protocol (MCP) Specification,\" 2024. Available: https://modelcontextprotocol.io",
        "[15] OWASP Foundation, \"OWASP Juice Shop,\" project page. Available: https://owasp.org/www-project-juice-shop/",
        "[16] ZAP Project, \"Automation Framework,\" ZAP documentation. Available: https://www.zaproxy.org/docs/automate/automation-framework/",
        "[17] PortSwigger, \"Burp Suite MCP Server extension,\" GitHub repository. Available: https://github.com/PortSwigger/mcp-server",
        "[18] ZAP Project, \"MCP Integration add-on,\" ZAP documentation. Available: https://www.zaproxy.org/docs/desktop/addons/mcp-integration/",
        "[19] DefectDojo, \"About Deduplication\" and \"Reimport,\" DefectDojo documentation. Available: https://docs.defectdojo.com/"
    ]
    for r in refs:
        p_ref = doc.add_paragraph(style=style_of('IEEE Reference Item'))
        p_ref.add_run(re.sub(r'^\[\d+\]\s*', '', r))  # [n] label comes from the style's numbering

    # 12. BIOGRAPHY
    add_h1("BIOGRAPHY")
    add_p(
        "The authors are undergraduate research scholars and faculty mentors in the Department of Computer Science and Engineering at Don Bosco Institute of Technology (DBIT), Bangalore, affiliated with Visvesvaraya Technological University (VTU), Belagavi, Karnataka, India. Their research focuses on automated vulnerability assessment, DevSecOps engineering, intelligent security orchestration, and agentic AI remediation systems."
    )

    # Save DOCX
    doc.save(docx_path)
    shutil.copy(docx_path, root_docx)
    print(f"Generated clean DOCX: {docx_path}")

    # Convert to PDF via Word COM
    word = win32com.client.Dispatch('Word.Application')
    word.Visible = False
    try:
        wdoc = word.Documents.Open(docx_path)
        wdoc.SaveAs(pdf_path, FileFormat=17) # 17 = wdFormatPDF
        wdoc.Close(SaveChanges=0)  # keep the python-docx file as built; do not let Word re-save it
        shutil.copy(pdf_path, root_pdf)
        print(f"Generated clean PDF: {pdf_path}")
        print(f"PDF size: {os.path.getsize(pdf_path)} bytes")
    finally:
        word.Quit()

if __name__ == '__main__':
    build_paper()
