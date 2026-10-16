"""Final validation of the revised AutoSecAudit paper (DOCX + PDF).

Run from the repository root:  python paper/revision_audit/validate_final.py
Checks internal consistency only; it cannot establish that the underlying measurements are real.
"""
import re
import subprocess
import sys
import docx
from docx.oxml.ns import qn

DOCX = "AutoSecAudit_Research_Paper_IJARCCE.docx"
PDF = "AutoSecAudit_Research_Paper_IJARCCE.pdf"
results = []


def chk(name, ok, detail=""):
    results.append(ok)
    print(("PASS  " if ok else "FAIL  ") + name + (" :: " + detail if detail else ""))


d = docx.Document(DOCX)
# paragraph text including field results (caption numbers are SEQ fields in the IJARCCE template)
paras = [p._p.xpath("string(.)") for p in d.paragraphs]
styles = [p.style.name for p in d.paragraphs]
body = "\n".join(paras)
idx_ref = next(i for i, t in enumerate(paras) if t.strip() == "REFERENCES")
idx_bio = next(i for i, t in enumerate(paras) if t.strip() == "BIOGRAPHY")
main_text = "\n".join(paras[:idx_ref])
ref_text = [t for t, st in zip(paras[idx_ref + 1:idx_bio], styles[idx_ref + 1:idx_bio]) if st == "IEEE Reference Item"]

# ---- preserved front matter
chk("author names preserved", "Kodi Vishruth Aithal, Thilak N, Vinaya Kumar B, Vishal Gowda B, Ranjitha R*" in body)
chk("affiliation preserved", "Don Bosco Institute of Technology, Bangalore, Karnataka, India" in body)
chk("corresponding author designation preserved", "(*Corresponding Author & Faculty Mentor)" in body)
chk("emails preserved", "ranjitha.r@dbit.co.in" in body and "aithalvishruth" in body)
chk("acknowledgment preserved", "ACKNOWLEDGMENT" in body and "faculty mentor Ms. Ranjitha R" in body)

# ---- structure
chk("4 figures embedded", len(d.inline_shapes) == 4, str(len(d.inline_shapes)))
chk("4 tables present", len(d.tables) == 4, str(len(d.tables)))
for cap in ("TABLE I ", "TABLE II ", "TABLE III ", "TABLE IV "):
    chk(f"caption {cap.strip()}", cap in body)
for f in ("Fig. 1.", "Fig. 2.", "Fig. 3.", "Fig. 4."):
    chk(f"caption {f}", f in body)
    chk(f"{f} referenced in text", re.search(r"Fig\. " + f[-2] + r"(?!\.\s{2})", main_text.replace(f, "")) is not None)

# ---- references: every [n] cited, none out of range
cited = set()
cite_text = main_text.replace("range [10, 100]", "range")  # numeric interval, not a citation
for m in re.finditer(r"\[(\d+(?:[,\s\-]+\d+)*)\]", cite_text):
    for part in re.split(r"[,\s]+", m.group(1)):
        if part.isdigit():
            cited.add(int(part))
for m in re.finditer(r"\[(\d+)\],\s*\[(\d+)\]", cite_text):
    cited.update({int(m.group(1)), int(m.group(2))})
n_refs = len([r for r in ref_text if r.strip()])  # [n] labels come from the template list numbering
chk("reference list size", n_refs == 19, str(n_refs))
chk("all references 1..19 cited in body", set(range(1, 20)) <= cited, "missing: " + str(sorted(set(range(1, 20)) - cited)))
chk("no citation beyond list", max(cited) <= n_refs, str(max(cited)))

# ---- tables: recompute from the document itself and from the raw experiment output
import json
import os
import statistics


def table_rows(t):
    return [[c.text.strip() for c in r.cells] for r in t.rows]


def load(name):
    with open(os.path.join("benchmark", "results", "paper", name + ".json"), encoding="utf8") as fh:
        return json.load(fh)


sc, acc, dl2, dl1 = load("scaling"), load("accuracy"), load("delta"), load("delta_run1")

t3 = table_rows(d.tables[2])
ks = sorted(int(k) for k in sc["runs"])
sec = {k: [r["seconds"] for r in sc["runs"][str(k)]] for k in ks}
chk("Table III has one row per thread count", len(t3) == len(ks) + 1, str(len(t3) - 1))
ok_rows = True
for row, k in zip(t3[1:], ks):
    mean, sd = statistics.fmean(sec[k]), statistics.stdev(sec[k])
    med = statistics.median(sec[k])
    ok_rows &= row[1] == f"{mean:.1f} +/- {sd:.1f}" and row[2] == f"{med:.1f}"
    ok_rows &= row[3] == f"{min(sec[k]):.1f}-{max(sec[k]):.1f}"
    ok_rows &= row[4] == f"{statistics.median(sec[ks[0]]) / med:.2f}x"
chk("Table III matches raw scaling.json (mean, SD, median, range, speedup)", ok_rows)

t4 = table_rows(d.tables[3])
ok4 = True
for row, name in zip(t4[1:], ("testbed1", "testbed2")):
    runs = acc["runs"][name]
    tp = [r["tp"] for r in runs]
    complete = [r for r in runs if r["tp"] == r["total_real"]]
    raw = statistics.fmean(r["raw_alerts"] for r in complete)
    merged = statistics.fmean(r["raw_findings"] for r in complete)
    ok4 &= row[1] == str(len(runs)) and row[2] == str(runs[0]["total_real"])
    ok4 &= row[3] == f"{statistics.fmean(tp):.1f} ({min(tp)}-{max(tp)})"
    ok4 &= row[4] == str(sum(r["fp"] for r in runs))
    ok4 &= row[6] == f"{statistics.fmean(r['recall'] for r in runs):.2f}"
    ok4 &= row[7].startswith(f"{raw:.0f} to {merged:.0f}")
chk("Table IV matches raw accuracy.json", ok4)
chk("accuracy runs all report 17 of 17 plugins run", all(r["plugins_run"] == 17 for n in acc["runs"] for r in acc["runs"][n]))

# delta numbers in the text equal the raw delta files
dtxt = main_text
for dd in (dl1, dl2):
    for key in ("v1_to_v2", "v2_to_v3"):
        sm = dd[key]["summary"]
        chk(f"delta {key} counts appear in text ({sm['new_count']}/{sm['fixed_count']}/{sm['unchanged_count']})",
            f"{sm['new_count']} new" in dtxt and f"{sm['fixed_count']} fixed" in dtxt)
chk("delta run 2 is exact (2 new,0 fixed then 0 new,2 fixed)",
    (dl2["v1_to_v2"]["summary"]["new_count"], dl2["v1_to_v2"]["summary"]["fixed_count"],
     dl2["v2_to_v3"]["summary"]["new_count"], dl2["v2_to_v3"]["summary"]["fixed_count"]) == (2, 0, 0, 2))

# ---- cross-section agreement of headline numbers
abstract = next(t for t in paras if t.startswith("Abstract"))
concl_i = next(i for i, t in enumerate(paras) if t.strip() == "CONCLUSION AND FUTURE WORK")
conclusion = paras[concl_i + 1]
a1, a2 = acc["runs"]["testbed1"], acc["runs"]["testbed2"]
full1 = sum(1 for r in a1 if r["tp"] == r["total_real"])
chk("abstract states testbed 1 complete-run count", f"{full1} of {len(a1)} runs" in abstract, str(full1))
chk("abstract states the 17/8 planted vulnerabilities", "17 and 8 planted" in abstract)
chk("abstract withdraws the speedup claim", "earlier speedup claim is withdrawn" in abstract)
chk("abstract discloses the false positive seen in the test-suite run", "one further testbed 2 run" in abstract)
chk("conclusion states complete-run count", f"{full1} of {len(a1)} runs on testbed 1" in conclusion)
chk("old Juice Shop figures are not reported as results",
    not any(tok in main_text for tok in ("184.2", "64.8", "97.9%", "88.5%", "38.2%", "76 raw", "47 findings")))
chk("old results are explicitly withdrawn", "withdrawn" in main_text)
chk("test count in text matches the recorded run (578, 577 passed, 1 failed)", "578 tests" in main_text and "577 passed and 1 failed" in main_text)

# ---- claims that must NOT remain (or must be negated)
def occurrences(pattern):
    return [m.start() for m in re.finditer(pattern, main_text, flags=re.I)]

chk("no 'false alarms are eliminated'", not occurrences(r"false alarms are eliminated"))
chk("no '100% classification fidelity'", not occurrences(r"100% classification"))
chk("no 'Autonomous AI Remediation' claim", not occurrences(r"autonomous ai remediation"))
chk("no 'guarantee reliable'", not occurrences(r"guarantee"))
chk("no 'compound-key deduplication' wording", not occurrences(r"compound-key dedup"))
chk("no 'breadth-first' except negation", all("not breadth-first" in main_text[max(0, p - 20):p + 40] for p in occurrences(r"breadth-first")))
chk("no autosec_list_scanners", "autosec_list_scanners" not in body)
chk("no embedded offline CVE dictionary claim except negation", all("no embedded offline" in main_text[max(0, p - 30):p + 60] for p in occurrences(r"offline CVE")))
chk("no 'weak HMAC secrets' except negation", all("does not test weak HMAC" in main_text[max(0, p - 30):p + 60] for p in occurrences(r"weak HMAC")))
chk("no 'stored XSS' claim", not occurrences(r"stored XSS"))
chk("timing formula matches code (max(3*sigma, 0.70*tau); control 0.35*tau)", "max(3*sigma_base, 0.70*tau)" in main_text and "0.35*tau" in main_text)
chk("thread default disclosed (4)", "default 4" in main_text)
chk("scope guard described as resolution-based, not lexical", "resolved through DNS" in main_text and "lexical" not in main_text)
chk("delta described as fingerprint-based, not identifier-based", "content fingerprint" in main_text and "identifier-based" not in main_text.lower())
chk("no stale test counts (165/161/492)", not any(t in main_text for t in ("165 tests", "161 tests", "492")))
chk("MCP default-mock caveat kept (Table II and Sec. V)", any("mock defaults to true" in c.text for r in d.tables[1].rows for c in r.cells) and "autosec_scan tool also defaults to mock" in body)
chk("Table II lists exactly 4 MCP tools", len(d.tables[1].rows) == 5)

# ---- IJARCCE template compliance (styles, numbering, header/footer, page setup)
import zipfile
from collections import Counter
sty = Counter(styles)
chk("built on the IJARCCE template styles", all(k in sty for k in ("IEEE Title", "IEEE Author Affiliation", "IEEE Abtract", "IEEE Heading 1", "IEEE Heading 2", "IEEE Paragraph", "IEEE Figure", "IEEE Table Caption", "IEEE Reference Item")), str(dict(sty)))
chk("one IEEE Title for the title plus author line", paras[0].startswith("AutoSecAudit:") and styles[0] == "IEEE Title" and styles[2] == "IEEE Title")
chk("6 numbered level-1 sections + Acknowledgment, References, Biography", sty["IEEE Heading 1"] == 9, str(sty["IEEE Heading 1"]))
chk("no manual numerals in headings (numbering comes from styles)", not any(re.match(r"^([IVX]+|[A-H])\.\s", t) for t, st in zip(paras, styles) if st in ("IEEE Heading 1", "IEEE Heading 2")))
chk("references use the template reference list style (19)", sty["IEEE Reference Item"] == 19, str(sty["IEEE Reference Item"]))
chk("captions use template caption styles (4 + 4)", sty["IEEE Table Caption"] == 4 and sty["IEEE Figure Caption Multi-Lines"] == 4)
sec = d.sections[0]
chk("single A4 section, 0.8 inch margins", len(d.sections) == 1 and round(sec.page_width.inches, 2) == 8.27 and all(round(m.inches, 2) == 0.8 for m in (sec.left_margin, sec.right_margin, sec.top_margin, sec.bottom_margin)))
zf = zipfile.ZipFile(DOCX)
hdr = " ".join(zf.read(n).decode("utf8", "ignore") for n in zf.namelist() if n.startswith("word/header"))
ftr = " ".join(zf.read(n).decode("utf8", "ignore") for n in zf.namelist() if n.startswith("word/footer"))
chk("no running header (placeholders removed)", not d.sections[0]._sectPr.findall(qn("w:headerReference")) and "Vol. 15" not in re.sub(r"<[^>]+>", "", " ".join(zf.read(n).decode("utf8", "ignore") for n in zf.namelist() if n == "word/document.xml")))
chk("IJARCCE footer licence line with PAGE field", "Creative Commons Attribution 4.0" in re.sub(r"<[^>]+>", "", ftr) and "PAGE" in ftr)
fonts = Counter(r.font.name for p in d.paragraphs for r in p.runs if r.font.name)
chk("fonts: Times New Roman (style default) plus Courier New only for code boxes", set(fonts) <= {"Courier New"}, str(dict(fonts)))
sizes = {r.font.size.pt for p, st in zip(d.paragraphs, styles) if st in ("IEEE Heading 1", "IEEE Heading 2", "IEEE Paragraph") for r in p.runs if r.font.size and r.font.name != "Courier New"}
chk("body/heading runs carry no size override (10 pt comes from styles)", sizes <= {10.0}, str(sizes))

# ---- PDF
out = subprocess.run(["pdfinfo", PDF], capture_output=True, text=True).stdout
pages = int(re.search(r"Pages:\s+(\d+)", out).group(1))
chk("PDF page count", 9 <= pages <= 13, str(pages))
txt = subprocess.run(["pdftotext", "-layout", PDF, "-"], capture_output=True, text=True).stdout
for token in ("TABLE I ", "TABLE II ", "TABLE III ", "TABLE IV ", "Fig. 1.", "Fig. 4.", "Doupé", "[19] DefectDojo"):
    chk(f"PDF text contains {token.strip()}", token in txt)
chk("PDF has no replacement characters", "�" not in txt)
imgs = subprocess.run(["pdfimages", "-list", PDF], capture_output=True, text=True).stdout.strip().splitlines()
# the IJARCCE header repeats a small logo on every page; figures are the wide images
figs = [l for l in imgs[2:] if int(l.split()[3]) >= 500]
chk("PDF contains 4 figure images", len(figs) == 4, str(len(figs)))

print(f"\n{sum(results)}/{len(results)} checks passed")
sys.exit(0 if all(results) else 1)
