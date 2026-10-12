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

# ---- tables: recompute from the document itself
def table_rows(t):
    return [[c.text.strip() for c in r.cells] for r in t.rows]

t3 = table_rows(d.tables[2])
lat = {int(re.match(r"(\d+)", r[0]).group(1)): float(r[1].split()[0]) for r in t3[1:]}
spd = {int(re.match(r"(\d+)", r[0]).group(1)): float(r[2].rstrip("x")) for r in t3[1:]}
chk("Table III speedups recomputed", all(round(lat[1] / lat[k], 2) == spd[k] for k in lat), str({k: round(lat[1] / lat[k], 2) for k in lat}))
red = (lat[1] - lat[8]) / lat[1] * 100
chk("64.8% latency reduction", round(red, 1) == 64.8, f"{red:.2f}%")

t4 = table_rows(d.tables[3])
rows = t4[1:-1]
tot = t4[-1]
tp = sum(int(r[1]) for r in rows); fp = sum(int(r[2]) for r in rows); raw = sum(int(r[3]) for r in rows); cor = sum(int(r[4]) for r in rows)
chk("Table IV column sums = totals row", (tp, fp, raw) == (int(tot[1]), int(tot[2]), int(tot[3])) and cor == int(tot[4].split()[0]), f"TP={tp} FP={fp} raw={raw} cons={cor}")
chk("Table IV row consolidated = TP+FP", all(int(r[4]) == int(r[1]) + int(r[2]) for r in rows))
GT = 52
prec, rec = tp / (tp + fp), tp / GT
f1 = 2 * prec * rec / (prec + rec)
chk("precision 97.9%", round(prec * 100, 1) == 97.9, f"{prec*100:.2f}")
chk("recall 88.5%", round(rec * 100, 1) == 88.5, f"{rec*100:.2f}")
chk("F1 92.9%", round(f1 * 100, 1) == 92.9, f"{f1*100:.2f}")
chk("alert reduction 38.2%", round((raw - cor) / raw * 100, 1) == 38.2, f"{(raw-cor)/raw*100:.2f}")
chk("delta arithmetic 47-10+3=40, 40-14=26", 47 - 10 + 3 == 40 and 40 - 14 == 26)

# ---- cross-section agreement of headline numbers
abstract = next(t for t in paras if t.startswith("Abstract"))
concl_i = next(i for i, t in enumerate(paras) if t.strip() == "CONCLUSION AND FUTURE WORK")
conclusion = paras[concl_i + 1]
for token in ("184.2", "64.8%", "2.84x", "76", "47", "97.9%", "88.5%", "52"):
    chk(f"abstract contains {token}", token in abstract)
for token in ("64.8%", "2.84x", "97.9%", "88.5%", "38.2%"):
    chk(f"conclusion contains {token}", token in conclusion)
chk("results text gives F1 and FN", "92.9%" in main_text and "6 FN" in main_text)

# ---- claims that must NOT remain (or must be negated)
def occurrences(pattern):
    return [m.start() for m in re.finditer(pattern, main_text, flags=re.I)]

chk("no 'false alarms are eliminated'", not occurrences(r"false alarms are eliminated"))
chk("no '100% classification fidelity'", not occurrences(r"100% classification"))
chk("no 'Autonomous AI Remediation' claim", not occurrences(r"autonomous ai remediation"))
chk("no 'guarantee reliable'", not occurrences(r"guarantee"))
chk("no unqualified 'compound-key deduplication'", all("not part of the released" in main_text[max(0, p - 120):p + 200] or "compound-key merge" in main_text[p:p + 20] for p in occurrences(r"compound-key dedup")))
chk("no 'breadth-first' except negation", all("not breadth-first" in main_text[max(0, p - 20):p + 40] for p in occurrences(r"breadth-first")))
chk("no autosec_list_scanners", "autosec_list_scanners" not in body)
chk("no embedded offline CVE dictionary claim except negation", all("no embedded offline" in main_text[max(0, p - 30):p + 60] for p in occurrences(r"offline CVE")))
chk("no 'weak HMAC secrets' except negation", all("does not test weak HMAC" in main_text[max(0, p - 30):p + 60] for p in occurrences(r"weak HMAC")))
chk("no 'stored XSS' claim", not occurrences(r"stored XSS"))
chk("timing formula matches code (0.70, 0.35; no 3*sigma)", "rho = 0.70" in main_text and "0.35*tau" in main_text and "3*sigma" not in main_text)
chk("thread default disclosed (4)", "default 4" in main_text)
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
