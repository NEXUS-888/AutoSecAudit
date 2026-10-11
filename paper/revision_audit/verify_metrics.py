"""Recompute every derived metric reported in the AutoSecAudit paper from its stated inputs.

This checks arithmetic consistency only. It does NOT validate that the underlying
measurements (latencies, TP/FP counts, ground truth) are real; raw logs are not in the repository.
"""
latency = {1: 184.2, 2: 102.5, 4: 71.4, 8: 64.8, 16: 66.1}
paper_speedup = {1: 1.00, 2: 1.80, 4: 2.58, 8: 2.84, 16: 2.79}
rows = {  # class: (TP, FP, raw, correlated)
    "Injection": (8, 0, 14, 8), "XSS/CSRF": (12, 1, 19, 13), "Misconfig/Recon": (15, 0, 26, 15),
    "Access/Traversal": (6, 0, 9, 6), "API/Tokens": (5, 0, 8, 5)}
GT, RAW, CORR, TP, FP = 52, 76, 47, 46, 1
checks = []
def chk(name, ok, detail): checks.append((name, ok, detail)); print(("PASS " if ok else "FAIL ") + name + " :: " + detail)

for k, t in latency.items():
    sp = latency[1] / t
    chk(f"speedup k={k}", round(sp, 2) == paper_speedup[k], f"{sp:.4f} vs reported {paper_speedup[k]}")
red = (latency[1] - latency[8]) / latency[1] * 100
chk("latency reduction 8 workers", round(red, 1) == 64.8, f"{red:.2f}%")
chk("sums TP", sum(r[0] for r in rows.values()) == TP, str(sum(r[0] for r in rows.values())))
chk("sums FP", sum(r[1] for r in rows.values()) == FP, str(sum(r[1] for r in rows.values())))
chk("sums raw", sum(r[2] for r in rows.values()) == RAW, str(sum(r[2] for r in rows.values())))
chk("sums correlated", sum(r[3] for r in rows.values()) == CORR, str(sum(r[3] for r in rows.values())))
for n, (tp, fp, raw, cor) in rows.items():
    chk(f"row correlated=TP+FP [{n}]", cor == tp + fp, f"{cor} vs {tp}+{fp}")
prec, rec = TP / CORR, TP / GT
f1 = 2 * prec * rec / (prec + rec)
chk("precision", round(prec * 100, 1) == 97.9, f"{prec*100:.2f}%")
chk("recall", round(rec * 100, 1) == 88.5, f"{rec*100:.2f}%")
chk("F1", round(f1 * 100, 1) == 92.9, f"{f1*100:.2f}%  (=2TP/(2TP+FP+FN)={2*TP/(2*TP+FP+(GT-TP)):.4f})")
noise = (RAW - CORR) / RAW * 100
chk("alert reduction", round(noise, 1) == 38.2, f"{noise:.2f}% ({RAW-CORR} of {RAW} alerts)")
chk("FN = GT - TP", GT - TP == 6, f"{GT-TP}")
chk("delta v1.1 active", 47 - 10 + 3 == 40 and 47 - 10 == 37, "47-10+3=40; unchanged 37")
chk("delta v1.2 active", 40 - 14 == 26, "40-14=26")
bad = [c for c in checks if not c[1]]
print(f"\n{len(checks)-len(bad)}/{len(checks)} arithmetic checks passed")
raise SystemExit(1 if bad else 0)
