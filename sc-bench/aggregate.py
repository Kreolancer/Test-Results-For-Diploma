#!/usr/bin/env python3
"""Агрегатор результатов Slither (слепой режим) в единую CSV."""
import csv, json, re
from pathlib import Path

CORPUS = Path("/home/andrei/Рабочий стол/Kursovaya/Diplom/contracts")
RESULTS = Path.home() / "sc-bench/results/slither_blind"
META = CORPUS / "metadata.csv"
OUT = Path.home() / "sc-bench/results/slither_results.csv"

# маппинг сигнальных детекторов -> SC-класс
DET2SC = {}
for sc, dets in {
    "SC01": ["arbitrary-send-eth","arbitrary-send-erc20","suicidal","tx-origin",
             "controlled-delegatecall","incorrect-modifier"],
    "SC05": ["timestamp","weak-prng","missing-zero-check"],
    "SC06": ["unchecked-lowlevel","unchecked-send","unchecked-transfer",
             "unused-return","low-level-calls","locked-ether","calls-loop"],
    "SC08": ["reentrancy-eth","reentrancy-no-eth","reentrancy-benign",
             "reentrancy-events","reentrancy-unlimited-gas"],
    "SC09": ["divide-before-multiply","incorrect-equality","tautology",
             "controlled-array-length"],
}.items():
    for d in dets:
        DET2SC[d] = sc

def parse_time(p):
    """Возвращает (sec, mem_mb) из файла /usr/bin/time -v."""
    sec, mem = None, None
    if not p.exists():
        return sec, mem
    txt = p.read_text(errors="ignore")
    m = re.search(r"Elapsed.*?:\s*([\d:.]+)", txt)
    if m:
        parts = m.group(1).split(":")
        sec = float(parts[-1]) + (float(parts[-2])*60 if len(parts) > 1 else 0)
    m = re.search(r"Maximum resident set size \(kbytes\):\s*(\d+)", txt)
    if m:
        mem = int(m.group(1)) / 1024.0
    return sec, mem

def load_findings(jpath):
    """(status, set_of_signal_detectors, all_detectors_count) ."""
    if not jpath.exists():
        return "failed", set(), 0
    try:
        data = json.loads(jpath.read_text())
    except Exception:
        return "failed", set(), 0
    if not data.get("success", False):
        return "failed", set(), 0
    dets = [d.get("check") for d in (data.get("results",{}).get("detectors") or [])]
    signal = {d for d in dets if d in DET2SC}
    return "analyzed", signal, len(dets)

rows = []
with META.open() as f:
    for r in csv.DictReader(f):
        cid, label, sc = r["id"], r["label"], r["sc_class"]
        jpath = RESULTS / f"{cid}.json"
        tpath = RESULTS / f"{cid}.time"
        status, signal, n_all = load_findings(jpath)
        sec, mem = parse_time(tpath)
        # классы, по которым Slither "сработал"
        fired_classes = sorted({DET2SC[d] for d in signal})
        # сработал ли детектор ЦЕЛЕВОГО класса (для уязвимых)
        hit_target = sc in fired_classes if label == "vuln" else ""
        rows.append({
            "id": cid, "label": label, "sc_class": sc, "status": status,
            "n_findings_total": n_all,
            "signal_detectors": ";".join(sorted(signal)),
            "fired_classes": ";".join(fired_classes),
            "hit_target_class": hit_target,
            "time_sec": f"{sec:.2f}" if sec is not None else "",
            "mem_mb": f"{mem:.1f}" if mem is not None else "",
        })

with OUT.open("w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
    w.writeheader(); w.writerows(rows)

# сводка
analyzed = [r for r in rows if r["status"]=="analyzed"]
failed   = [r for r in rows if r["status"]=="failed"]
print(f"Всего: {len(rows)} | analyzed: {len(analyzed)} | failed: {len(failed)}")
print(f"CSV -> {OUT}")
print("\nПо классам (analyzed / hit_target для уязвимых):")
from collections import defaultdict
agg = defaultdict(lambda: [0,0,0])  # sc -> [analyzed, hit, failed]
for r in rows:
    sc = r["sc_class"]
    if r["status"]=="failed": agg[sc][2]+=1
    else:
        agg[sc][0]+=1
        if r["label"]=="vuln" and r["hit_target_class"] is True: agg[sc][1]+=1
for sc in sorted(agg):
    a,h,fl = agg[sc]
    print(f"  {sc}: analyzed={a} failed={fl} hit_target={h}")
