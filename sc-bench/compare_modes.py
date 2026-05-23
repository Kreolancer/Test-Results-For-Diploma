#!/usr/bin/env python3
"""Сравнение слепой vs таргет на уровне отдельных контрактов."""
import csv, json
from pathlib import Path
CORPUS = Path("/home/andrei/Рабочий стол/Kursovaya/Diplom/contracts")
TARG = Path.home()/"sc-bench/results/slither_targeted"
BLIND_CSV = Path.home()/"sc-bench/results/slither_results.csv"

def targ_hit(cid, sc):
    p = TARG/f"{cid}__{sc}.json"
    if not p.exists(): return None
    try: d = json.loads(p.read_text())
    except: return None
    if not d.get("success"): return None
    return len(d.get("results",{}).get("detectors") or []) > 0

blind = {r["id"]:r for r in csv.DictReader(open(BLIND_CSV))}
print(f"{'Класс':6} {'слеп_TP':>8} {'тарг_TP':>8} {'тарг_нашёл_новое':>16}")
from collections import defaultdict
agg = defaultdict(lambda:[0,0,0,[]])  # b_tp, t_tp, t_only, list
for cid,r in blind.items():
    if r["label"]!="vuln" or r["status"]!="analyzed": continue
    sc = r["sc_class"]
    b_hit = (r["hit_target_class"]=="True")
    t_hit = targ_hit(cid, sc)
    if t_hit is None: continue
    agg[sc][0]+=int(b_hit); agg[sc][1]+=int(t_hit)
    if t_hit and not b_hit:           # таргет нашёл, слепой пропустил
        agg[sc][2]+=1; agg[sc][3].append(cid)
for sc in sorted(agg):
    b,t,only,lst = agg[sc]
    print(f"{sc:6} {b:>8} {t:>8} {only:>16} {';'.join(lst)}")
