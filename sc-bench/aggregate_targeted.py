#!/usr/bin/env python3
"""Агрегатор таргетированного режима Slither + сравнение со слепым."""
import csv, json, statistics
from pathlib import Path
from collections import defaultdict

CORPUS = Path("/home/andrei/Рабочий стол/Kursovaya/Diplom/contracts")
TARG = Path.home()/"sc-bench/results/slither_targeted"
META = CORPUS/"metadata.csv"
CLASSES = ["SC01","SC05","SC06","SC08","SC09"]

# какие детекторы относятся к классу (для интерпретации, в таргете и так только они)
def fired_set(jpath):
    """множество сработавших детекторов или None если failed."""
    if not jpath.exists(): return None
    try: data = json.loads(jpath.read_text())
    except Exception: return None
    if not data.get("success", False): return None
    return {d.get("check") for d in (data.get("results",{}).get("detectors") or [])}

# метаданные
meta = {}
with META.open() as f:
    for r in csv.DictReader(f):
        meta[r["id"]] = (r["label"], r["sc_class"])

# уязвимые: сработал ли хоть один детектор целевого класса
vuln_hit = {}   # sc -> [TP, FN, failed]
agg_v = defaultdict(lambda:[0,0,0])
for cid,(label,sc) in meta.items():
    if label!="vuln": continue
    fs = fired_set(TARG/f"{cid}__{sc}.json")
    if fs is None: agg_v[sc][2]+=1
    elif len(fs)>0: agg_v[sc][0]+=1   # TP
    else: agg_v[sc][1]+=1             # FN

# safe: FP по классу X = сработал набор X хоть одним детектором
agg_fp = defaultdict(lambda:[0,0])   # sc -> [FP, TN]
for cid,(label,sc) in meta.items():
    if label!="safe": continue
    for X in CLASSES:
        fs = fired_set(TARG/f"{cid}__{X}.json")
        if fs is None: continue
        if len(fs)>0: agg_fp[X][0]+=1
        else: agg_fp[X][1]+=1

print("ТАРГЕТИРОВАННЫЙ РЕЖИМ Slither\n")
print(f"{'Класс':6} {'TP':>3} {'FP':>3} {'TN':>3} {'FN':>3} {'Prec':>6} {'Rec':>6} {'F1':>6}")
print("-"*46)
mp=mr=mf=0;k=0
res={}
for X in CLASSES:
    TP,FN,fail = agg_v[X]; FP,TN = agg_fp[X]
    P=TP/(TP+FP) if TP+FP else 0; R=TP/(TP+FN) if TP+FN else 0; F=2*P*R/(P+R) if P+R else 0
    res[X]=(P,R,F); mp+=P;mr+=R;mf+=F;k+=1
    print(f"{X:6} {TP:>3} {FP:>3} {TN:>3} {FN:>3} {P:>6.3f} {R:>6.3f} {F:>6.3f}")
print("-"*46)
print(f"{'Macro':6} {'':>3} {'':>3} {'':>3} {'':>3} {mp/k:>6.3f} {mr/k:>6.3f} {mf/k:>6.3f}")

# время/память таргета (по .time файлам)
import re
times=[];mems=[]
for p in TARG.glob("*.time"):
    t=p.read_text(errors="ignore")
    m=re.search(r"Elapsed.*?:\s*([\d:.]+)",t)
    if m:
        pp=m.group(1).split(":"); times.append(float(pp[-1])+(float(pp[-2])*60 if len(pp)>1 else 0))
    m=re.search(r"Maximum resident set size \(kbytes\):\s*(\d+)",t)
    if m: mems.append(int(m.group(1))/1024)
if times: print(f"\nВремя/прогон: медиана {statistics.median(times):.2f}с")
if mems: print(f"Память/прогон: медиана {statistics.median(mems):.1f}МБ")
