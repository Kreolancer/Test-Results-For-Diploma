#!/usr/bin/env python3
"""Пересчёт: таргет = слепые детекторы, но только impact High/Medium."""
import csv, json
from pathlib import Path
from collections import defaultdict
CORPUS=Path("/home/andrei/Рабочий стол/Kursovaya/Diplom/contracts")
BLIND=Path.home()/"sc-bench/results/slither_blind"
META=CORPUS/"metadata.csv"
CLASSES=["SC01","SC05","SC06","SC08","SC09"]
DET2SC={}
for sc,ds in {
 "SC01":["arbitrary-send-eth","arbitrary-send-erc20","suicidal","tx-origin","controlled-delegatecall","incorrect-modifier"],
 "SC05":["timestamp","weak-prng","missing-zero-check"],
 "SC06":["unchecked-lowlevel","unchecked-send","unchecked-transfer","unused-return","low-level-calls","locked-ether","calls-loop"],
 "SC08":["reentrancy-eth","reentrancy-no-eth","reentrancy-benign","reentrancy-events","reentrancy-unlimited-gas"],
 "SC09":["divide-before-multiply","incorrect-equality","tautology","controlled-array-length"],
}.items():
    for d in ds: DET2SC[d]=sc

def fired(cid, min_impact=False):
    p=BLIND/f"{cid}.json"
    if not p.exists(): return None
    try: d=json.loads(p.read_text())
    except: return None
    if not d.get("success"): return None
    out=set()
    for det in (d.get("results",{}).get("detectors") or []):
        chk=det.get("check"); imp=det.get("impact","")
        if chk not in DET2SC: continue
        if min_impact and imp not in ("High","Medium"): continue
        out.add(DET2SC[chk])
    return out

meta={r["id"]:(r["label"],r["sc_class"]) for r in csv.DictReader(open(META))}

def metrics(min_impact):
    safe=[c for c,(l,s) in meta.items() if l=="safe"]
    print(f"\n{'=== ТОЛЬКО High/Medium ===' if min_impact else '=== ВСЕ impact (слепой) ==='}")
    print(f"{'Кл':5} {'TP':>3} {'FP':>3} {'FN':>3} {'Prec':>6} {'Rec':>6} {'F1':>6}")
    mp=mr=mf=0;k=0
    for X in CLASSES:
        vul=[c for c,(l,s) in meta.items() if l=="vuln" and s==X]
        TP=FN=FP=0
        for c in vul:
            f=fired(c,min_impact)
            if f is None: continue
            if X in f: TP+=1
            else: FN+=1
        for c in safe:
            f=fired(c,min_impact)
            if f is None: continue
            if X in f: FP+=1
        P=TP/(TP+FP) if TP+FP else 0; R=TP/(TP+FN) if TP+FN else 0; Fm=2*P*R/(P+R) if P+R else 0
        mp+=P;mr+=R;mf+=Fm;k+=1
        print(f"{X:5} {TP:>3} {FP:>3} {FN:>3} {P:>6.3f} {R:>6.3f} {Fm:>6.3f}")
    print(f"{'Macro':5} {'':>3} {'':>3} {'':>3} {mp/k:>6.3f} {mr/k:>6.3f} {mf/k:>6.3f}")

metrics(False)
metrics(True)
