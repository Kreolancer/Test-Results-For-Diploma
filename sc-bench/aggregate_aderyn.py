#!/usr/bin/env python3
"""Агрегатор Aderyn: полный режим (high+low) и фильтр (high), исключая канонические битые."""
import csv, json, statistics
from pathlib import Path
CORPUS=Path("/home/andrei/Рабочий стол/Kursovaya/Diplom/contracts")
RES=Path.home()/"sc-bench/results/aderyn"
META=CORPUS/"metadata.csv"
LOG=RES/"_log.csv"
CLASSES=["SC01","SC05","SC06","SC08","SC09"]

EXCLUDE={
 "vuln_087_SC01","vuln_088_SC01","vuln_089_SC01","vuln_090_SC01","vuln_091_SC01",
 "vuln_092_SC01","vuln_093_SC01","vuln_094_SC01","vuln_095_SC01","vuln_096_SC01",
 "vuln_097_SC01","vuln_098_SC01",
 "vuln_112_SC06","vuln_115_SC06","vuln_116_SC06","vuln_118_SC06","vuln_119_SC06",
 "vuln_057_SC08","vuln_059_SC08",
}

# detector -> (SC-класс, severity) ; severity: H или L
DET={
 "selfdestruct":("SC01","H"),"arbitrary-transfer-from":("SC01","H"),
 "constant-function-changes-state":("SC01","H"),
 "weak-randomness":("SC05","H"),"ecrecover":("SC05","L"),
 "unchecked-low-level-call":("SC06","H"),"unchecked-send":("SC06","H"),
 "unchecked-return":("SC06","L"),
 "reentrancy-state-change":("SC08","H"),
 "division-before-multiplication":("SC09","L"),
}

# статус обработки из лога
status={}
for line in open(LOG):
    p=line.strip().split(",")
    if len(p)>=2: status[p[0]]="ok" if p[1]=="1" else "fail"

meta={r["id"]:(r["label"],r["sc_class"]) for r in csv.DictReader(open(META))}

def fired(cid, high_only=False):
    p=RES/f"{cid}.json"
    if not p.exists(): return set()
    try: d=json.loads(p.read_text())
    except: return set()
    out=set()
    for sec_key,sev in [("high_issues","H"),("low_issues","L")]:
        if high_only and sev!="H": continue
        for iss in d.get(sec_key,{}).get("issues",[]):
            dn=iss.get("detector_name","")
            if dn in DET and DET[dn][1]==sev:
                out.add(DET[dn][0])
    return out

def compute(high_only):
    safe=[c for c,(l,s) in meta.items() if l=="safe" and status.get(c)=="ok"]
    rows=[];mp=mr=mf=0;k=0
    for X in CLASSES:
        vul=[c for c,(l,s) in meta.items() if l=="vuln" and s==X and c not in EXCLUDE and status.get(c)=="ok"]
        TP=sum(1 for c in vul if X in fired(c,high_only))
        FN=sum(1 for c in vul if X not in fired(c,high_only))
        FP=sum(1 for c in safe if X in fired(c,high_only))
        TN=len(safe)-FP
        P=TP/(TP+FP) if TP+FP else 0
        R=TP/(TP+FN) if TP+FN else 0
        Fm=2*P*R/(P+R) if P+R else 0
        mp+=P;mr+=R;mf+=Fm;k+=1
        rows.append((X,TP,FP,TN,FN,P,R,Fm))
    return rows,(mp/k,mr/k,mf/k)

def show(title,high_only):
    rows,(MP,MR,MF)=compute(high_only)
    print(f"\n=== {title} ===")
    print(f"{'Кл':5} {'TP':>3} {'FP':>3} {'TN':>3} {'FN':>3} {'Prec':>6} {'Rec':>6} {'F1':>6}")
    for X,TP,FP,TN,FN,P,R,Fm in rows:
        print(f"{X:5} {TP:>3} {FP:>3} {TN:>3} {FN:>3} {P:>6.3f} {R:>6.3f} {Fm:>6.3f}")
    print(f"{'Macro':5} {'':>3} {'':>3} {'':>3} {'':>3} {MP:>6.3f} {MR:>6.3f} {MF:>6.3f}")

show("ПОЛНЫЙ (high+low)", False)
show("ФИЛЬТР (только high)", True)

# полнота обработки
print("\n=== Полнота обработки ===")
from collections import defaultdict
agg=defaultdict(lambda:[0,0])
for c,(l,s) in meta.items():
    if c in EXCLUDE: continue
    key=s if l=="vuln" else "SAFE"
    if status.get(c)=="ok": agg[key][0]+=1
    else: agg[key][1]+=1
for k in CLASSES+["SAFE"]:
    print(f"  {k}: обработано {agg[k][0]}, ошибка компиляции {agg[k][1]}")

# ресурсы (исключаем выброс vuln_004 и неудачные, берём только ok)
times=[];mems=[]
for line in open(LOG):
    p=line.strip().split(",")
    if len(p)>=4 and p[1]=="1" and p[2].isdigit():
        times.append(int(p[2])); 
        if p[3].isdigit(): mems.append(int(p[3])/1024)
print(f"\nВремя (только ok): медиана {statistics.median(times):.0f}мс, макс {max(times)}мс")
print(f"Память (только ok): медиана {statistics.median(mems):.0f}МБ, макс {max(mems):.0f}МБ")
