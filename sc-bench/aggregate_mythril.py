#!/usr/bin/env python3
"""Агрегатор Mythril: метрики с двумя трактовками тайм-аутов + фильтр severity."""
import csv, json
from pathlib import Path
from collections import defaultdict
CORPUS=Path("/home/andrei/Рабочий стол/Kursovaya/Diplom/contracts")
RES=Path.home()/"sc-bench/results/mythril_full"
META=CORPUS/"metadata.csv"
LOG=RES/"_log.csv"
CLASSES=["SC01","SC05","SC06","SC08","SC09"]
# контракты, бывшие compilation-failed у Slither — исключаем для сопоставимости

EXCLUDE = {
 "vuln_087_SC01","vuln_088_SC01","vuln_089_SC01","vuln_090_SC01","vuln_091_SC01",
 "vuln_092_SC01","vuln_093_SC01","vuln_094_SC01","vuln_095_SC01","vuln_096_SC01",
 "vuln_097_SC01","vuln_098_SC01",
 "vuln_112_SC06","vuln_115_SC06","vuln_116_SC06","vuln_118_SC06","vuln_119_SC06",
 "vuln_057_SC08","vuln_059_SC08",
}

SWC2SC={
 "105":"SC01","106":"SC01","112":"SC01","115":"SC01","124":"SC01",
 "116":"SC05","120":"SC05","114":"SC05",
 "104":"SC06",
 "107":"SC08",
 "101":"SC09",
}

# статус из лога: 0/1=analyzed, 124=timeout
status={}
for line in open(LOG):
    p=line.strip().split(",")
    if len(p)<2: continue
    rc=p[1]
    status[p[0]]= "timeout" if rc=="124" else "analyzed"

meta={r["id"]:(r["label"],r["sc_class"]) for r in csv.DictReader(open(META))}

def fired(cid, hm_only=False):
    """множество SC-классов, обнаруженных Mythril. hm_only=True → только High/Medium."""
    p=RES/f"{cid}.json"
    if not p.exists(): return set()
    try: d=json.loads(p.read_text())
    except: return set()
    out=set()
    for iss in (d.get("issues") or []):
        swc=str(iss.get("swc-id","")); sev=iss.get("severity","")
        if swc not in SWC2SC: continue
        if hm_only and sev not in ("High","Medium"): continue
        out.add(SWC2SC[swc])
    return out

def compute(hm_only, timeout_as_fn):
    safe=[c for c,(l,s) in meta.items() if l=="safe"]
    rows=[]
    mp=mr=mf=0;k=0
    for X in CLASSES:
        vul=[c for c,(l,s) in meta.items() if l=="vuln" and s==X]
        TP=FN=FP=0
        for c in vul:
            if c in EXCLUDE: continue 
            st=status.get(c,"analyzed")
            if st=="timeout":
                if timeout_as_fn: FN+=1   # пессимистичный: тайм-аут = пропуск
                continue                   # оптимистичный: исключаем
            if X in fired(c,hm_only): TP+=1
            else: FN+=1
        for c in safe:
            if status.get(c)=="timeout": continue  # тайм-аут safe не даёт FP
            if X in fired(c,hm_only): FP+=1
        P=TP/(TP+FP) if TP+FP else 0
        R=TP/(TP+FN) if TP+FN else 0
        Fm=2*P*R/(P+R) if P+R else 0
        mp+=P;mr+=R;mf+=Fm;k+=1
        rows.append((X,TP,FP,FN,P,R,Fm))
    return rows,(mp/k,mr/k,mf/k)

def show(title, hm_only, timeout_as_fn):
    rows,(MP,MR,MF)=compute(hm_only,timeout_as_fn)
    print(f"\n=== {title} ===")
    print(f"{'Кл':5} {'TP':>3} {'FP':>3} {'FN':>3} {'Prec':>6} {'Rec':>6} {'F1':>6}")
    for X,TP,FP,FN,P,R,Fm in rows:
        print(f"{X:5} {TP:>3} {FP:>3} {FN:>3} {P:>6.3f} {R:>6.3f} {Fm:>6.3f}")
    print(f"{'Macro':5} {'':>3} {'':>3} {'':>3} {MP:>6.3f} {MR:>6.3f} {MF:>6.3f}")

# Полный режим (все severity), Recall оптимистичный (тайм-ауты исключены)
show("ПОЛНЫЙ, Recall оптимистичный (тайм-ауты исключены)", False, False)
# Полный режим, Recall пессимистичный (тайм-ауты = FN)
show("ПОЛНЫЙ, Recall пессимистичный (тайм-ауты = FN)", False, True)
# Фильтр severity High/Medium, оптимистичный
show("ФИЛЬТР High/Medium, Recall оптимистичный", True, False)
# Фильтр severity High/Medium, пессимистичный
show("ФИЛЬТР High/Medium, Recall пессимистичный", True, True)

# графа полноты обработки
print("\n=== Полнота обработки (тайм-ауты по классам) ===")
agg=defaultdict(lambda:[0,0])
for c,(l,s) in meta.items():
    if c in EXCLUDE: continue 
    key=s if l=="vuln" else "SAFE"
    if status.get(c)=="timeout": agg[key][1]+=1
    else: agg[key][0]+=1
for k in ["SC01","SC05","SC06","SC08","SC09","SAFE"]:
    print(f"  {k}: проанализировано {agg[k][0]}, тайм-аут {agg[k][1]}")

# ресурсы (по _log.csv: время сек = поле 4, память кб = поле 5)
import statistics
times=[];mems=[]
for line in open(LOG):
    p=line.strip().split(",")
    if len(p)>=5 and p[3].isdigit():
        times.append(int(p[3]))
        if p[4].isdigit(): mems.append(int(p[4])/1024)
print(f"\nВремя: медиана {statistics.median(times):.0f}с, макс {max(times)}с")
print(f"Память: медиана {statistics.median(mems):.0f}МБ, макс {max(mems):.0f}МБ")
