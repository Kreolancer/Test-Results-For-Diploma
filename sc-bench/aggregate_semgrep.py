#!/usr/bin/env python3
"""Агрегатор Semgrep (правила Decurity): полный режим и фильтр ERROR/WARNING."""
import csv, json, statistics
from pathlib import Path
CORPUS=Path("/home/andrei/Рабочий стол/Kursovaya/Diplom/contracts")
RES=Path.home()/"sc-bench/results/semgrep"
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

# правило (последняя часть check_id) -> SC-класс
RULE2SC={
 "accessible-selfdestruct":"SC01","unrestricted-transferownership":"SC01",
 "bad-transferfrom-access-control":"SC01","erc20-public-transfer":"SC01",
 "erc20-public-burn":"SC01","rigoblock-missing-access-control":"SC01",
 "delegatecall-to-arbitrary-address":"SC01",
 "incorrect-use-of-blockhash":"SC05","exact-balance-check":"SC05",
 "arbitrary-low-level-call":"SC06",
 "curve-readonly-reentrancy":"SC08","compound-borrowfresh-reentrancy":"SC08",
 "erc677-reentrancy":"SC08","erc721-reentrancy":"SC08","erc777-reentrancy":"SC08",
 "balancer-readonly-reentrancy-getpooltokens":"SC08",
 "balancer-readonly-reentrancy-getrate":"SC08",
 "basic-arithmetic-underflow":"SC09",
}

meta={r["id"]:(r["label"],r["sc_class"]) for r in csv.DictReader(open(META))}

def fired(cid, hw_only=False):
    """SC-классы, обнаруженные. hw_only=True → только ERROR/WARNING (без INFO)."""
    p=RES/f"{cid}.json"
    if not p.exists(): return set()
    try: d=json.loads(p.read_text())
    except: return set()
    out=set()
    for r in d.get("results",[]):
        rule=r["check_id"].split(".")[-1]
        sev=r.get("extra",{}).get("severity","")
        if rule not in RULE2SC: continue
        if hw_only and sev not in ("ERROR","WARNING"): continue
        out.add(RULE2SC[rule])
    return out

def compute(hw_only):
    safe=[c for c,(l,s) in meta.items() if l=="safe"]
    rows=[];mp=mr=mf=0;k=0
    for X in CLASSES:
        vul=[c for c,(l,s) in meta.items() if l=="vuln" and s==X and c not in EXCLUDE]
        TP=sum(1 for c in vul if X in fired(c,hw_only))
        FN=sum(1 for c in vul if X not in fired(c,hw_only))
        FP=sum(1 for c in safe if X in fired(c,hw_only))
        TN=len(safe)-FP
        P=TP/(TP+FP) if TP+FP else 0
        R=TP/(TP+FN) if TP+FN else 0
        Fm=2*P*R/(P+R) if P+R else 0
        mp+=P;mr+=R;mf+=Fm;k+=1
        rows.append((X,TP,FP,TN,FN,P,R,Fm))
    return rows,(mp/k,mr/k,mf/k)

def show(title,hw_only):
    rows,(MP,MR,MF)=compute(hw_only)
    print(f"\n=== {title} ===")
    print(f"{'Кл':5} {'TP':>3} {'FP':>3} {'TN':>3} {'FN':>3} {'Prec':>6} {'Rec':>6} {'F1':>6}")
    for X,TP,FP,TN,FN,P,R,Fm in rows:
        print(f"{X:5} {TP:>3} {FP:>3} {TN:>3} {FN:>3} {P:>6.3f} {R:>6.3f} {Fm:>6.3f}")
    print(f"{'Macro':5} {'':>3} {'':>3} {'':>3} {'':>3} {MP:>6.3f} {MR:>6.3f} {MF:>6.3f}")

show("ПОЛНЫЙ (все severity)", False)
show("ФИЛЬТР (ERROR/WARNING, без INFO)", True)

times=[]
for line in open(LOG):
    p=line.strip().split(",")
    if len(p)>=3 and p[2].isdigit(): times.append(int(p[2]))
print(f"\nВремя: медиана {statistics.median(times):.0f}мс, макс {max(times)}мс")
print("Память: см. .time файлы (Semgrep ~стабилен)")
