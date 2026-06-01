#!/usr/bin/env bash
# build_corpus.sh — сборка стратифицированного корпуса
set -uo pipefail
SB="/home/andrei/Рабочий стол/Kursovaya/Diplom/dataset"
BCCC="/home/andrei/Рабочий стол/Kursovaya/Diplom/BCCC-SCsVul-2024/SourceCodes/Source Codes"
DEST="/home/andrei/Рабочий стол/Kursovaya/Diplom/contracts"
PER_CLASS=30          # уязвимых на класс
N_SAFE=150            # безопасных
SEED=42
mkdir -p "$DEST/vulnerable" "$DEST/safe"
META="$DEST/metadata.csv"
echo "id,orig_path,label,sc_class,source" > "$META"
# детерминированная "случайная" сортировка
shuf_seed() { shuf --random-source=<(yes "$SEED"); }
idx=1
add_files() {           # $1=glob-папка  $2=sc_class  $3=label  $4=limit  $5=source
  local dir="$1" sc="$2" label="$3" limit="$4" src="$5" count=0
  while IFS= read -r f; do
    [ "$count" -ge "$limit" ] && break
    local cid; cid=$(printf "%s_%03d_%s" "$label" "$idx" "$sc")
    cp "$f" "$DEST/$([ "$label" = safe ] && echo safe || echo vulnerable)/$cid.sol"
    echo "$cid,\"$f\",$label,$sc,$src" >> "$META"
    idx=$((idx+1)); count=$((count+1))
  done < <(find "$dir" -name "*.sol" 2>/dev/null | shuf_seed)
  echo "  $sc ($src): добавлено $count"
}
echo "== SmartBugs =="
add_files "$SB/access_control"     SC01 vuln "$PER_CLASS" smartbugs
add_files "$SB/bad_randomness"     SC05 vuln 10 smartbugs
add_files "$SB/time_manipulation"  SC05 vuln 10 smartbugs
add_files "$SB/front_running"      SC05 vuln 10 smartbugs
add_files "$SB/denial_of_service"  SC06 vuln 15 smartbugs
add_files "$SB/reentrancy"         SC08 vuln "$PER_CLASS" smartbugs
add_files "$SB/arithmetic"         SC09 vuln "$PER_CLASS" smartbugs
echo "== BCCC (добор до 30/класс + безопасные) =="
add_files "$BCCC/WeakAccessMod"             SC01 vuln 12 bccc   # 18 + 12 = 30
add_files "$BCCC/Timestamp"                 SC05 vuln 13 bccc   # 17 + 13 = 30
add_files "$BCCC/CallToUnknown"             SC06 vuln 8  bccc   # 6 + 8 + 8 + 8 = 30
add_files "$BCCC/UnusedReturn"              SC06 vuln 8  bccc
add_files "$BCCC/MishandledException"       SC06 vuln 8  bccc
add_files "$BCCC/IntegerUO"                 SC09 vuln 15 bccc   # 15 + 15 = 30
add_files "$BCCC/NonVulnerable"             SAFE safe "$N_SAFE" bccc
echo ""
echo "Итого в корпусе:"
column -t -s, "$META" | tail -n +2 | awk -F'  +' '{print $4}' | sort | uniq -c
