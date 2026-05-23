#!/usr/bin/env bash
# run_mythril_pilot.sh — пилот Mythril, -t 2, проверка времени и памяти
set -uo pipefail
CORPUS="/home/andrei/Рабочий стол/Kursovaya/Diplom/contracts"
OUT=~/sc-bench/results/mythril_pilot
SOLCX=~/.solcx
EXT_TIMEOUT=180
EXEC_TIMEOUT=120
SOLVER_TIMEOUT=10000
TXCOUNT=2
PARALLEL=3
source ~/sc-bench/tools/mythril-venv/bin/activate
mkdir -p "$OUT"
: > "$OUT/_log.csv"

run_one() {
    local f="$1"
    local id; id=$(basename "$f" .sol)
    local pragma; pragma=$(grep -oP 'pragma\s+solidity\s+\K[^;]+' "$f" | head -1 | grep -oP '\d+\.\d+\.\d+' | head -1)
    local ver="${pragma:-0.4.24}"
    local start; start=$(date +%s)
    /usr/bin/time -v -o "$OUT/$id.time" \
        timeout "$EXT_TIMEOUT" \
        myth analyze "$f" --solv "$ver" --execution-timeout "$EXEC_TIMEOUT" \
            -t "$TXCOUNT" --solver-timeout "$SOLVER_TIMEOUT" -o json \
        > "$OUT/$id.json" 2> "$OUT/$id.stderr"
    local rc=$?
    local dur=$(( $(date +%s) - start ))
    local mem; mem=$(grep "Maximum resident" "$OUT/$id.time" 2>/dev/null | grep -oP '\d+' | head -1)
    echo "$id,$rc,$ver,$dur,$mem" >> "$OUT/_log.csv"
    echo "  $id -> rc=$rc ${dur}с mem=$((${mem:-0}/1024))MB"
}
export -f run_one
export OUT EXT_TIMEOUT EXEC_TIMEOUT SOLVER_TIMEOUT TXCOUNT

# 2 уязвимых из каждого класса + 5 safe = 15
mapfile -t files < <(
  for sc in SC01 SC05 SC06 SC08 SC09; do
    find "$CORPUS/vulnerable" -name "*_${sc}.sol" | sort | head -2
  done
  find "$CORPUS/safe" -name "*.sol" | sort | head -5
)

echo "Пилот: ${#files[@]} контрактов, -t $TXCOUNT, parallel $PARALLEL"
printf '%s\n' "${files[@]}" | parallel --env run_one --env OUT --env EXT_TIMEOUT --env EXEC_TIMEOUT --env SOLVER_TIMEOUT --env TXCOUNT -j "$PARALLEL" run_one {}

echo ""
echo "=== Статусы (0/1=ОК, 124=таймаут) ==="
cut -d, -f2 "$OUT/_log.csv" | sort | uniq -c
echo "=== Время: мин/медиана/макс ==="
cut -d, -f4 "$OUT/_log.csv" | sort -n | awk '{a[NR]=$1} END{print "min="a[1]" med="a[int(NR/2)+1]" max="a[NR]}'
echo "=== Память макс (МБ) ==="
cut -d, -f5 "$OUT/_log.csv" | sort -n | tail -1 | awk '{print $1/1024}'
