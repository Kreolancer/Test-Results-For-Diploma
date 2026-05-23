#!/usr/bin/env bash
# run_mythril_full.sh — полный прогон Mythril, 300 контрактов
set -uo pipefail
CORPUS="/home/andrei/Рабочий стол/Kursovaya/Diplom/contracts"
OUT=~/sc-bench/results/mythril_full
EXT_TIMEOUT=150
EXEC_TIMEOUT=100
SOLVER_TIMEOUT=10000
TXCOUNT=2
PARALLEL=2
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

find "$CORPUS" -name "*.sol" | sort | \
    parallel --env run_one --env OUT --env EXT_TIMEOUT --env EXEC_TIMEOUT --env SOLVER_TIMEOUT --env TXCOUNT -j "$PARALLEL" run_one {}

echo ""
echo "=== Статусы (0/1=ОК, 124=таймаут) ==="
cut -d, -f2 "$OUT/_log.csv" | sort | uniq -c
echo "Обработано: $(wc -l < "$OUT/_log.csv") из 300"
