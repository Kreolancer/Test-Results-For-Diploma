#!/usr/bin/env bash
# run_slither.sh — слепой прогон Slither по корпусу
set -uo pipefail

export CORPUS="/home/andrei/Рабочий стол/Kursovaya/Diplom/contracts"
export TOOLS=~/sc-bench/tools
export OUT=~/sc-bench/results/slither_blind
export TIMEOUT=120
PARALLEL=6

mkdir -p "$OUT"
source "$TOOLS/slither-venv/bin/activate"
: > "$OUT/_exit_codes.csv"

run_one() {
    local f="$1"
    local id; id=$(basename "$f" .sol)

    local pragma; pragma=$(grep -oP 'pragma\s+solidity\s+\K[^;]+' "$f" | head -1 \
                           | grep -oP '\d+\.\d+\.\d+' | head -1)
    local ver="${pragma:-0.8.20}"
    local to="${TIMEOUT:-120}"

    SOLC_VERSION="$ver" /usr/bin/time -v -o "$OUT/$id.time" \
        timeout "$to" \
        slither "$f" --json "$OUT/$id.json" \
        > "$OUT/$id.stdout" 2> "$OUT/$id.stderr"
    echo "$id,$?,$ver" >> "$OUT/_exit_codes.csv"
}
export -f run_one

find "$CORPUS" -name "*.sol" | sort | \
    parallel --env run_one --env OUT --env TIMEOUT -j "$PARALLEL" run_one {}

echo ""
echo "=== Готово. Статусы (0=ОК, 124=таймаут, прочее=ошибка) ==="
cut -d, -f2 "$OUT/_exit_codes.csv" | sort | uniq -c
