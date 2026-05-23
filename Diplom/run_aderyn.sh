#!/usr/bin/env bash
# run_aderyn.sh — прогон Aderyn по корпусу, по одному файлу
set -uo pipefail
CORPUS="/home/andrei/Рабочий стол/Kursovaya/Diplom/contracts"
OUT=~/sc-bench/results/aderyn
TMP=/tmp/aderyn_run
mkdir -p "$OUT" "$TMP/src"
: > "$OUT/_log.csv"

run_one() {
    local f="$1"
    local id; id=$(basename "$f" .sol)
    rm -rf "$TMP/src"; mkdir -p "$TMP/src"
    cp "$f" "$TMP/src/"
    local start; start=$(date +%s%N)
    /usr/bin/time -v -o "$OUT/$id.time" \
        aderyn "$TMP" -o "$OUT/$id.json" \
        > "$OUT/$id.stdout" 2> "$OUT/$id.stderr"
    local rc=$?
    local dur=$(( ($(date +%s%N) - start)/1000000 ))   # мс
    # критерий обработки: JSON существует и total_source_units>=1
    local ok=0
    if [ -f "$OUT/$id.json" ] && python3 -c "import json,sys; d=json.load(open('$OUT/$id.json')); sys.exit(0 if d.get('files_summary',{}).get('total_source_units',0)>=1 else 1)" 2>/dev/null; then
        ok=1
    fi
    local mem; mem=$(grep "Maximum resident" "$OUT/$id.time" 2>/dev/null | grep -oP '\d+' | head -1)
    echo "$id,$ok,$dur,$mem" >> "$OUT/_log.csv"
    echo "  $id -> ok=$ok ${dur}ms mem=$((${mem:-0}/1024))MB"
}

# последовательно — Aderyn быстрый, гонки за solc не нужны
find "$CORPUS" -name "*.sol" | sort | while IFS= read -r f; do
    run_one "$f"
done

echo ""
echo "=== Обработано (ok=1) / ошибки (ok=0) ==="
cut -d, -f2 "$OUT/_log.csv" | sort | uniq -c
echo "Всего: $(wc -l < "$OUT/_log.csv")"
