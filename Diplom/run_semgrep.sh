#!/usr/bin/env bash
# run_semgrep.sh — прогон Semgrep (правила Decurity solidity/security) по корпусу
set -uo pipefail
CORPUS="/home/andrei/Рабочий стол/Kursovaya/Diplom/contracts"
RULES=~/sc-bench/tools/semgrep-smart-contracts/solidity/security
OUT=~/sc-bench/results/semgrep
source ~/sc-bench/tools/semgrep-venv/bin/activate
mkdir -p "$OUT"
: > "$OUT/_log.csv"

find "$CORPUS" -name "*.sol" | sort | while IFS= read -r f; do
    id=$(basename "$f" .sol)
    start=$(date +%s%N)
    /usr/bin/time -v -o "$OUT/$id.time" \
        semgrep --config "$RULES" "$f" --json --quiet \
        > "$OUT/$id.json" 2> "$OUT/$id.stderr"
    rc=$?
    dur=$(( ($(date +%s%N) - start)/1000000 ))
    # успех = валидный JSON с ключом results
    ok=0
    if python3 -c "import json; d=json.load(open('$OUT/$id.json')); assert 'results' in d" 2>/dev/null; then ok=1; fi
    mem=$(grep "Maximum resident" "$OUT/$id.time" 2>/dev/null | grep -oP '\d+' | head -1)
    echo "$id,$ok,$dur,$mem" >> "$OUT/_log.csv"
    echo "  $id -> ok=$ok ${dur}ms"
done

echo ""
echo "=== Обработано ==="
cut -d, -f2 "$OUT/_log.csv" | sort | uniq -c
echo "Всего: $(wc -l < "$OUT/_log.csv")"
