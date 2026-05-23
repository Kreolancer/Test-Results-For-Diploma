#!/usr/bin/env bash
# fix_failed.sh — перепрогон упавших с автоподбором solc
set -uo pipefail
CORPUS="/home/andrei/Рабочий стол/Kursovaya/Diplom/contracts"
OUT=~/sc-bench/results/slither_blind
TIMEOUT=120
source ~/sc-bench/tools/slither-venv/bin/activate

# кандидаты: частые в BCCC + 0.8.x для тех, что заявлены как 0.8.20
CANDIDATES="0.4.24 0.4.25 0.4.26 0.5.0 0.5.1 0.5.17 0.6.12 0.7.6 0.8.20 0.4.22 0.4.23"

mapfile -t failed < <(awk -F, '$2!=0 && $2!=255 {print $1}' "$OUT/_exit_codes.csv")
echo "Упавших к перепрогону: ${#failed[@]}"

: > "$OUT/_refix_codes.csv"
for id in "${failed[@]}"; do
    f=$(find "$CORPUS" -name "$id.sol")
    [ -z "$f" ] && { echo "$id,notfound," >> "$OUT/_refix_codes.csv"; continue; }
    fixed=""
    for ver in $CANDIDATES; do
        SOLC_VERSION="$ver" /usr/bin/time -v -o "$OUT/$id.time" \
            timeout "$TIMEOUT" slither "$f" --json "$OUT/$id.json" \
            > "$OUT/$id.stdout" 2> "$OUT/$id.stderr" || true
        # критерий успеха — валидный JSON с success=true, код выхода игнорируем
        if jq -e '.success == true' "$OUT/$id.json" >/dev/null 2>&1; then
            fixed="$ver"; break
        fi
    done
    if [ -n "$fixed" ]; then
        echo "$id,fixed,$fixed" >> "$OUT/_refix_codes.csv"
    else
        echo "$id,failed," >> "$OUT/_refix_codes.csv"
    fi
    echo "  $id -> $(tail -1 "$OUT/_refix_codes.csv" | cut -d, -f2,3)"
done

echo ""
echo "=== Итог перепрогона ==="
cut -d, -f2 "$OUT/_refix_codes.csv" | sort | uniq -c
