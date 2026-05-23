#!/usr/bin/env bash
# add_replacements.sh v2 — быстрый добор замен (проверка через solc, не slither)
set -uo pipefail
CORPUS="/home/andrei/Рабочий стол/Kursovaya/Diplom/contracts"
BCCC="/home/andrei/Рабочий стол/Kursovaya/Diplom/BCCC-SCsVul-2024/SourceCodes/Source Codes"
OUT=~/sc-bench/results/slither_blind
TIMEOUT=120
SEED=777
source ~/sc-bench/tools/slither-venv/bin/activate

declare -A SRC NEED
SRC[SC01]="WeakAccessMod"
SRC[SC06]="CallToUnknown UnusedReturn MishandledException ExternalBug"
SRC[SC08]="Reentrancy"
NEED[SC01]=12; NEED[SC06]=5; NEED[SC08]=2

shuf_seed() { shuf --random-source=<(yes "$SEED"); }
USED=$(awk -F'"' 'NR>1{print $2}' "$CORPUS/metadata.csv")
maxidx=$(awk -F, 'NR>1{n=$1; gsub(/[^0-9]/,"",n); if(n>m)m=n} END{print m}' "$CORPUS/metadata.csv")
idx=$((maxidx+1))

# быстрая проверка компиляции голым solc; печатает версию или пусто
fast_compiles() {  # $1=file -> echo ver | пусто
    local f="$1" pragma cand
    pragma=$(grep -oP 'pragma\s+solidity\s+\K[^;]+' "$f" | head -1 | grep -oP '\d+\.\d+\.\d+' | head -1)
    for cand in "${pragma:-0.4.24}" 0.4.24 0.4.25 0.5.17; do
        solc-select use "$cand" >/dev/null 2>&1 || continue
        if solc "$f" --bin >/dev/null 2>&1; then echo "$cand"; return; fi
    done
}

for sc in SC01 SC06 SC08; do
    need=${NEED[$sc]}; got=0 tried=0
    echo "== $sc: нужно $need замен =="
    for srcdir in ${SRC[$sc]}; do
        [ "$got" -ge "$need" ] && break
        while IFS= read -r f; do
            [ "$got" -ge "$need" ] && break
            echo "$USED" | grep -qF "$f" && continue
            tried=$((tried+1))
            [ $((tried % 20)) -eq 0 ] && echo "    ...проверено $tried кандидатов, найдено $got"
            ver=$(fast_compiles "$f")
            [ -z "$ver" ] && continue

            cid=$(printf "vuln_%03d_%s" "$idx" "$sc")
            cp "$f" "$CORPUS/vulnerable/$cid.sol"
            echo "$cid,\"$f\",vuln,$sc,bccc_repl" >> "$CORPUS/metadata.csv"
            SOLC_VERSION="$ver" /usr/bin/time -v -o "$OUT/$cid.time" \
                timeout "$TIMEOUT" slither "$CORPUS/vulnerable/$cid.sol" --json "$OUT/$cid.json" \
                > "$OUT/$cid.stdout" 2> "$OUT/$cid.stderr" || true
            echo "$cid,replaced,$ver" >> "$OUT/_exit_codes.csv"
            idx=$((idx+1)); got=$((got+1))
            echo "  + $cid (ver=$ver) [$got/$need]"
        done < <(find "$BCCC/$srcdir" -name "*.sol" 2>/dev/null | shuf_seed)
    done
    echo "  итог $sc: добрано $got (проверено $tried)"
done
echo "Готово. Не забудь: solc-select use вернуть в 0.8.20 при необходимости."
solc-select use 0.8.20 >/dev/null 2>&1 || true
