#!/usr/bin/env bash
# run_slither_targeted.sh — таргетированный режим (только детекторы целевого класса)
set -uo pipefail
CORPUS="/home/andrei/Рабочий стол/Kursovaya/Diplom/contracts"
OUT=~/sc-bench/results/slither_targeted
TIMEOUT=120
source ~/sc-bench/tools/slither-venv/bin/activate
mkdir -p "$OUT"
: > "$OUT/_runs.csv"   # id,class_set,ver

declare -A DET
DET[SC01]="arbitrary-send-eth,arbitrary-send-erc20,suicidal,tx-origin,controlled-delegatecall"
DET[SC05]="timestamp,weak-prng"
DET[SC06]="unchecked-lowlevel,unchecked-send,unchecked-transfer,unused-return,locked-ether"
DET[SC08]="reentrancy-eth,reentrancy-no-eth"
DET[SC09]="divide-before-multiply,incorrect-equality"

pick_ver() {  # печатает рабочую версию (как в слепом: pragma, иначе 0.4.24)
    local f="$1" pragma
    pragma=$(grep -oP 'pragma\s+solidity\s+\K[^;]+' "$f" | head -1 | grep -oP '\d+\.\d+\.\d+' | head -1)
    echo "${pragma:-0.8.20}"
}

# прогон одного файла одним набором детекторов; результат в OUT/<id>__<set>.json
run() {
    local f="$1" set="$2"
    local id; id=$(basename "$f" .sol)
    local dets="${DET[$set]}"
    local ver; ver=$(pick_ver "$f")
    local out="$OUT/${id}__${set}.json"

    SOLC_VERSION="$ver" /usr/bin/time -v -o "$OUT/${id}__${set}.time" \
        timeout "$TIMEOUT" slither "$f" --detect "$dets" --json "$out" \
        > /dev/null 2> "$OUT/${id}__${set}.stderr" || true
    if ! jq -e '.success==true' "$out" >/dev/null 2>&1; then
        SOLC_VERSION="0.4.24" /usr/bin/time -v -o "$OUT/${id}__${set}.time" \
            timeout "$TIMEOUT" slither "$f" --detect "$dets" --json "$out" \
            > /dev/null 2> "$OUT/${id}__${set}.stderr" || true
        ver="0.4.24"
    fi
    echo "${id},${set},${ver}" >> "$OUT/_runs.csv"
}

# уязвимые — только своим целевым набором
echo "== Уязвимые =="
while IFS= read -r f; do
    id=$(basename "$f" .sol); sc=$(echo "$id" | grep -oE 'SC[0-9]+')
    run "$f" "$sc"
    echo "  $id ($sc)"
done < <(find "$CORPUS/vulnerable" -name "*.sol" | sort)

# safe — всеми пятью наборами (для FP по каждому классу)
echo "== Safe (×5 наборов) =="
while IFS= read -r f; do
    id=$(basename "$f" .sol)
    for set in SC01 SC05 SC06 SC08 SC09; do run "$f" "$set"; done
    echo "  $id ×5"
done < <(find "$CORPUS/safe" -name "*.sol" | sort)

echo "Готово. Прогонов: $(wc -l < "$OUT/_runs.csv")"
