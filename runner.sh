#!/usr/bin/env bash
set -euo pipefail

function execute_ghidra_headless_analyzer {
    "$GHIDRA_HEADLESS_PATH" "$GHIDRA_PROJECT_DIR" "$SHA256" -import "$ELF_FILE" \
        -processor "$1" -cspec "$2" -readOnly -analysisTimeoutPerFile 300 \
        -postScript "$RUNNER_DIR"/ghidra_scripts/xor_scanner.py "$OUTPUT_DIR"/"$SHA256"/xor_scanner.json \
        -postScript "$RUNNER_DIR"/ghidra_scripts/xor_table.py "$OUTPUT_DIR"/"$SHA256"/xor_table.json

    echo "output: $OUTPUT_DIR/$SHA256/xor_scanner.json"
    echo "output: $OUTPUT_DIR/$SHA256/xor_table.json"
}

GHIDRA_INSTALL_DIR="${GHIDRA_INSTALL_DIR:-"/opt/ghidra"}"
GHIDRA_HEADLESS_PATH="$GHIDRA_INSTALL_DIR"/support/analyzeHeadless

RUNNER_PATH="$0"
RUNNER_DIR=$(dirname "$RUNNER_PATH")

GHIDRA_PROJECT_DIR="$RUNNER_DIR"/ghidra_project
OUTPUT_DIR="$RUNNER_DIR"/output

ELF_FILE="$1"

if [ "$#" -ne 1 ]; then
    echo "usage: $0 <ELF_FILE>"
    exit 11
fi

if [ ! -f "$ELF_FILE" ]; then
    echo "error: $ELF_FILE not found"
    exit 12
fi

if file "$ELF_FILE" | grep -q "ELF"; then
    :
else
    echo "error: this file is not elf"
    exit 13
fi

READELF_OUTPUT=$(readelf -h "$ELF_FILE" || :)
ARCH=$(echo "$READELF_OUTPUT" | awk '/Machine:/ {print $0}' | sed -e 's/Machine://' | xargs)
BITS=$(echo "$READELF_OUTPUT" | awk '/Class:/ {print $0}' | sed -e 's/Class://' | xargs)
ENDIAN=$(echo "$READELF_OUTPUT" | awk '/Data:/ {print $0}' | sed -e 's/Data://' | cut -d',' -f2 | xargs)
SHA256=$(sha256sum "$ELF_FILE" | cut -d' ' -f1)

if [ ! -d "$GHIDRA_PROJECT_DIR" ]; then
    mkdir -p "$GHIDRA_PROJECT_DIR"
fi

# remove ghidra file for re-analyzing same malware
if [ "$(ls "$GHIDRA_PROJECT_DIR"/"$SHA256"*)" != '' ]; then
    rm -r "${GHIDRA_PROJECT_DIR:?}"/"${SHA256:?}"*
fi

if [ ! -d "$OUTPUT_DIR"/"$SHA256" ]; then
    mkdir -p "$OUTPUT_DIR"/"$SHA256"
fi

if [[ "$ARCH" == "ARM" && "$BITS" == "ELF32" && "$ENDIAN" == "big endian" ]]; then
    execute_ghidra_headless_analyzer ARM:BE:32:v8 default
elif [[ "$ARCH" == "ARM" && "$BITS" == "ELF32" && "$ENDIAN" == "little endian" ]]; then
    execute_ghidra_headless_analyzer ARM:LE:32:v8 default
elif [[ "$ARCH" == "MC68000" && "$BITS" == "ELF32" && "$ENDIAN" == "big endian" ]]; then
    execute_ghidra_headless_analyzer 68000:BE:32:Coldfire default
elif [[ "$ARCH" == "MIPS"* && "$BITS" == "ELF32" && "$ENDIAN" == "big endian" ]]; then
    # e.g. MIPS R3000
    execute_ghidra_headless_analyzer MIPS:BE:32:default default
elif [[ "$ARCH" == "MIPS"* && "$BITS" == "ELF32" && "$ENDIAN" == "little endian" ]]; then
    execute_ghidra_headless_analyzer MIPS:LE:32:default default
elif [[ "$ARCH" == "PowerPC" && "$BITS" == "ELF32" && "$ENDIAN" == "big endian" ]]; then
    execute_ghidra_headless_analyzer PowerPC:BE:32:default default
elif [[ "$ARCH" == "Renesas / SuperH SH" && "$BITS" == "ELF32" && "$ENDIAN" == "little endian" ]]; then
    execute_ghidra_headless_analyzer SuperH4:LE:32:default default
elif [[ "$ARCH" == "Sparc" && "$BITS" == "ELF32" && "$ENDIAN" == "big endian" ]]; then
    execute_ghidra_headless_analyzer sparc:BE:32:default default
elif [[ "$ARCH" == "Intel 80386" && "$BITS" == "ELF32" && "$ENDIAN" == "little endian" ]]; then
    execute_ghidra_headless_analyzer x86:LE:32:default gcc
elif [[ "$ARCH" == "Advanced Micro Devices X86-64" && "$BITS" == "ELF64" && "$ENDIAN" == "little endian" ]]; then
    execute_ghidra_headless_analyzer x86:LE:64:default gcc
else
    echo "error: not supported arch"
    echo "- ARCH: $ARCH"
    echo "- BITS: $BITS"
    echo "- ENDIAN: $ENDIAN"
fi

# output file command results
file "$ELF_FILE" > "$OUTPUT_DIR"/"$SHA256"/file.txt

# output readelf command results
readelf -a "$ELF_FILE" > "$OUTPUT_DIR"/"$SHA256"/readelf.txt || :

# dont save ghidra project files
rm -r "${GHIDRA_PROJECT_DIR:?}"
