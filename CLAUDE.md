# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

Cross-architecture Mirai config extractor. Three standalone Ghidra/Jython scripts in `ghidra_scripts/` reverse the Mirai XOR-obfuscation scheme and dump config (C2, credential list, DoS vectors) as JSON. Everything else in the repo is harness or evaluation around those three scripts.

## Commands

```bash
# Single sample (output lands in ./output/<SHA256>/)
GHIDRA_INSTALL_DIR=/opt/ghidra/ghidra_12.0.4_PUBLIC ./runner.sh <ELF_FILE>
./runner.sh --keep-project <ELF_FILE>   # keep the Ghidra project for GUI inspection

# Corpus benchmark (6 concurrent headless workers)
python3 benchmark.py                          # all hashes in mirai_dataset_hashes.txt
python3 benchmark.py --timeout 120            # per-sample timeout
python3 benchmark.py --retrytimeout 300       # re-run only samples that previously timed out

# VirusTotal ground truth for C2s (needs VT_API_KEY in .env)
python3 vt_c2_extractor.py
```

There is no test suite and no linter. The benchmark **is** the regression test: run it before and after touching a Ghidra script and compare `table_success` / `c2_success` rates in `benchmark_report.json`.

Scripts can also be run by copy-pasting into Ghidra's GUI Jython interpreter (Window → Jython) against an already-open binary — useful when debugging one stubborn sample.

## Architecture

`runner.sh` is the entry point: it hashes the ELF, reads `readelf -h` to map (Machine, Class, Data) → a Ghidra `-processor`/`-cspec` pair, then invokes `analyzeHeadless` once with all three scripts as `-postScript`, each writing its own JSON. **Adding an architecture means two edits**: a new branch in `runner.sh`'s dispatch chain, and the matching language ID added to the `ARCH_*` constants + `LANGS` list in each of the three scripts (they gate arch-specific decompiler/varnode handling on it).

The three scripts target different Mirai source files and are independent:

- `xor_scanner.py` — `scanner.c`. Key extractor finds the function that recursively 1-byte-XORs each byte of data; decoder locates `add_auth_entry()` call sites and decrypts arg1/arg2 (user/pass). Weight (arg3) is plaintext.
- `xor_table.py` (largest) — `table.c`. Key extractor scans `INT_XOR` P-code ops per function and takes the 4 XORed bytes from the function doing it 4 times. Decoder cannot rely on `add_entry()` — it is inlined — so it takes table data from the `util_memcpy()` inside it, then derives each entry's ID arithmetically: `id = (data_addr - table_base_addr) / data_size`, where `data_size` is 6 (MC68000), 8 (other 32-bit), 16 (x86_64). Yields C2/SR domain+port, DoS params, botnet name, kill signatures.
- `parse_main.py` — `main.c` / `attack.c`. Added after the paper's experiment because some variants store the C2 as **plaintext in `resolve_cnc_addr()` rather than in the table**. Also enumerates registered DoS vectors from `attack_init()`.

All three share the same shape: `defUndefinedFuncs()` to recover functions Ghidra missed → `DecompInterface` decompilation → pattern-match decompiled C and P-code (`INT_XOR`, `CALL`/`CALLIND`) → decode. Two load-bearing details from the paper:

- **`updateFunction()` is the core trick.** Ghidra routinely infers the wrong arg count/type for `add_auth_entry`/`add_entry`, which corrupts the decompiled output. The scripts overwrite the signature before reading args. Bugs of the form "extraction works on one arch but not another" are usually here.
- **"Reference connector"** is the paper's name for the `refs` field in table output: it matches `table_retrieve_val(ID, …)` call sites against decoded table IDs to report which function/address consumes each config value. This is what the tool has that miraicfg does not.

Mirai's "4-byte XOR key" is equivalent to a 1-byte key (the 4 bytes are XORed together): `0xdeadbeef` → `0x22`. Known variant keys: MIRAI `0xdeadbeef`/`0x22`, Akiru `0xdf7ecadf`/`0xb4`, SORA `0xdedefbaf`/`0x54`, WICKED `0x1337c0d3`/`0x37`. Both forms appear in table output as `table_original_key` and `table_key`.

Extraction is heuristic on decompiler output, so it is brittle across compilers and Mirai forks — a change that fixes one variant frequently regresses others, which is why the benchmark exists.

## Methodology — follow this when improving the tool

The paper's contribution is as much the development method as the code. Both halves below are what make one script cover 8 architectures; abandoning either is how this tool degenerates into a per-arch pile.

### 1. Design rule: match on P-Code and decompiled C, never on assembly

Ghidra decompiles in stages: `binary → assembly → P-Code → pseudo-C`. Assembly and registers are architecture-specific; **P-Code and the decompiled C are not**. Every detection heuristic in this repo is deliberately written against those two arch-independent layers — that is the entire reason a single script handles ARM through x86_64, and why supporting a new architecture is a small diff rather than a new backend.

Practical consequence when adding or fixing a heuristic:

- Identify functions by **P-Code op patterns** (`INT_XOR`, `CALL`/`CALLIND`) and by **shape of the decompiled C**, not by opcode bytes, instruction mnemonics, or register names.
- Never key on symbol names — real samples are usually stripped.
- If a fix genuinely requires arch-specific handling, gate it on `language_id` against the `ARCH_*` constants (as `xor_table.py` does for the 6/8/16-byte entry size) and keep that block as small as possible. A growing pile of `if language_id ==` is the signal the heuristic was written at the wrong layer.
- Where the decompiler gets in the way (wrong function signatures), fix the decompiler's view with `updateFunction()` rather than special-casing the output per arch.

### 2. Development loop: tune against purpose-built verification samples, not wild samples

Real samples give you no ground truth — you cannot tell a missed config from a sample that has none. The paper's answer is to compile your own corpus where the answer is known:

1. **Collect realistic cross-compilers.** Don't invent a toolchain. The authors surveyed 213 Mirai source repos on GitHub; 115 referenced a toolchain and these reduced to only **4 distinct toolchains** (uClibc 0.9.30.1, Slitaz, Aboriginal Linux 1.2.6 and 1.4.5). From those they took gcc for all 8 supported architectures, keeping every available version per arch — **54 cross-compilers** total.
2. **Build verification malware from real variant sources**, chosen to span different XOR keys: MIRAI, Akiru, SORA, WICKED. Build each **twice — unstripped, then `strip`ped** → **370 samples**.
3. **Iterate**: run the tool, find samples where the config comes out wrong, fix, repeat. The paper's endpoint was 364/370 correct (the other 6 Ghidra could not analyze at all).

The unstripped/stripped pair is the point of the method: the unstripped build has symbols and tells you the correct answer, the stripped build is what the heuristic must solve blind. That's a free oracle, and it is why a fix can be verified rather than guessed at.

**The known gap in this corpus, and the first thing to fix:** everything was built at `-O3`, so other optimization levels were never covered — the documented top cause of extraction failure on real samples (see below). Extending the corpus to `-O0`/`-O1`/`-O2` is the highest-value improvement to the methodology itself.

Order of operations for any change: reproduce on a verification sample → fix at the P-Code/decompiled-C layer → confirm on both stripped and unstripped → then run `benchmark.py` over the real-world corpus to check for regressions.

Output contracts are pinned by `jsonschema/*_jsonschema.json`, with worked examples in `sample/`. Keep them in sync when adding output keys.

`tables_sha256` / `auth_tables_sha256` hash the *extracted config*, not the binary — two samples built for different architectures from the same source share a hash. Use them to group campaigns across arch and to spot new variants; don't break them casually, since they only stay comparable if extraction and serialization stay stable.

## Constraints

- Ghidra scripts run under **Jython 2.7** inside Ghidra — Python 2 syntax only, stdlib only, no pip packages. `.python-version` is 2.7.18 for this reason. The host-side tooling (`benchmark.py`, `vt_c2_extractor.py`) is Python 3.
- Samples must be **unpacked** before analysis. Most packing is UPX, and Mirai commonly corrupts `l_info`/`p_info` header values so plain `upx -d` fails — headers must be restored first. Note UPX does not pack MC68000, SPARC, SuperH4, or ARC ELFs, so those samples arrive unpacked.
- Expect **~50 s per sample** (the paper's figure; miraicfg is 2–3 s). That is why `benchmark.py` defaults to a 60 s timeout and why `--retrytimeout` exists — a "timeout" is often a slow decompile, not a failure.
- `benchmark.py` hardcodes `MALWARE_DIR` at the top; it is machine-specific and expects files named by their SHA256.
- Malware corpus, `.env`, and `output/` are local only — never commit sample binaries or the VT key.

## Known failure modes

Before treating a benchmark miss as a new bug, check it against the causes the paper already documented:

1. **Non-`-O3` builds.** The tool was tuned against verification samples compiled at `-O3`; other optimization levels were not considered during the experiment and were the main cause of low extraction on the IIJ-MALWARE set (notably the MIORI variant). Post-paper updates improved this but it remains the top suspect. x86_64 has the lowest extraction rate for this reason.
2. **Not 1-byte XOR.** Newer variants use other encryption entirely. Out of scope — the tool assumes 1-byte XOR.
3. **C2 in `resolve_cnc_addr()` as plaintext**, not in the table — that is `parse_main.py`'s job, so check its JSON before concluding C2 extraction failed.
4. **Unsupported arch.** AArch64 Mirai exists in the wild (rare); ARC is not supported by Ghidra at all.
5. **Still packed / malformed UPX header.**

Baseline from the paper (2,426 real-world samples): 1,641 passlists (68%), 1,743 tables (72%), vs miraicfg's 673 tables. A local benchmark run materially below that on comparable samples means a regression, not a hard variant.

`report.md` and `docs/no_c2_analysis.md` record the current local failure analysis (which hashes miss C2 and why); `no_C2_found.txt` is the working list of those hashes. Update them when the benchmark numbers move.

## Background

`docs/mirai-toushi-botconf.pdf` is the Botconf 2025 / CyBIN paper describing the design. Read §4 (implementation), §6.1 (extraction failure), and §7.2 (post-paper updates) before making non-trivial changes to a Ghidra script — most "why is it done this way" questions are answered there.
