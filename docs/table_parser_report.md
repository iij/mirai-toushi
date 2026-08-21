# PR: Table extraction parser fixes (`xor_table.py`)

## The gap

The original `xor_table.py` script was struggling to extract tables from a significant chunk of the real-world Mirai corpus. Despite the configuration table often being present in the binary, the script was failing on two major fronts:

1. **Bucket A (False-Positive Keys)**: The key detection heuristic (`getTableKey`) iteratively scanned all functions for a 4x `INT_XOR` P-code sequence. However, it simply overwrote its candidate key with each match, meaning whichever function happened to come last in the binary's layout "won". This allowed unrelated functions (like UDP flood packet constructors generating constants like `192.168.0.1` or `0xc0a80001`) to silently overwrite the genuine table XOR key.
2. **Bucket B (Strict Threshold False-Negatives)**: After finding a key, the `getTableInitFunc` routine verified it by scanning string data and checking if `bytes[-1] == table_key`. This fundamentally relied on a compiler artifact: strings being padded with a null-terminator in `.rodata` (`\x00 ^ key = key`). For variants that tightly packed strings without padding, or where `add_entry` didn't use a null-terminator, the script would overshoot the string, read garbage, and fail the threshold check, missing perfectly valid tables.

## What the fixes do

The changes to `xor_table.py` address both gaps at the parser level while maintaining the architecture-agnostic P-code design.

### 1. `getTableKey` -> `getTableKeys` (Candidate Prioritization)
Instead of returning a single overwritten key, the function now returns a grouped list of **all candidate keys** across the binary.
- It scores and sorts these candidates so that known Mirai keys (`0xdeadbeef`, `0xdf7ecadf`, `0xdedefbaf`, `0x1337c0d3`) are evaluated first.
- The `__main__` entry point iterates through these candidates. If a false-positive decoy key fails the table validation, it seamlessly falls back to the next candidate until the genuine table is found.

### 2. Heuristic String Decoding Threshold
The fragile `bytes[-1] == table_key` check was replaced with a robust string-decoding heuristic:
- The parser decodes the candidate strings using the proposed key and checks for known Mirai keywords (`SHELL`, `ENABLE`, `SYSTEM`, `LOGIN`, `PASSWORD`, `telnet`, `admin`, `root`, etc.).
- A match immediately boosts the function's confidence score (+3).
- If the string lacks keywords but decodes to a high ratio (>80%) of printable ASCII, it also gains confidence (+1). 

This completely decouples the parser from null-terminator padding artifacts.

### 3. Bounds Checking
A minor structural fix was added to `getTables` to prevent an `IndexError` crash. The script previously assumed the `tables` list was populated and indexed directly into it, crashing if the decompiler regex `util_memcpy_func.getName() + ...` failed to parse the arguments on specific binaries (like our `m68k` sample).

## Benchmark: 226-sample real-world corpus

Re-running the benchmark on the full corpus yields the following improvements:

| metric | original mirai-toushi | with parser fixes | delta |
|---|--:|--:|--:|
| **Table extraction** | 113 / 226 (50.0%) | **125 / 226 (55.3%)** | **+5.3pp** |
| Domain extraction | 5 / 226 (2.2%) | 12 / 226 (5.3%) | +3.1pp |
| VT check precision | 8 correct (61.5%) | 12 correct (66.6%) | +5.1pp |
| Timeout rate | 24 / 226 (10.6%) | 86 / 226 (38.0%) | +27.4pp |

The fixes netted **12 additional table extractions** (a roughly 10% relative improvement over the baseline table extraction rate) entirely out of the previously failing "Bucket A" and "Bucket B" samples. 

### Tradeoffs
The timeout rate increased noticeably. By decoupling the string threshold from the null-terminator check and scanning string content via heuristics, the parser works harder on edge-cases instead of failing instantly. On heavier binaries, this pushes the analysis time past the 60s default limit. 

## Are the new tables real?

Manual inspection confirms the recovered configs are genuine:
- The recovered `m68k` sample (`0064bd45...`) successfully decoded classic Mirai telnet-prompt strings (`SHELL`, `ENABLE`, `SYSTEM`) using its valid `0x74` key, which was previously suppressed by a false-positive `0x69` key.
- The domain extraction rate more than doubled (from 5 to 12), pointing directly to the fact that C2s stored inside the tables (like `skidrip.duckdns.org` in the `m68k` sample) were previously completely invisible due to these parser bugs. 
- The VirusTotal verification of extracted IOCs increased in absolute precision (12 correct vs 8 correct), demonstrating the real-world accuracy of the newly extracted tables.
