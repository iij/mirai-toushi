# Benchmarking mirai-toushi

To test improvements to the `mirai-toushi` config extractor against new variants while avoiding regressions, a benchmark framework is available in `benchmark.py`.

## Reproducing the Benchmark

### 1. Build the Dataset Hashes
Create a file named `mirai_dataset_hashes.txt` containing one SHA256 hash per line. These binaries must be unpacked and present in your malware directory.

If you have a tracker file like `whoswho.txt` and want to extract all samples explicitly labeled as Mirai, run:
```bash
awk -F' \\| ' '$5 ~ /Mirai/ || $6 ~ /Mirai/ || $5 ~ /mirai/ || $6 ~ /mirai/ {print $1}' ~/data/malware/mirai2/whoswho.txt > mirai_dataset_hashes.txt
```

### 2. Configure the Paths
Open `benchmark.py` and ensure the following variables point to your correct data locations:
*   `MALWARE_DIR`: The path to the folder containing the unpacked ELF files. (Default: `~/data/malware/mirai2/merged`)
*   `GHIDRA_INSTALL_DIR`: The path to your Ghidra installation. (Set inside the script's environment to `/opt/ghidra/ghidra_12.0.4_PUBLIC` by default).

### 3. Run the Benchmark
Execute the Python script:
```bash
chmod +x benchmark.py
python3 benchmark.py
```

The script will launch up to 6 Ghidra headless analysis workers concurrently to speed up the process.

### 4. Read the Results
When the script completes, it will output a console summary like this:

```
--- BENCHMARK SUMMARY ---
Total Samples    : 226
Time Taken       : 125.30 seconds
Table Extraction : 150 / 226 (66.37%)
C2 Extraction    : 140 / 226 (61.95%)
Full report saved to benchmark_report.json
```

It will save `benchmark_report.json` in the current directory. You can inspect this file to find which specific hashes failed `table_success` or `c2_success` to target them for manual reverse engineering and signature updates.
