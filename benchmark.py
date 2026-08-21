#!/usr/bin/env python3
import json
import argparse
import os
import re
import subprocess
import concurrent.futures
import time

MALWARE_DIR = "/path/to/dataset"
HASH_FILE = "mirai_dataset_hashes.txt"
OUTPUT_DIR = "./output"
REPORT_FILE = "benchmark_report.json"
VT_FILE = "vt_c2_results.json"

IP_REGEX = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
DOMAIN_REGEX = re.compile(r'^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$')
ARCH_EXTS = ['.mips', '.mipsel', '.x86', '.x86_64', '.arm', '.arm5', '.arm6', '.arm7', '.sh4', '.mpsl', '.spc', '.m68k', '.ppc', '.sh', '.arc', '.txt', '.json', '.c']

# Set environment variable for Ghidra to avoid interactive prompts or missing paths
env = os.environ.copy()
if "GHIDRA_INSTALL_DIR" not in env:
    env["GHIDRA_INSTALL_DIR"] = "/opt/ghidra/ghidra_12.0.4_PUBLIC"

def process_sample(sha256, timeout_val=60, retry_timeout=None):
    binary_path = os.path.join(MALWARE_DIR, sha256)
    
    result = {
        "hash": sha256,
        "table_success": False,
        "c2_success": False,
        "domain_success": False,
        "strings_c2_success": False,
        "strings_domain_success": False,
        "timeout": False,
        "immediate_c2": None,
        "immediate_c2_port": None,
        "c2_correct": False,
        "c2_wrong": False,
        "c2_unverifiable": True,
        "c2s": [],
        "domains": [],
        "strings_c2s": [],
        "strings_domains": [],
        "error": None
    }
    
    if not os.path.exists(binary_path):
        result["error"] = "Binary not found"
        return result

    import hashlib
    try:
        with open(binary_path, "rb") as f:
            real_sha256 = hashlib.sha256(f.read()).hexdigest()
    except Exception as e:
        result["error"] = f"Could not hash file: {e}"
        return result

    try:
        strings_output = subprocess.check_output(["strings", binary_path], stderr=subprocess.DEVNULL, text=True)
        for line in strings_output.splitlines():
            val = line.strip()
            if IP_REGEX.search(val):
                result["strings_c2_success"] = True
                if val not in result["strings_c2s"]:
                    result["strings_c2s"].append(val)
            elif DOMAIN_REGEX.search(val):
                if not any(val.endswith(ext) for ext in ARCH_EXTS):
                    result["strings_domain_success"] = True
                    if val not in result["strings_domains"]:
                        result["strings_domains"].append(val)
    except Exception:
        pass

    output_hash_dir = os.path.join(OUTPUT_DIR, real_sha256)
    
    # timeout.txt left by a previous run counts as a timeout too
    timeout_marker = os.path.join(output_hash_dir, "timeout.txt")
    if os.path.exists(timeout_marker):
        if retry_timeout:
            # drop the marker and any partial JSON from the killed run, so the retry is from scratch
            for f in os.listdir(output_hash_dir):
                if f.endswith(".json") or f == "timeout.txt":
                    os.remove(os.path.join(output_hash_dir, f))
            timeout_val = retry_timeout
        else:
            result["timeout"] = True

    if not os.path.exists(os.path.join(output_hash_dir, "file.txt")) and not result["timeout"]:
        import signal
        try:
            # Run runner.sh in a new process group
            proc = subprocess.Popen(["./runner.sh", "--keep-project", binary_path], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, preexec_fn=os.setsid)
            try:
                proc.communicate(timeout=timeout_val)
            except subprocess.TimeoutExpired:
                os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
                proc.communicate()
                result["error"] = "Timeout"
                result["timeout"] = True
                os.makedirs(output_hash_dir, exist_ok=True)
                with open(os.path.join(output_hash_dir, "timeout.txt"), "w") as f:
                    f.write("timeout")
                # fall through: earlier postScripts (parse_main/xor_scanner/xor_table)
                # write their JSON before cnc_scanner runs last, so a hang in cnc_scanner
                # shouldn't discard credit for what already completed and hit disk
        except Exception as e:
            result["error"] = str(e)
            return result

    # Check xor_table.json
    table_file = os.path.join(OUTPUT_DIR, real_sha256, "xor_table.json")
    if os.path.exists(table_file):
        try:
            with open(table_file, "r") as f:
                data = json.load(f)
                if "table_init_func" in data:
                    result["table_success"] = True
                    # Look for IP in tables
                    tables = data["table_init_func"].get("tables", [])
                    for t in tables:
                        val = t.get("str_data", "")
                        if IP_REGEX.search(val):
                            result["c2_success"] = True
                            if val not in result["c2s"]:
                                result["c2s"].append(val)
                        elif DOMAIN_REGEX.search(val):
                            if not any(val.endswith(ext) for ext in ARCH_EXTS):
                                result["domain_success"] = True
                                if val not in result["domains"]:
                                    result["domains"].append(val)
        except Exception:
            pass

    # Check parse_main.json for C2s as well, as some variants store them directly
    parse_main_file = os.path.join(OUTPUT_DIR, real_sha256, "parse_main.json")
    if os.path.exists(parse_main_file):
        try:
            with open(parse_main_file, "r") as f:
                data = json.load(f)
                if "resolve_cnc_addr_func" in data:
                    addr = data["resolve_cnc_addr_func"].get("cnc", "")
                    if addr:
                        if IP_REGEX.search(addr):
                            result["c2_success"] = True
                            if addr not in result["c2s"]:
                                result["c2s"].append(addr)
                        else:
                            result["domain_success"] = True
                            if addr not in result["domains"]:
                                result["domains"].append(addr)
        except Exception:
            pass

    # Check cnc_scanner.json: C2s hardcoded as numeric immediates in the
    # sockaddr_in setup, which never show up as a string or a table entry
    cnc_file = os.path.join(OUTPUT_DIR, real_sha256, "cnc_scanner.json")
    if os.path.exists(cnc_file):
        try:
            with open(cnc_file, "r") as f:
                data = json.load(f)
            for cand in data.get("cnc_candidates", []):
                if not cand.get("best"):
                    continue
                ip = cand.get("ip", "")
                if not ip:
                    continue
                result["immediate_c2"] = ip
                result["immediate_c2_port"] = cand.get("port")
                result["c2_success"] = True
                if ip not in result["c2s"]:
                    result["c2s"].append(ip)
        except Exception:
            pass

    score_against_vt(result)
    return result


def load_vt_truth():
    """md5 -> {"ips": [...], "domains": [...]} as collected by vt_c2_extractor.py"""
    if not os.path.exists(VT_FILE):
        return {}
    try:
        with open(VT_FILE, "r") as f:
            return json.load(f)
    except Exception:
        return {}


VT_TRUTH = load_vt_truth()


def score_against_vt(result):
    """Compare what we extracted with VirusTotal's network IOCs.

    VT has nothing for a large part of this corpus, so a sample without truth
    is *unverifiable*, never a failure - only samples with known IOCs count
    towards precision.
    """
    truth = VT_TRUTH.get(result["hash"]) or {}
    known = set(truth.get("ips", [])) | set(truth.get("domains", []))
    if not known:
        result["c2_unverifiable"] = True
        return
    result["c2_unverifiable"] = False
    extracted = set(result["c2s"]) | set(result["domains"])
    if not extracted:
        return
    if extracted & known:
        result["c2_correct"] = True
    else:
        result["c2_wrong"] = True


def main():
    parser = argparse.ArgumentParser(description="Benchmark mirai-toushi")
    parser.add_argument("--timeout", type=int, default=60, help="Timeout in seconds for each sample")
    parser.add_argument("--retrytimeout", type=int, metavar="SECONDS", help="Re-run samples that previously timed out, using this timeout instead")
    parser.add_argument("--hashfile", default=HASH_FILE, help="file listing the sample hashes to benchmark")
    parser.add_argument("--report", default=REPORT_FILE, help="where to write the JSON report")
    args = parser.parse_args()

    if not os.path.exists(args.hashfile):
        print(f"Error: {args.hashfile} not found.")
        return

    with open(args.hashfile, "r") as f:
        hashes = [line.strip() for line in f if line.strip()]

    print(f"Starting benchmark on {len(hashes)} samples...")
    start_time = time.time()

    results = []
    
    # We use ThreadPoolExecutor to run things in parallel
    # Ghidra is quite heavy, so limit max_workers to 6 to avoid OOM
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as executor:
        future_to_hash = {executor.submit(process_sample, h, args.timeout, args.retrytimeout): h for h in hashes}
        for i, future in enumerate(concurrent.futures.as_completed(future_to_hash)):
            h = future_to_hash[future]
            try:
                res = future.result()
                results.append(res)
                if res["table_success"]:
                    print(f"[{i+1}/{len(hashes)}] {h[:8]}... Extracted [Table: OK, IP: {'OK' if res['c2_success'] else 'FAIL'}, Dom: {'OK' if res['domain_success'] else 'FAIL'}] | Raw Strings [IP: {'OK' if res['strings_c2_success'] else 'FAIL'}, Dom: {'OK' if res['strings_domain_success'] else 'FAIL'}]")
                else:
                    print(f"[{i+1}/{len(hashes)}] {h[:8]}... Extracted [Table: FAIL, IP: {'OK' if res['c2_success'] else 'FAIL'}, Dom: {'OK' if res['domain_success'] else 'FAIL'}] | Raw Strings [IP: {'OK' if res['strings_c2_success'] else 'FAIL'}, Dom: {'OK' if res['strings_domain_success'] else 'FAIL'}]")
            except Exception as e:
                print(f"[{i+1}/{len(hashes)}] {h[:8]}... Exception: {e}")
                results.append({"hash": h, "table_success": False, "c2_success": False, "domain_success": False, "strings_c2_success": False, "strings_domain_success": False, "c2s": [], "domains": [], "strings_c2s": [], "strings_domains": [], "error": str(e)})

    # Calculate metrics
    table_success_count = sum(1 for r in results if r["table_success"])
    c2_success_count = sum(1 for r in results if r["c2_success"])
    domain_success_count = sum(1 for r in results if r["domain_success"])
    strings_c2_success_count = sum(1 for r in results if r["strings_c2_success"])
    strings_domain_success_count = sum(1 for r in results if r["strings_domain_success"])
    timeout_count = sum(1 for r in results if r.get("timeout"))
    immediate_c2_count = sum(1 for r in results if r.get("immediate_c2"))
    c2_correct_count = sum(1 for r in results if r.get("c2_correct"))
    c2_wrong_count = sum(1 for r in results if r.get("c2_wrong"))
    c2_unverifiable_count = sum(1 for r in results if r.get("c2_unverifiable"))
    verifiable_hits = c2_correct_count + c2_wrong_count
    c2_precision = (c2_correct_count / verifiable_hits) * 100 if verifiable_hits else 0

    table_success_rate = (table_success_count / len(hashes)) * 100 if hashes else 0
    c2_success_rate = (c2_success_count / len(hashes)) * 100 if hashes else 0
    domain_success_rate = (domain_success_count / len(hashes)) * 100 if hashes else 0
    strings_c2_success_rate = (strings_c2_success_count / len(hashes)) * 100 if hashes else 0
    strings_domain_success_rate = (strings_domain_success_count / len(hashes)) * 100 if hashes else 0
    timeout_rate = (timeout_count / len(hashes)) * 100 if hashes else 0

    report = {
        "total_samples": len(hashes),
        "table_success_count": table_success_count,
        "table_success_rate": table_success_rate,
        "c2_success_count": c2_success_count,
        "c2_success_rate": c2_success_rate,
        "domain_success_count": domain_success_count,
        "domain_success_rate": domain_success_rate,
        "strings_c2_success_count": strings_c2_success_count,
        "strings_c2_success_rate": strings_c2_success_rate,
        "strings_domain_success_count": strings_domain_success_count,
        "strings_domain_success_rate": strings_domain_success_rate,
        "timeout_count": timeout_count,
        "timeout_rate": timeout_rate,
        "immediate_c2_count": immediate_c2_count,
        "c2_correct_count": c2_correct_count,
        "c2_wrong_count": c2_wrong_count,
        "c2_unverifiable_count": c2_unverifiable_count,
        "c2_precision": c2_precision,
        "results": results
    }

    with open(args.report, "w") as f:
        json.dump(report, f, indent=4)

    end_time = time.time()
    print("\n--- BENCHMARK SUMMARY ---")
    print(f"Total Samples    : {len(hashes)}")
    print(f"Time Taken       : {end_time - start_time:.2f} seconds")
    print(f"Table Extraction : {table_success_count} / {len(hashes)} ({table_success_rate:.2f}%)")
    print(f"C2 Extraction    : {c2_success_count} / {len(hashes)} ({c2_success_rate:.2f}%)  | Raw Strings IP: {strings_c2_success_count} / {len(hashes)} ({strings_c2_success_rate:.2f}%)")
    print(f"Domain Extraction: {domain_success_count} / {len(hashes)} ({domain_success_rate:.2f}%)  | Raw Strings Domain: {strings_domain_success_count} / {len(hashes)} ({strings_domain_success_rate:.2f}%)")
    print(f"Timeouts         : {timeout_count} / {len(hashes)} ({timeout_rate:.2f}%)")
    print(f"Immediate C2s    : {immediate_c2_count} / {len(hashes)} (numeric literals in sockaddr setup)")
    print(f"VT check         : {c2_correct_count} correct, {c2_wrong_count} wrong, {c2_unverifiable_count} unverifiable | precision {c2_precision:.2f}% of {verifiable_hits} verifiable hits")
    print(f"Full report saved to {args.report}")

if __name__ == "__main__":
    main()
