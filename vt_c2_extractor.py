import time
import requests
import json
import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()
API_KEY = os.getenv("VT_API_KEY")

if not API_KEY:
    print("Error: Please set VT_API_KEY in your .env file")
    exit(1)

headers = {"x-apikey": API_KEY}

def get_vt_c2s(file_hash):
    ips = []
    domains = []
    
    # By using the relationships parameter, we can fetch the contacted IPs and domains
    # in a single API request, which helps us stay within the VT Free Tier limits.
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}?relationships=contacted_domains,contacted_ips"
    
    try:
        response = requests.get(url, headers=headers)
    except requests.exceptions.RequestException as e:
        return False, [], [], f"Request failed: {e}"
    
    if response.status_code == 200:
        data = response.json()
        
        # Parse contacted domains from relationships
        try:
            domain_data = data.get("data", {}).get("relationships", {}).get("contacted_domains", {}).get("data", [])
            if domain_data:
                for item in domain_data:
                    domains.append(item.get("id"))
        except Exception:
            pass
            
        # Parse contacted IPs from relationships
        try:
            ip_data = data.get("data", {}).get("relationships", {}).get("contacted_ips", {}).get("data", [])
            if ip_data:
                for item in ip_data:
                    ips.append(item.get("id"))
        except Exception:
            pass
            
        return True, ips, domains, None
        
    elif response.status_code == 404:
        return False, [], [], "Hash not found on VirusTotal"
    elif response.status_code == 429:
        return False, [], [], "Rate limit"
    elif response.status_code == 401:
        return False, [], [], "Unauthorized (Check your API key)"
    else:
        return False, [], [], f"HTTP {response.status_code}"

def main():
    hash_file = "mirai_dataset_hashes.txt"
    output_file = "vt_c2_results.json"
    
    if not os.path.exists(hash_file):
        print(f"Error: Hash list file '{hash_file}' not found.")
        return

    with open(hash_file, "r") as f:
        hash_list = [line.strip() for line in f if line.strip()]

    results = {}
    
    # 1. Load existing results to act as cache so we don't query the same hashes
    if os.path.exists(output_file):
        try:
            with open(output_file, "r") as f:
                results = json.load(f)
            print(f"Loaded {len(results)} previously queried hashes from cache.")
        except Exception as e:
            print(f"Warning: Could not load existing cache: {e}")

    print(f"Loaded {len(hash_list)} hashes. Starting VT API extraction...")
    
    try:
        for i, file_hash in enumerate(hash_list):
            # 2. Check if hash is already in our cache before querying
            if file_hash in results:
                print(f"[{i+1}/{len(hash_list)}] Skipping {file_hash} (Already cached)")
                continue

            print(f"[{i+1}/{len(hash_list)}] Querying VT for {file_hash}...")
            success, ips, domains, error = get_vt_c2s(file_hash)
            
            if success:
                print(f"  -> Found {len(ips)} IPs and {len(domains)} Domains")
                results[file_hash] = {
                    "ips": ips,
                    "domains": domains
                }
            else:
                if error == "Rate limit":
                    print("  -> Rate limit hit! Slowing down or upgrading your tier is needed.")
                    break
                print(f"  -> {error}")
                # We also cache missing hashes so we don't waste requests on them again
                if error == "Hash not found on VirusTotal":
                    results[file_hash] = {"ips": [], "domains": [], "error": "Not found"}
            
            # 3. Save incrementally after EACH API call
            with open(output_file, "w") as f:
                json.dump(results, f, indent=4)
            
            # Strictly adhere to the 4 requests/minute limit on the free tier (15 seconds per request)
            if i < len(hash_list) - 1:
                time.sleep(15)

    except KeyboardInterrupt:
        # Safely handle Ctrl+C stopping the script
        print(f"\n[!] Script interrupted by user. Progress up to this point has been saved to {output_file}.")
        return

    print(f"\nExtraction complete. Saved results for {len(results)} hashes to {output_file}")

if __name__ == "__main__":
    main()
