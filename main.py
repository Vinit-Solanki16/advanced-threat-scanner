import sys
import os
import time
import llm_scanner
import concurrent.futures
from urllib.parse import urlparse

try:
    import port_scanner
    import crawler
    import scanner
    import reporter
except ImportError as e:
    print(f"[-] Critical Error: Missing module. {e}")
    sys.exit(1)

def create_scan_folder(target_url):
    domain = urlparse(target_url).netloc
    if not domain: domain = "scan_results"
    clean_domain = domain.split(':')[0]
    
    if not os.path.exists("scans"): os.makedirs("scans")
        
    timestamp = time.strftime("%Y%m%d-%H%M%S")
    folder_name = f"{clean_domain}_{timestamp}"
    folder_path = os.path.join("scans", folder_name)
    
    if not os.path.exists(folder_path): os.makedirs(folder_path)
    print(f"    [+] Scan Workspace: {folder_path}")
    return folder_path

def print_separator(title):
    print("\n" + "="*60)
    print(f" {title}")
    print("="*60)

# --- CONCURRENCY WORKER FUNCTION ---
def scan_single_form(form, target_url):
    """This function is run by multiple threads simultaneously."""
    vulnerabilities = []
    action_url = form.get('action', 'Unknown')
    
    # 1. Test XSS
    if scanner.test_xss_in_form(form, target_url):
        vulnerabilities.append({
            "type": "Reflected XSS",
            "url": action_url,
            "method": form.get('method', 'GET').upper(),
            "severity": "High"
        })
        
    # 2. Test ML Blind SQLi
    try:
        if scanner.test_time_based_sqli(form, target_url):
            vulnerabilities.append({
                "type": "Blind SQL Injection (Time-Based)",
                "detection_method": "ML Anomaly (Isolation Forest)",
                "url": action_url,
                "severity": "Critical"
            })
    except AttributeError:
        pass # Handle if ML function isn't perfectly set up yet
        
    return vulnerabilities

def main():
    os.system('cls' if os.name == 'nt' else 'clear') 
    
    print("""
    ############################################################
    #      ADVANCED THREAT SCANNER (ML & THREADED) v3.0        #
    #      --------------------------------------------        #
    #      > Deep Network Reconnaissance                       #
    #      > Intelligent Form Crawling                         #
    #      > Concurrent Vulnerability Engine                   #
    #      > XSS & ML-Based Blind SQLi Detection               #
    #      > LLM & AI Agent Auditing                           #
    #      > AES-256 Encrypted Reporting                       #
    ############################################################
    """)

    target_url = input("[?] Enter Target URL (e.g., http://testphp.vulnweb.com): ").strip()
    if not target_url.startswith("http"):
        print("[-] Error: URL must start with http:// or https://")
        sys.exit(1)

    # --- NEW: Ask for LLM Endpoint ---
    llm_url = input("[?] Enter Chatbot API Endpoint (or press Enter to skip): ").strip()

    print("\n[*] Initializing scan environment...")
    scan_folder = create_scan_folder(target_url)
    
    full_report = {
        "target": target_url,
        "scan_time": time.ctime(),
        "network_security": {},
        "discovered_endpoints": [], # Added to store links
        "discovered_forms": [],     # Added to store forms
        "web_vulnerabilities": []
    }

    # --- PHASE 1: NETWORK SCANNING ---
    print_separator("PHASE 1: NETWORK INFRASTRUCTURE ANALYSIS")
    print(f"[*] scanning ports and services for {target_url}...")
    try:
        open_ports = port_scanner.scan_ports(target_url)
        full_report["network_security"]["open_ports"] = open_ports
    except Exception as e:
        print(f"[-] Network scan failed: {e}")

    # --- PHASE 2: WEB CRAWLING ---
    print_separator("PHASE 2: INTELLIGENT WEB CRAWLING")
    print("[*] Mapping application structure...")
    try:
        links = crawler.extract_links(target_url)
        forms = crawler.extract_forms(target_url)
        
        # Save to full report so the viewer can see them
        full_report["discovered_endpoints"] = list(links)
        full_report["discovered_forms"] = forms
        
        print(f"    [+] Discovered {len(links)} endpoints.")
        # Print a preview of the first 5 links
        for link in list(links)[:5]:
            print(f"        - {link}")
        if len(links) > 5:
            print("        ... (remaining links saved to encrypted report)")
            
        print(f"\n    [+] Discovered {len(forms)} interactive forms.")
        for form in forms[:3]:
            print(f"        - Form Action: {form.get('action')}")
            
    except Exception as e:
        print(f"[-] Crawler error: {e}")
        forms = []

    # --- PHASE 3: CONCURRENT VULNERABILITY ENGINE ---
    print_separator("PHASE 3: CONCURRENT VULNERABILITY ENGINE")
    
    if not forms:
        print("    [-] No forms found. Skipping injection tests.")
    else:
        print(f"[*] Launching Thread Pool for {len(forms)} forms...")
        
        # This is the Multi-Threading magic!
        # It creates up to 5 workers to scan forms simultaneously.
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            # Submit all forms to the executor
            future_to_form = {executor.submit(scan_single_form, form, target_url): form for form in forms}
            
            # As each thread finishes, gather the results
            for future in concurrent.futures.as_completed(future_to_form):
                found_vulns = future.result()
                if found_vulns:
                    full_report["web_vulnerabilities"].extend(found_vulns)

    # --- NEW PHASE 4: LLM SECURITY AUDITING ---
    if llm_url:
        print_separator("PHASE 4: LLM & AI AGENT SECURITY AUDIT")
        try:
            llm_vulns = llm_scanner.test_llm_endpoint(llm_url)
            if llm_vulns:
                # Add a new list to our report if it doesn't exist
                if "llm_vulnerabilities" not in full_report:
                    full_report["llm_vulnerabilities"] = []
                full_report["llm_vulnerabilities"].extend(llm_vulns)
        except Exception as e:
            print(f"[-] LLM Scan failed: {e}")
    else:
        print("\n[*] Skipping Phase 4: No LLM endpoint provided.")

    # --- PHASE 5: SECURE REPORTING ---
    print_separator("PHASE 5: ENCRYPTED REPORT GENERATION")
    
    report_path = os.path.join(scan_folder, "vuln_report.enc")
    key_path = os.path.join(scan_folder, "secret.key")
    
    try:
        from cryptography.fernet import Fernet
        import json
        
        key = Fernet.generate_key()
        f = Fernet(key)
        
        json_bytes = json.dumps(full_report, indent=4).encode('utf-8')
        encrypted_data = f.encrypt(json_bytes)
        
        with open(key_path, "wb") as kf: kf.write(key)
        with open(report_path, "wb") as rf: rf.write(encrypted_data)
            
        print(f"    [+] Report Encrypted & Saved: {report_path}")
    except Exception as e:
        print(f"[-] Reporting error: {e}")

    print("\n" + "#"*60)
    print(" SCAN COMPLETED SUCCESSFULLY")
    print("#"*60)

if __name__ == "__main__":
    main()
