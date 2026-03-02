import os
import sys
import json
from cryptography.fernet import Fernet

def list_scans():
    """Lists available scan folders."""
    if not os.path.exists("scans"):
        print("[-] No 'scans' directory found. Run main.py first.")
        return []
    return sorted(os.listdir("scans"))

def print_header(title):
    print("\n" + "="*70)
    print(f" {title}")
    print("="*70)

def view_report():
    os.system('cls' if os.name == 'nt' else 'clear')
    print_header("SECURE REPORT VIEWER")
    
    scans = list_scans()
    if not scans:
        return

    print("\nAvailable Scan Reports:")
    for i, scan in enumerate(scans):
        print(f"[{i+1}] {scan}")
        
    try:
        choice = int(input("\n[?] Select report number to decrypt: ")) - 1
        selected_folder = os.path.join("scans", scans[choice])
    except (ValueError, IndexError):
        print("[-] Invalid selection.")
        return

    key_path = os.path.join(selected_folder, "secret.key")
    report_path = os.path.join(selected_folder, "vuln_report.enc")

    try:
        with open(key_path, "rb") as kf:
            key = kf.read()
            
        f = Fernet(key)
        
        with open(report_path, "rb") as rf:
            encrypted_data = rf.read()
            
        decrypted_json = f.decrypt(encrypted_data).decode()
        report = json.loads(decrypted_json)
        
        # --- DISPLAY THE FULL REPORT ---
        print_header(f"REPORT: {report.get('target', 'Unknown Target')}")
        print(f"Scan Date: {report.get('scan_time', 'Unknown')}")
        
        # 1. Network Section
        print("\n[+] NETWORK SECURITY")
        ports = report.get('network_security', {}).get('open_ports', [])
        if ports:
            print(f"    Open Ports: {', '.join(map(str, ports))}")
        else:
            print("    No open ports found or scan failed.")

        # 2. Endpoints Section (Now shows ALL of them)
        endpoints = report.get('discovered_endpoints', [])
        print(f"\n[+] DISCOVERED ENDPOINTS ({len(endpoints)} Total)")
        if endpoints:
            for i, link in enumerate(endpoints):
                print(f"    {i+1}. {link}")
        else:
            print("    No endpoints discovered.")

        # 3. Forms Section (NEW: Formatted beautifully)
        forms = report.get('discovered_forms', [])
        print(f"\n[+] INTERACTIVE FORMS EXTRACTED ({len(forms)} Total)")
        if forms:
            for i, form in enumerate(forms):
                print(f"    Form #{i+1}:")
                print(f"      - Action URL : {form.get('action')}")
                print(f"      - HTTP Method: {form.get('method', 'GET').upper()}")
                
                # Format the inputs so they are easy to read
                inputs = form.get('inputs', [])
                if inputs:
                    input_list = [f"{inp.get('name', 'unnamed')} ({inp.get('type', 'unknown')})" for inp in inputs]
                    print(f"      - Parameters : {', '.join(input_list)}")
                else:
                    print("      - Parameters : None found")
        else:
            print("    No forms discovered.")

        # 4. Vulnerabilities Section
        vulns = report.get('web_vulnerabilities', [])
        print(f"\n[+] VULNERABILITY AUDIT")
        
        if not vulns:
            print("    [SAFE] No critical vulnerabilities detected.")
        else:
            print(f"    [!] WARNING: {len(vulns)} Threat(s) Detected!\n")
            for i, v in enumerate(vulns):
                print(f"    Threat #{i+1}: {v.get('type')}")
                print(f"       URL:      {v.get('url')}")
                print(f"       Severity: {v.get('severity', 'Unknown')}")
                if 'detection_method' in v:
                    print(f"       Method:   {v.get('detection_method')}")
                print("-" * 50)
        
        print("\n" + "="*70)
        
    except FileNotFoundError:
        print("[-] Error: Could not find report files in that folder.")
    except Exception as e:
        print(f"[-] Decryption/Parsing error: {e}")

if __name__ == "__main__":
    view_report()
