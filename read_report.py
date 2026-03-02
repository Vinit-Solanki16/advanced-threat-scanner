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

def view_report():
    os.system('cls' if os.name == 'nt' else 'clear')
    print("\n" + "="*70)
    print(" SECURE REPORT VIEWER & EXPORTER")
    print("="*70)
    
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
        
        # --- STRING BUILDER FOR EXPORT ---
        # This list captures everything we print so we can save it later
        report_text = []
        
        def out(text=""):
            """Prints to terminal AND saves to our export list."""
            print(text)
            report_text.append(text)
            
        def out_header(title):
            out("\n" + "="*70)
            out(f" {title}")
            out("="*70)

        # --- DISPLAY & CAPTURE THE FULL REPORT ---
        out_header(f"REPORT: {report.get('target', 'Unknown Target')}")
        out(f"Scan Date: {report.get('scan_time', 'Unknown')}")
        
        out("\n[+] NETWORK SECURITY")
        ports = report.get('network_security', {}).get('open_ports', [])
        if ports:
            out(f"    Open Ports: {', '.join(map(str, ports))}")
        else:
            out("    No open ports found or scan failed.")

        endpoints = report.get('discovered_endpoints', [])
        out(f"\n[+] DISCOVERED ENDPOINTS ({len(endpoints)} Total)")
        if endpoints:
            for i, link in enumerate(endpoints):
                out(f"    {i+1}. {link}")
        else:
            out("    No endpoints discovered.")

        forms = report.get('discovered_forms', [])
        out(f"\n[+] INTERACTIVE FORMS EXTRACTED ({len(forms)} Total)")
        if forms:
            for i, form in enumerate(forms):
                out(f"    Form #{i+1}:")
                out(f"      - Action URL : {form.get('action')}")
                out(f"      - HTTP Method: {form.get('method', 'GET').upper()}")
                
                inputs = form.get('inputs', [])
                if inputs:
                    input_list = [f"{inp.get('name', 'unnamed')} ({inp.get('type', 'unknown')})" for inp in inputs]
                    out(f"      - Parameters : {', '.join(input_list)}")
                else:
                    out("      - Parameters : None found")
        else:
            out("    No forms discovered.")

        vulns = report.get('web_vulnerabilities', [])
        out(f"\n[+] VULNERABILITY AUDIT")
        
        if not vulns:
            out("    [SAFE] No critical vulnerabilities detected.")
        else:
            out(f"    [!] WARNING: {len(vulns)} Threat(s) Detected!\n")
            for i, v in enumerate(vulns):
                out(f"    Threat #{i+1}: {v.get('type')}")
                out(f"       URL:      {v.get('url')}")
                out(f"       Severity: {v.get('severity', 'Unknown')}")
                if 'detection_method' in v:
                    out(f"       Method:   {v.get('detection_method')}")
                out("-" * 50)
                
        # --- NEW: LLM Vulnerabilities Section ---
        llm_vulns = report.get('llm_vulnerabilities', [])
        if llm_vulns:
            out(f"\n[+] AI / LLM SECURITY AUDIT")
            out(f"    [!] WARNING: {len(llm_vulns)} AI Prompt Injections Successful!\n")
            for i, v in enumerate(llm_vulns):
                out(f"    AI Threat #{i+1}: {v.get('type')}")
                out(f"       Endpoint: {v.get('endpoint')}")
                out(f"       Severity: {v.get('severity')}")
                out(f"       Vector:   {v.get('attack_vector')}")
                out("-" * 50)
        
        out("\n" + "="*70)
        
        # --- EXPORT FEATURE ---
        export_choice = input("\n[?] Do you want to export this report to a text file? (y/n): ").strip().lower()
        if export_choice == 'y':
            export_filename = "Security_Audit_Report.txt"
            export_path = os.path.join(selected_folder, export_filename)
            
            with open(export_path, "w") as ef:
                ef.write("\n".join(report_text))
                
            print(f"\n[+] SUCCESS! Report successfully exported to: {export_path}")
            print("    You can now copy this file, open it in Word/Google Docs, and print it!")
        
    except FileNotFoundError:
        print("[-] Error: Could not find report files in that folder.")
    except Exception as e:
        print(f"[-] Decryption/Parsing error: {e}")

if __name__ == "__main__":
    view_report()
