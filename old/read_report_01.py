import os
import sys
from cryptography.fernet import Fernet

def list_scans():
    """Lists available scan folders."""
    if not os.path.exists("scans"):
        print("[-] No 'scans' directory found. Run main.py first.")
        return []
    return os.listdir("scans")

def view_report():
    print("--- SECURE REPORT VIEWER ---")
    
    # 1. Show available folders
    scans = list_scans()
    if not scans:
        return

    print("\nAvailable Scans:")
    for i, scan in enumerate(scans):
        print(f"{i+1}. {scan}")
        
    # 2. User selects a folder
    try:
        choice = int(input("\n[?] Enter the number of the scan to view: ")) - 1
        selected_folder = os.path.join("scans", scans[choice])
    except (ValueError, IndexError):
        print("[-] Invalid selection.")
        return

    # 3. Define paths
    key_path = os.path.join(selected_folder, "secret.key")
    report_path = os.path.join(selected_folder, "vuln_report.enc")

    # 4. Decrypt
    try:
        with open(key_path, "rb") as kf:
            key = kf.read()
            
        f = Fernet(key)
        
        with open(report_path, "rb") as rf:
            encrypted_data = rf.read()
            
        decrypted_data = f.decrypt(encrypted_data).decode()
        
        print("\n" + "="*40)
        print(f" REPORT: {selected_folder}")
        print("="*40)
        print(decrypted_data)
        print("="*40)
        
    except FileNotFoundError:
        print("[-] Error: Could not find report files in that folder.")
    except Exception as e:
        print(f"[-] Decryption error: {e}")

if __name__ == "__main__":
    view_report()
