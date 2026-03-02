import json
import os
from cryptography.fernet import Fernet

def generate_key():
    """Generates a secret key and saves it to a file."""
    key = Fernet.generate_key()
    with open("secret.key", "wb") as key_file:
        key_file.write(key)
    print("    [+] New encryption key generated and saved as 'secret.key'")
    return key

def encrypt_report(data, filename="vuln_report.enc"):
    """Encrypts the vulnerability data and saves it securely."""
    # 1. Load or generate the encryption key
    if not os.path.exists("secret.key"):
        key = generate_key()
    else:
        with open("secret.key", "rb") as key_file:
            key = key_file.read()
            print("    [+] Existing encryption key loaded.")
            
    f = Fernet(key)
    
    # 2. Convert our Python dictionary into a JSON string, then into bytes
    json_data = json.dumps(data, indent=4).encode('utf-8')
    
    # 3. Encrypt the bytes
    encrypted_data = f.encrypt(json_data)
    
    # 4. Save the encrypted data to a file
    with open(filename, "wb") as file:
        file.write(encrypted_data)
    print(f"    [+] Encrypted report securely saved to '{filename}'")

def decrypt_report(filename="vuln_report.enc"):
    """Decrypts the report so the authorized user can read it."""
    with open("secret.key", "rb") as key_file:
        key = key_file.read()
        
    f = Fernet(key)
    
    with open(filename, "rb") as file:
        encrypted_data = file.read()
        
    # Decrypt and decode back to a string
    decrypted_data = f.decrypt(encrypted_data).decode('utf-8')
    
    print("\n--- DECRYPTED REPORT CONTENTS ---")
    print(decrypted_data)
    print("---------------------------------")

# --- Main Execution Block ---
if __name__ == "__main__":
    print("--- Secure Reporting Module ---")
    
    # These are the simulated findings from our previous crawler, scanner, and scapy scripts
    findings = {
        "target_url": "http://testphp.vulnweb.com",
        "scapy_network_scan": {
            "open_ports": [80],
            "filtered_ports": [22, 443, 8080]
        },
        "web_vulnerabilities": [
            {
                "type": "Cross-Site Scripting (XSS)",
                "vulnerable_url": "http://testphp.vulnweb.com/search.php?test=query",
                "parameter": "searchFor",
                "injected_payload": "<script>alert('XSS_VULNERABILITY_FOUND')</script>"
            }
        ],
        "overall_risk_level": "CRITICAL"
    }
    
    print("[*] Encrypting findings...")
    encrypt_report(findings)
    
    print("\n[*] Simulating authorized user decrypting the report...")
    decrypt_report()
