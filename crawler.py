import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin

def extract_links(url):
    """Fetches a URL and returns a list of all unique links on the page."""
    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.content, "html.parser")
        links = set() # Using a set prevents duplicate links
        
        for a_tag in soup.find_all("a"):
            href = a_tag.get("href")
            if href:
                # urljoin ensures relative links (like '/login.php') become full URLs
                full_url = urljoin(url, href)
                links.add(full_url)
        return list(links)
    except requests.exceptions.RequestException as e:
        print(f"Error connecting to {url}: {e}")
        return []

def extract_forms(url):
    """Fetches a URL and extracts details of all HTML forms."""
    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.content, "html.parser")
        forms = soup.find_all("form")
        form_details = []
        
        for form in forms:
            details = {}
            # Get the action URL (where the form sends data)
            action = form.attrs.get("action", "").lower()
            # Get the method (GET or POST)
            method = form.attrs.get("method", "get").lower()
            
            # Extract all input fields inside the form
            inputs = []
            for input_tag in form.find_all("input"):
                input_type = input_tag.attrs.get("type", "text")
                input_name = input_tag.attrs.get("name")
                inputs.append({"type": input_type, "name": input_name})
                
            details["action"] = urljoin(url, action)
            details["method"] = method
            details["inputs"] = inputs
            form_details.append(details)
            
        return form_details
    except requests.exceptions.RequestException:
        return []

# --- Main Execution Block ---
if __name__ == "__main__":
    # We use the authorized testing site
    target_url = "http://testphp.vulnweb.com"
    
    print(f"--- Crawling {target_url} ---")
    
    # 1. Test finding links
    found_links = extract_links(target_url)
    print(f"\n[+] Found {len(found_links)} links. Here are the first 5:")
    for link in found_links[:5]:
        print(f"    - {link}")
        
    # 2. Test finding forms
    found_forms = extract_forms(target_url)
    print(f"\n[+] Found {len(found_forms)} forms. Here are the details:")
    for i, form in enumerate(found_forms):
        print(f"    Form {i+1}: Sends data to {form['action']} using {form['method'].upper()}")
        print(f"    Inputs needed: {form['inputs']}")
