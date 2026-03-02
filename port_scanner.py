from scapy.all import IP, TCP, sr1
import socket
from urllib.parse import urlparse
import sys

# The Nmap Top 100 Most Common Ports
TOP_100_PORTS = [
    7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111, 113, 119, 135,
    139, 143, 144, 179, 199, 389, 427, 443, 444, 445, 465, 513, 514, 515, 543, 544, 548,
    554, 587, 631, 646, 873, 990, 993, 995, 1025, 1026, 1027, 1028, 1029, 1110, 1433, 1720,
    1723, 1755, 1900, 2000, 2001, 2049, 2121, 2717, 3000, 3128, 3306, 3389, 3986, 4899,
    5000, 5009, 5051, 5060, 5190, 5357, 5432, 5631, 5666, 5800, 5900, 6000, 6001, 6646,
    7070, 8000, 8008, 8009, 8080, 8081, 8443, 8888, 9100, 9999, 10000, 32768, 49152,
    49153, 49154, 49155, 49156, 49157
]

def scan_ports(url):
    """Performs a TCP SYN scan on the Top 100 ports."""
    domain = urlparse(url).netloc
    if not domain:
        domain = url
        
    try:
        target_ip = socket.gethostbyname(domain)
        print(f"[*] Target IP resolved to: {target_ip}")
    except socket.gaierror:
        print("[-] Could not resolve hostname. Check the URL.")
        return []

    print(f"[*] Initiating stealth TCP SYN scan on Top 100 ports...")
    print(f"    (This takes ~30 seconds. Please wait.)\n")
    
    open_ports = []
    
    for port in TOP_100_PORTS:
        # Craft the packet
        packet = IP(dst=target_ip)/TCP(dport=port, flags="S")
        
        # We reduced timeout to 0.5s to speed up the 100-port scan
        response = sr1(packet, timeout=0.5, verbose=0)
        
        if response is not None and response.haslayer(TCP):
            if response.getlayer(TCP).flags == 0x12: # SYN-ACK (Open)
                print(f"    [+] Port {port:5} : OPEN")
                open_ports.append(port)
                
                # Send RST to politely close connection
                rst_packet = IP(dst=target_ip)/TCP(dport=port, flags="R")
                sr1(rst_packet, timeout=0.5, verbose=0)
                
    if not open_ports:
        print("    [-] All Top 100 ports appear filtered or closed.")
        
    return open_ports

if __name__ == "__main__":
    target = "http://testphp.vulnweb.com"
    scan_ports(target)
