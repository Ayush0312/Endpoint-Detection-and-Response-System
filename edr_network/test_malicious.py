import socket
import requests
import time
import random
import string
import subprocess
import os

def generate_random_string(length):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def test_dns_tunneling():
    print("\n[*] Testing DNS Tunneling...")
    # Generate high entropy domain names
    for _ in range(3):
        domain = generate_random_string(32) + ".xyz"
        try:
            socket.gethostbyname(domain)
        except:
            pass
        time.sleep(0.5)

def test_http_anomalies():
    print("\n[*] Testing HTTP Anomalies...")
    # Test suspicious User-Agent
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'X-Forwarded-For': '192.168.1.100',
        'Accept': '*/*'
    }
    requests.get('http://httpbin.org/get', headers=headers)
    
    # Test rapid requests
    for _ in range(10):
        requests.get('http://httpbin.org/get')
        time.sleep(0.1)

def test_icmp_tunneling():
    print("\n[*] Testing ICMP Tunneling...")
    # Generate ICMP packets with large payloads
    for _ in range(3):
        subprocess.run(['ping', '-n', '1', '-l', '1000', '8.8.8.8'], 
                      stdout=subprocess.DEVNULL, 
                      stderr=subprocess.DEVNULL)
        time.sleep(1)

def test_port_scan():
    print("\n[*] Testing Port Scan...")
    # Quick port scan simulation
    for port in range(80, 85):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.1)
            sock.connect(('8.8.8.8', port))
            sock.close()
        except:
            pass
        time.sleep(0.1)

def test_suspicious_tls():
    print("\n[*] Testing Suspicious TLS...")
    # Test connections to known malicious domains
    domains = [
        'malware.example.com',
        'suspicious.xyz',
        'bad-domain.net'
    ]
    for domain in domains:
        try:
            socket.gethostbyname(domain)
        except:
            pass
        time.sleep(0.5)

def main():
    print("[*] Starting malicious traffic tests...")
    test_dns_tunneling()
    test_http_anomalies()
    test_icmp_tunneling()
    test_port_scan()
    test_suspicious_tls()
    print("\n[*] Malicious traffic tests completed")

if __name__ == "__main__":
    main() 