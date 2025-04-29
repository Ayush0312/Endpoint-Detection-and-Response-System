import requests
import time

def test_http():
    # Test 1: Normal HTTP request
    print("Testing normal HTTP request...")
    requests.get('http://httpbin.org/get')
    
    # Test 2: Suspicious User-Agent
    print("Testing suspicious User-Agent...")
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}
    requests.get('http://httpbin.org/get', headers=headers)
    
    # Test 3: Multiple rapid requests
    print("Testing rapid HTTP requests...")
    for _ in range(5):
        requests.get('http://httpbin.org/get')
        time.sleep(0.1)

if __name__ == "__main__":
    test_http() 