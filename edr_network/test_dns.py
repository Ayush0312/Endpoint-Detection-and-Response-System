import socket
import time

def test_dns():
    # Test 1: Normal DNS query
    print("Testing normal DNS query...")
    socket.gethostbyname('google.com')
    
    # Test 2: Suspicious domain (high entropy)
    print("Testing suspicious domain...")
    try:
        socket.gethostbyname('x7z9p2m4k8v3n5q1.xyz')
    except:
        pass
    
    # Test 3: Multiple rapid queries
    print("Testing rapid DNS queries...")
    for _ in range(5):
        try:
            socket.gethostbyname('test' + str(_) + '.com')
        except:
            pass
        time.sleep(0.1)

if __name__ == "__main__":
    test_dns() 