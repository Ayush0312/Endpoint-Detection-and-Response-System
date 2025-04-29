import time
import json
import requests
import os
import threading
from typing import Optional
from .core_sniffer import main as start_sniffer
from data_manager import DataManager

ALERT_FILE = "network_alerts.json"
EDR_SERVER_URL = "http://localhost:5000/api/alerts"  # EDR dashboard endpoint

class NetworkMonitor:
    def __init__(self, data_manager: DataManager):
        self.running = False
        self.thread: Optional[threading.Thread] = None
        self.data_manager = data_manager
        self.stats = {
            'packets_analyzed': 0,
            'suspicious_connections': 0,
            'blocked_ips': set(),
            'protocol_stats': {
                'HTTP': 0,
                'DNS': 0,
                'FTP': 0,
                'SSH': 0,
                'SMTP': 0,
                'Other': 0
            }
        }
        
    def start_monitoring(self):
        """Start the network monitoring"""
        if self.running:
            print("[!] Network monitor is already running")
            return
            
        self.running = True
        self.thread = threading.Thread(target=self._monitor_loop)
        self.thread.daemon = True
        self.thread.start()
        print("[+] Network monitor started")
        
    def stop_monitoring(self):
        """Stop the network monitoring"""
        if not self.running:
            print("[!] Network monitor is not running")
            return
            
        self.running = False
        if self.thread:
            self.thread.join(timeout=5)
        print("[+] Network monitor stopped")
        
    def _monitor_loop(self):
        """Main monitoring loop"""
        print("[*] EDR Network Agent started. Monitoring network traffic...")
        init_alert_file()
        
        try:
            # Start packet capture and analysis
            for packet in start_sniffer():
                if not self.running:
                    break
                    
                # Update statistics
                self.stats['packets_analyzed'] += 1
                
                # Update protocol stats
                if hasattr(packet, 'highest_layer'):
                    protocol = packet.highest_layer
                    if protocol in self.stats['protocol_stats']:
                        self.stats['protocol_stats'][protocol] += 1
                    else:
                        self.stats['protocol_stats']['Other'] += 1
                
                # Check for suspicious activity
                if self._is_suspicious(packet):
                    self.stats['suspicious_connections'] += 1
                    if hasattr(packet, 'ip'):
                        self.stats['blocked_ips'].add(packet.ip.src)
                
                # Update data manager every 10 packets
                if self.stats['packets_analyzed'] % 10 == 0:
                    self.data_manager.update_network_stats(self.stats)
                
        except Exception as e:
            print(f"[!] Error in network monitoring: {e}")
            self.running = False
    
    def _is_suspicious(self, packet) -> bool:
        """Check if a packet is suspicious"""
        try:
            # Example suspicious activity checks
            if hasattr(packet, 'dns') and hasattr(packet.dns, 'qry_name'):
                # Check for suspicious DNS queries
                if '.xyz' in packet.dns.qry_name or '.tk' in packet.dns.qry_name:
                    return True
            
            if hasattr(packet, 'http') and hasattr(packet.http, 'host'):
                # Check for suspicious HTTP requests
                if 'suspicious' in packet.http.host.lower():
                    return True
            
            return False
        except:
            return False

def init_alert_file():
    """Initialize the alert file if it doesn't exist"""
    if not os.path.exists(ALERT_FILE):
        with open(ALERT_FILE, "w") as f:
            json.dump([], f)
        print(f"[+] Created new alert file: {ALERT_FILE}")

def tail_alerts():
    """Monitor the alert file for new alerts"""
    print("[*] EDR Agent started. Monitoring alerts...")
    init_alert_file()
    
    with open(ALERT_FILE, "r") as f:
        f.seek(0, 2)  # Seek to end of file

        while True:
            line = f.readline()
            if not line:
                time.sleep(1)
                continue

            try:
                alert = json.loads(line.strip())
                forward_alert(alert)
            except Exception as e:
                print("[!] Failed to process alert:", e)

def forward_alert(alert):
    """Forward alert to the EDR server"""
    try:
        response = requests.post(EDR_SERVER_URL, json=alert)
        if response.status_code == 200:
            print(f"[+] Alert forwarded: {alert['technique_id']} - {alert['description']}")
        else:
            print(f"[!] Failed to forward alert: {response.status_code}")
    except Exception as e:
        print(f"[!] Network error: {e}")

if __name__ == "__main__":
    # Create a data manager instance for standalone testing
    data_manager = DataManager()
    monitor = NetworkMonitor(data_manager)
    monitor.start_monitoring()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        monitor.stop_monitoring()
