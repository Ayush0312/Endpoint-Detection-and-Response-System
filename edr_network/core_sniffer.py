import pyshark
from .utils.log import init_logger
import json
from datetime import datetime
import platform
import psutil
import asyncio
import nest_asyncio

# Import all protocol monitors
from .modules import (
    dns_monitor,
    http_monitor,
    ftp_monitor,
    icmp_monitor,
    dhcp_monitor,
    rdp_monitor,
    smb_monitor,
    smtp_monitor,
    snmp_monitor,
    ssh_monitor,
    telnet_monitor,
    tls_monitor,
    tor_monitor
)

# Apply nest_asyncio to allow nested event loops
nest_asyncio.apply()

def get_default_interface():
    """Get the default network interface based on the operating system"""
    if platform.system() == "Windows":
        # Get the first active interface on Windows
        for interface in psutil.net_if_stats().keys():
            if psutil.net_if_stats()[interface].isup:
                return interface
        return "Wi-Fi"  # Fallback to Wi-Fi if no active interface found
    else:
        return "eth0"  # Default for Linux/Unix systems

INTERFACE = get_default_interface()
ALERT_FILE = "network_alerts.json"

def log_alert(technique_id, technique, description, source_ip, destination_ip, **kwargs):
    alert = {
        "timestamp": str(datetime.utcnow()),
        "technique_id": technique_id,
        "technique": technique,
        "description": description,
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        **kwargs
    }
    
    with open(ALERT_FILE, "a") as f:
        f.write(json.dumps(alert) + "\n")
    
    print(f"\n[ALERT] {alert['timestamp']} - {technique}")
    print(f"Description: {description}")
    print(f"Source IP: {source_ip}")
    print(f"Destination IP: {destination_ip}")
    for key, value in kwargs.items():
        print(f"{key}: {value}")
    print("-" * 50)

async def process_packet(packet):
    """Process a single packet asynchronously"""
    try:
        # Pass packet and logger to each module
        dns_monitor.inspect(packet, log_alert)
        http_monitor.inspect(packet, log_alert)
        ftp_monitor.inspect(packet, log_alert)
        icmp_monitor.inspect(packet, log_alert)
        dhcp_monitor.inspect(packet, log_alert)
        rdp_monitor.inspect(packet, log_alert)
        smb_monitor.inspect(packet, log_alert)
        smtp_monitor.inspect(packet, log_alert)
        snmp_monitor.inspect(packet, log_alert)
        ssh_monitor.inspect(packet, log_alert)
        telnet_monitor.inspect(packet, log_alert)
        tls_monitor.inspect(packet, log_alert)
        tor_monitor.inspect(packet, log_alert)
    except Exception as e:
        print(f"[!] Error processing packet: {e}")

def main():
    print("[*] Starting EDR Network Filter (Full Modular)...")
    print("[*] Monitoring interface:", INTERFACE)
    print("[*] Alerts will be saved to:", ALERT_FILE)
    
    # Initialize alert file
    with open(ALERT_FILE, "w") as f:
        json.dump([], f)
    
    try:
        # Create a new event loop
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        # Create capture
        capture = pyshark.LiveCapture(interface=INTERFACE)
        
        print("\n[*] Starting packet capture...")
        for packet in capture.sniff_continuously():
            # Process packet in the event loop
            loop.run_until_complete(process_packet(packet))
            
    except Exception as e:
        print(f"[!] Error starting capture: {e}")
        print("[!] Please make sure you have the correct permissions and the interface is available.")
    finally:
        loop.close()

if __name__ == '__main__':
    main()
