from ..utils.fp_filter import is_false_positive
from datetime import datetime

def inspect(pkt, log_alert):
    try:
        # Check if packet has ICMP layer
        if "ICMP" not in pkt:
            return

        # Get IP layer information
        ip_layer = pkt.ip
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst

        # Get ICMP type and code if available
        icmp_type = pkt.icmp.type if hasattr(pkt.icmp, 'type') else "unknown"
        icmp_code = pkt.icmp.code if hasattr(pkt.icmp, 'code') else "unknown"

        # Get packet size
        packet_size = len(pkt) if hasattr(pkt, '__len__') else 0

        # Create detailed alert
        alert = {
            "technique_id": "T1040",
            "technique": "ICMP Tunneling or Discovery",
            "description": f"ICMP packet detected - Type: {icmp_type}, Code: {icmp_code}, Size: {packet_size} bytes",
            "source_ip": src_ip,
            "destination_ip": dst_ip,
            "icmp_type": icmp_type,
            "icmp_code": icmp_code,
            "packet_size": packet_size
        }

        # Log the alert
        print(f"[DEBUG] ICMP packet detected from {src_ip} to {dst_ip}")
        print(f"[DEBUG] ICMP Type: {icmp_type}, Code: {icmp_code}, Size: {packet_size}")
        
        if not is_false_positive(alert):
            log_alert(**alert)

    except Exception as e:
        print(f"[!] Error in ICMP monitor: {e}")
        pass
