from ..utils.fp_filter import is_false_positive
from datetime import datetime

def inspect(pkt, log_alert):
    try:
        if "bittorrent" in str(pkt):
            src_ip = pkt.ip.src
            dst_ip = pkt.ip.dst
            alert = {
                "timestamp": str(datetime.utcnow()),
                "technique_id": "T1071",  # Application Layer Protocol
                "technique": "BitTorrent Traffic",
                "description": "Potential P2P traffic detected",
                "source_ip": src_ip,
                "destination_ip": dst_ip
            }
            if not is_false_positive(alert):
                log_alert(**alert)
    except:
        pass
