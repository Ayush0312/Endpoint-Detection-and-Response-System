from ..utils.fp_filter import is_false_positive
from datetime import datetime

def inspect(pkt, log_alert):
    try:
        if "DHCP" in pkt or (pkt.udp and (pkt.udp.srcport == "67" or pkt.udp.dstport == "68")):
            src_ip = pkt.ip.src
            dst_ip = pkt.ip.dst
            alert = {
                "timestamp": str(datetime.utcnow()),
                "technique_id": "T1200",
                "technique": "DHCP Activity",
                "description": "DHCP message detected - check for rogue DHCP servers",
                "source_ip": src_ip,
                "destination_ip": dst_ip
            }
            if not is_false_positive(alert):
                log_alert(**alert)
    except:
        pass
