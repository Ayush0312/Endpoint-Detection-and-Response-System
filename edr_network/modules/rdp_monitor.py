from ..utils.fp_filter import is_false_positive

def inspect(pkt, log_alert):
    try:
        if pkt.tcp and (pkt.tcp.dstport == "3389" or pkt.tcp.srcport == "3389"):
            ip_layer = pkt.ip
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst

            alert = {
                "technique_id": "T1021.001",
                "technique": "Remote Desktop Protocol (RDP)",
                "description": "RDP connection attempt detected",
                "source_ip": src_ip,
                "destination_ip": dst_ip,
                "destination_port": int(pkt.tcp.dstport)
            }

            if not is_false_positive(alert):
                log_alert(**alert)

    except Exception:
        pass
