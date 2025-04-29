from ..utils.fp_filter import is_false_positive

def inspect(pkt, log_alert):
    try:
        if "MDNS" not in pkt:
            return

        src_ip = pkt.ip.src
        dst_ip = pkt.ip.dst

        alert = {
            "technique_id": "T1046",
            "technique": "mDNS Discovery",
            "description": "Multicast DNS detected - lateral movement possible",
            "source_ip": src_ip,
            "destination_ip": dst_ip
        }

        if not is_false_positive(alert):
            log_alert(**alert)
    except Exception:
        pass
