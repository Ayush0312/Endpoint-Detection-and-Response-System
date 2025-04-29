from ..utils.fp_filter import is_false_positive

def inspect(pkt, log_alert):
    try:
        if "NTP" not in pkt:
            return

        src_ip = pkt.ip.src
        dst_ip = pkt.ip.dst

        alert = {
            "technique_id": "T1220",
            "technique": "Network Protocol Abuse",
            "description": "NTP traffic detected - check for amplification or abuse",
            "source_ip": src_ip,
            "destination_ip": dst_ip
        }

        if not is_false_positive(alert):
            log_alert(**alert)
    except Exception:
        pass
