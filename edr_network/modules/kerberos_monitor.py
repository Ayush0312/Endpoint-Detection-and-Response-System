from ..utils.fp_filter import is_false_positive

def inspect(pkt, log_alert):
    try:
        if "KERBEROS" not in pkt:
            return

        src_ip = pkt.ip.src
        dst_ip = pkt.ip.dst

        alert = {
            "technique_id": "T1558.003",
            "technique": "Kerberoasting",
            "description": "Kerberos traffic detected - check for service ticket requests",
            "source_ip": src_ip,
            "destination_ip": dst_ip,
        }

        if not is_false_positive(alert):
            log_alert(**alert)
    except Exception:
        pass
