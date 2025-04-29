from ..utils.fp_filter import is_false_positive

def inspect(pkt, log_alert):
    try:
        if "TLS" not in pkt:
            return

        ip_layer = pkt.ip
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        ja3_hash = pkt.tls.get("ja3") if hasattr(pkt.tls, "ja3") else ""

        alert = {
            "technique_id": "T1040",
            "technique": "Encrypted Traffic (TLS/SSL)",
            "description": "Encrypted TLS traffic detected - potential covert C2",
            "source_ip": src_ip,
            "destination_ip": dst_ip,
            "ja3_hash": ja3_hash
        }

        if not is_false_positive(alert):
            log_alert(**alert)

    except Exception:
        pass
