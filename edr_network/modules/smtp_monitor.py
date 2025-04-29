from ..utils.fp_filter import is_false_positive

def inspect(pkt, log_alert):
    try:
        if "SMTP" not in pkt:
            return

        ip_layer = pkt.ip
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst

        alert = {
            "technique_id": "T1071.003",
            "technique": "SMTP Communication",
            "description": "SMTP traffic detected - possible phishing or exfiltration",
            "source_ip": src_ip,
            "destination_ip": dst_ip,
            "destination_port": int(pkt[pkt.transport_layer].dstport)
        }

        if not is_false_positive(alert):
            log_alert(**alert)

    except Exception:
        pass
