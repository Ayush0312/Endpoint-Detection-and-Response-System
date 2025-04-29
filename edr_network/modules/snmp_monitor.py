from ..utils.fp_filter import is_false_positive

def inspect(pkt, log_alert):
    try:
        if "SNMP" not in pkt:
            return

        ip_layer = pkt.ip
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst

        alert = {
            "technique_id": "T1046",
            "technique": "SNMP Discovery",
            "description": "SNMP traffic detected - may be part of network discovery",
            "source_ip": src_ip,
            "destination_ip": dst_ip
        }

        if not is_false_positive(alert):
            log_alert(**alert)

    except Exception:
        pass
