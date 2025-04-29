from ..utils.fp_filter import is_false_positive

def inspect(pkt, log_alert):
    try:
        if "LDAP" not in pkt:
            return

        src_ip = pkt.ip.src
        dst_ip = pkt.ip.dst

        alert = {
            "technique_id": "T1069.002",
            "technique": "LDAP Enumeration",
            "description": "LDAP query detected - possible account or group enumeration",
            "source_ip": src_ip,
            "destination_ip": dst_ip,
        }

        if not is_false_positive(alert):
            log_alert(**alert)
    except Exception:
        pass
