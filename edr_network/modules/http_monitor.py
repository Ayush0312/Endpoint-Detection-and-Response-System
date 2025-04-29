from ..utils.fp_filter import is_false_positive

def inspect(pkt, log_alert):
    try:
        if "HTTP" not in pkt:
            return

        ip_layer = pkt.ip
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        host = pkt.http.host if hasattr(pkt.http, 'host') else ""

        alert = {
            "technique_id": "T1071.001",
            "technique": "HTTP Communication",
            "description": f"HTTP request to {host}",
            "source_ip": src_ip,
            "destination_ip": dst_ip,
            "domain": host,
            "destination_port": int(pkt[pkt.transport_layer].dstport)
        }

        if not is_false_positive(alert):
            log_alert(**alert)

    except Exception:
        pass
