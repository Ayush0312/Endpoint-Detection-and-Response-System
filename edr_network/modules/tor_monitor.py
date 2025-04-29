from ..utils.fp_filter import is_false_positive

TOR_EXIT_NODES = [
    "51.83.146.238", "204.13.164.118", "171.25.193.20", "85.17.30.79",  # sample IPs
]

def inspect(pkt, log_alert):
    try:
        ip_layer = pkt.ip
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst

        if dst_ip in TOR_EXIT_NODES:
            alert = {
                "technique_id": "T1090.003",
                "technique": "Proxy/Tor Anonymization",
                "description": "Traffic to known Tor exit node",
                "source_ip": src_ip,
                "destination_ip": dst_ip
            }

            if not is_false_positive(alert):
                log_alert(**alert)

    except Exception:
        pass
