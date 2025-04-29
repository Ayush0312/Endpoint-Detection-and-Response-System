from ..utils.fp_filter import is_false_positive

def inspect(pkt, log_alert):
    try:
        if "NBNS" in pkt or "NBTNS" in pkt or pkt.udp.dstport == 137:
            src_ip = pkt.ip.src
            dst_ip = pkt.ip.dst

            alert = {
                "technique_id": "T1040",
                "technique": "NetBIOS Activity",
                "description": "NetBIOS traffic detected - Windows info disclosure",
                "source_ip": src_ip,
                "destination_ip": dst_ip
            }

            if not is_false_positive(alert):
                log_alert(**alert)
    except Exception:
        pass
