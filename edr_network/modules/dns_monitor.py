from ..utils.entropy import is_high_entropy
from ..utils.fp_filter import is_false_positive
from datetime import datetime

INTERNAL_IP_RANGE = "192.168."

def inspect(pkt, log_alert):
    try:
        if "DNS" not in pkt:
            return

        ip_layer = pkt.ip
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst

        if not src_ip.startswith(INTERNAL_IP_RANGE):
            return

        domain = pkt.dns.qry_name if hasattr(pkt.dns, 'qry_name') else ""

        if domain.endswith(".xyz") or is_high_entropy(domain):
            alert = {
                "timestamp": str(datetime.utcnow()),
                "technique_id": "T1071.004",
                "technique": "C2 Over DNS",
                "description": f"Suspicious DNS query: {domain}",
                "source_ip": src_ip,
                "destination_ip": dst_ip,
                "domain": domain
            }
            if not is_false_positive(alert):
                log_alert(**alert)

        if hasattr(pkt.dns, 'qry_type') and pkt.dns.qry_type == "16":
            alert = {
                "timestamp": str(datetime.utcnow()),
                "technique_id": "T1048.003",
                "technique": "DNS TXT Exfiltration",
                "description": f"TXT record in DNS query: {domain}",
                "source_ip": src_ip,
                "destination_ip": dst_ip,
                "domain": domain
            }
            if not is_false_positive(alert):
                log_alert(**alert)

    except:
        pass

