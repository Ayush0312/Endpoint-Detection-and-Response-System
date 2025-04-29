from datetime import datetime, timedelta

alert_history = {}

# MITRE technique-based suppression rules for known false positives
IGNORED_TECHNIQUES = {
    "T1046": {  # Network Service Discovery (NetBIOS, LLMNR, mDNS)
        "source_ip_prefixes": ["192.168.1.", "192.168.57."],
        "allowed_ports": [5353, 137, 138],
        "ignore_destinations": ["224.0.0.251", "255.255.255.255"],
        "max_per_minute": 8,
    },
    "T1040": {  # ICMP Tunneling or Discovery
        "source_ip_prefixes": [],  # Allow all source IPs
        "ignore_destinations": [],  # Don't ignore any destinations
        "max_per_minute": 30,  # Allow more ICMP packets per minute
        "allowed_types": [0, 8]  # Allow echo request (8) and echo reply (0)
    },
    "T1071": {  # Application Layer Protocol (HTTP/HTTPS C2)
        "trusted_domains": ["update.microsoft.com", "s3.amazonaws.com", "windowsupdate.com"],
        "max_per_minute": 10
    },
    "T1078": {  # Valid Accounts (LDAP/Kerberos)
        "source_ip_prefixes": ["192.168.0.10", "192.168.0.11"],
        "max_per_minute": 20
    },
    "T1200": {  # DHCP spoof detection
        "allowed_ports": [67, 68],
        "source_ip_prefixes": ["192.168."],
        "ignore_destinations": ["255.255.255.255"],
        "max_per_minute": 6
    },
    "T1071.004": {  # DNS C2
        "trusted_domains": ["dns.google", "cloudflare-dns.com"],
        "max_per_minute": 10
    },
    "T1021.001": {  # RDP
        "max_per_minute": 3
    },
    "T1021.002": {  # SMB
        "max_per_minute": 5
    },
    "T1048.003": {  # DNS TXT Exfiltration
        "max_per_minute": 2
    },
    "T1021.004": {  # SSH
        "max_per_minute": 3
    }
}

def is_false_positive(alert):
    technique = alert.get("technique_id")
    src_ip = alert.get("source_ip")
    dst_ip = alert.get("destination_ip")
    dst_port = alert.get("destination_port", None)
    domain = alert.get("domain", None)
    icmp_type = alert.get("icmp_type", None)
    now = datetime.utcnow()

    if not technique or technique not in IGNORED_TECHNIQUES:
        return False

    rule = IGNORED_TECHNIQUES[technique]

    # Special handling for ICMP
    if technique == "T1040":
        # Allow all ICMP echo request/reply packets
        if icmp_type in rule.get("allowed_types", []):
            return True

    # Match source IP prefix
    for prefix in rule.get("source_ip_prefixes", []):
        if src_ip.startswith(prefix):
            return True

    # Ignore destination broadcast/multicast
    if dst_ip in rule.get("ignore_destinations", []):
        return True

    # Allow specific ports
    if dst_port and dst_port in rule.get("allowed_ports", []):
        return True

    # Allow known trusted domains
    if domain and domain in rule.get("trusted_domains", []):
        return True

    # Rate limit check (per minute per technique + source)
    key = (technique, src_ip)
    if key not in alert_history:
        alert_history[key] = []
    alert_history[key].append(now)

    # Keep only recent (last 1 min) timestamps
    alert_history[key] = [ts for ts in alert_history[key] if now - ts < timedelta(minutes=1)]

    if len(alert_history[key]) > rule.get("max_per_minute", 10):
        return True

    return False
