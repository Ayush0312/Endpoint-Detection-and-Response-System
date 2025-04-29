import json
from datetime import datetime

LOG_FILE = "network_alerts.json"

def init_logger():
    def log_alert(technique_id, technique, description, source_ip, destination_ip, extra={}):
        alert = {
            "timestamp": datetime.utcnow().isoformat(),
            "technique_id": technique_id,
            "technique": technique,
            "description": description,
            "source_ip": source_ip,
            "destination_ip": destination_ip,
            **extra
        }
        print("[DEBUG] Logging alert to file:", alert)
        with open(LOG_FILE, "a") as f:
            f.write(json.dumps(alert) + "\n")
            f.flush() 
    return log_alert
