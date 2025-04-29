from flask import Flask, request, jsonify
import json
from datetime import datetime

app = Flask(__name__)

@app.route('/api/alerts', methods=['POST'])
def receive_alert():
    alert = request.json
    print(f"\n[ALERT] {alert['timestamp']} - {alert['technique']}")
    print(f"Description: {alert['description']}")
    print(f"Source IP: {alert['source_ip']}")
    print(f"Destination IP: {alert['destination_ip']}")
    if 'domain' in alert:
        print(f"Domain: {alert['domain']}")
    print("-" * 50)
    return jsonify({"status": "success"})

if __name__ == '__main__':
    print("[*] Starting EDR Dashboard server on http://localhost:5000")
    app.run(host='0.0.0.0', port=5000) 