import os
import subprocess
import sys
from datetime import datetime
from time import sleep

import joblib
import pandas as pd

# Paths
DATA_PATH = os.path.join(os.path.dirname(__file__), '..', 'data', 'captured_packets.csv')
ALERTS_CSV_PATH = os.path.join(os.path.dirname(__file__), '..', 'data', 'alerts.csv')
MODEL_PATH = os.path.join(os.path.dirname(__file__), '..', 'models', 'rf_model.joblib')
PROTO_ENCODER_PATH = os.path.join(os.path.dirname(__file__), '..', 'models', 'proto_encoder.joblib')

# Load AI Assets
clf = joblib.load(MODEL_PATH)
le_proto = joblib.load(PROTO_ENCODER_PATH)
ABUSEIPDB_API_KEY = os.environ.get('ABUSEIPDB_API_KEY')

# Import AbuseIPDB helper
sys.path.append(os.path.join(os.path.dirname(__file__)))
try:
    from threat_intel import check_ip_abuse
except ImportError:
    def check_ip_abuse(ip, key): return {"abuseConfidenceScore": 0, "isp": "N/A", "countryCode": "N/A"}

# NSL-KDD Attack Mapping
ATTACK_MAP = {0: "Normal", 10: "Neptune (DoS)", 11: "Ipsweep (Probe)", 16: "Satan (Probe)"}
PROTOCOL_MAP = {'TCP': 'tcp', 'UDP': 'udp', 'ICMP': 'icmp'}

def preprocess_row(row):
    proto_type = PROTOCOL_MAP.get(str(row['protocol']).upper(), 'other')
    row['protocol_type'] = le_proto.transform([proto_type])[0] if proto_type in le_proto.classes_ else 0
    row['src_bytes'] = int(row['packet_length']) if pd.notnull(row['packet_length']) else 0
    row['dst_bytes'] = 0
    return row

def main():
    print('--- AI Detection Engine (CSV Database Mode) Started ---')
    last_seen = 0
    while True:
        if not os.path.exists(DATA_PATH):
            sleep(1); continue

        df = pd.read_csv(DATA_PATH)
        if len(df) == 0 or last_seen >= len(df):
            sleep(1); continue

        new_rows = df.iloc[last_seen:].copy()
        processed = new_rows.apply(preprocess_row, axis=1)
        preds = clf.predict(processed[['protocol_type', 'src_bytes', 'dst_bytes']])

        for i, pred in enumerate(preds):
            if pred != 0:
                row = new_rows.iloc[i]
                src_ip = row['src_ip']
                attack_name = ATTACK_MAP.get(pred, f"Attack ({pred})")

                # Fetch Intelligence
                intel = {"abuseConfidenceScore": 0, "isp": "Local", "countryCode": "Local"}
                if ABUSEIPDB_API_KEY and not src_ip.startswith("192.168."):
                    intel = check_ip_abuse(src_ip, ABUSEIPDB_API_KEY)

                # Create Structured Entry
                alert_entry = {
                    'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    'src_ip': src_ip,
                    'dst_ip': row['dst_ip'],
                    'attack': attack_name,
                    'abuse_score': intel.get('abuseConfidenceScore', 0),
                    'isp': intel.get('isp', 'Unknown'),
                    'country': intel.get('countryCode', 'Unknown')
                }

                # Save to alerts.csv for the dashboard
                alert_df = pd.DataFrame([alert_entry])
                alert_df.to_csv(ALERTS_CSV_PATH, mode='a', index=False, header=not os.path.exists(ALERTS_CSV_PATH))
                print(f"\033[91mALERT: {attack_name} detected from {src_ip}\033[0m")

        last_seen = len(df)
        sleep(2)

if __name__ == '__main__':
    main()
