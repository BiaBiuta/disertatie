import time
import requests
import pandas as pd
import numpy as np

API_URL = "http://127.0.0.1:8000/api/ingest/"
CSV_PATH = "dataset/cicids2017_sample.csv"

print(f"Pornire simulare trafic către SOC Dashboard ({API_URL})...")
df = pd.read_csv(CSV_PATH, nrows=500, low_memory=False)
df.columns = df.columns.str.strip()
df = df.replace([np.inf, -np.inf], np.nan).dropna()

for idx, row in df.iterrows():
    payload = {
        "src_ip": f"192.168.1.{np.random.randint(10, 200)}",
        "dst_ip": "172.16.0.5",
        "src_port": int(np.random.randint(1024, 65535)),
        "dst_port": int(row.get("Destination Port", 80)),
        "protocol": "TCP",
        "flow_duration": float(row.get("Flow Duration", 0.0)),
        "total_fwd_packets": int(row.get("Total Fwd Packets", 1)),
        "total_bwd_packets": int(row.get("Total Backward Packets", 0)),
        "flow_bytes_per_sec": float(row.get("Flow Bytes/s", 0.0)),
        "flow_packets_per_sec": float(row.get("Flow Packets/s", 0.0)),
        "fwd_pkt_len_max": float(row.get("Fwd Packet Length Max", 0.0)),
        "flow_iat_mean": float(row.get("Flow IAT Mean", 0.0)),
        "flow_iat_max": float(row.get("Flow IAT Max", 0.0))
    }

    try:
        r = requests.post(API_URL, json=payload, timeout=10)
        if r.status_code == 200:
            res = r.json()
            print(f"[{idx+1}/500] Alert ID {res.get('alert_id')} | Risc: {res.get('final_risk')} | Severitate: {res.get('severity')}")
    except Exception as e:
        print(f"Latență rețea / Reîncercare: {e}")
        time.sleep(0.5)
        print(f"Eroare conectare server Django: {e}")
        break

    time.sleep(0.1)  # Interval de 100ms între fluxuri pentru vizualizare cursivă pe ecran