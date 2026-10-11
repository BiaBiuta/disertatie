import pandas as pd
import urllib.request
import json
import time

url = "http://127.0.0.1:8000/api/ingest/"
csv_path = "dataset/cicids2017_sample.csv"

df = pd.read_csv(csv_path)
df.columns = df.columns.str.strip()

print(f"Începe streamingul a 30 de fluxuri reale către platformă...")

for i, row in df.sample(n=30, random_state=123).iterrows():
    payload = {
        "src_ip": f"192.168.1.{int(row.get('Destination Port', 80)) % 250 + 1}",
        "dst_ip": "172.16.0.1",
        "src_port": 50000 + (i % 1000),
        "dst_port": int(row.get('Destination Port', 80)),
        "protocol": "TCP",
        "flow_duration": float(row.get('Flow Duration', 0.0)),
        "total_fwd_packets": int(row.get('Total Fwd Packets', 0)),
        "total_bwd_packets": int(row.get('Total Backward Packets', 0)),
        "flow_bytes_per_sec": float(row.get('Flow Bytes/s', 0.0)),
        "flow_packets_per_sec": float(row.get('Flow Packets/s', 0.0))
    }

    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode('utf-8'),
        headers={'Content-Type': 'application/json'}
    )

    try:
        with urllib.request.urlopen(req) as resp:
            data = json.loads(resp.read().decode('utf-8'))
            print(f"[Flux {i}] Port: {payload['dst_port']} | Risc: {data['final_risk']}")
    except Exception as err:
        print(f"Eroare trimitere: {err}")

    time.sleep(1.5)