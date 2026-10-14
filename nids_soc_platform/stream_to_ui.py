import time
import requests
import pandas as pd
import numpy as np

API_URL = "http://127.0.0.1:8000/api/ingest/"
CSV_PATH = "dataset/cicids2017_sample.csv"

print(f"Pornire simulare trafic către SOC Dashboard ({API_URL})...")
df = pd.read_csv(CSV_PATH, nrows=500, low_memory=False)
df.columns = df.columns.str.strip()
df = df.replace([np.inf, -np.inf], np.nan).fillna(0)

for idx, row in df.iterrows():
    # Trimitem tot rândul din CSV sub formă de dicționar (conține toate trăsăturile posibile)
    payload = row.to_dict()

    # Adăugăm metadate suplimentare de rețea
    payload.update({
        "src_ip": f"192.168.1.{np.random.randint(10, 200)}",
        "dst_ip": "172.16.0.5",
        "src_port": int(np.random.randint(1024, 65535)),
        "dst_port": int(row.get("Destination Port", 80)),
        "protocol": "TCP"
    })

    try:
        r = requests.post(API_URL, json=payload, timeout=10)
        if r.status_code == 200:
            res = r.json()
            print(
                f"[{idx + 1}/500] Model: {res.get('mode_used')} | Alert ID {res.get('alert_id')} | Risc: {res.get('final_risk'):.4f} | Sev: {res.get('severity')}")
        else:
            print(f"⚠️ Status HTTP {r.status_code}: {r.text[:100]}")
    except Exception as e:
        print(f"Eroare conectare server Django: {e}")
        break

    time.sleep(0.1)