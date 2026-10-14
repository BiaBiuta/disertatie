"""
stream_fullrow.py
=================
Simulator de trafic care trimite RÂNDUL COMPLET din CIC-IDS2017 (toate coloanele)
către /api/ingest/. Astfel, orice trăsătură cerută de modelul activ (research sau
baseline) este prezentă în payload, iar detecția live funcționează real — atacurile
apar în tabel și în diagrame.

Spre deosebire de stream_to_ui.py (care trimite doar câteva câmpuri snake_case),
acest script trimite exact numele de coloane din CSV, deci nu depinde de ce
trăsături a ales optimizatorul.

Rulare (cu serverul Django pornit, din folderul nids_soc_platform):
    python stream_fullrow.py                 # 300 fluxuri amestecate benign/atac
    python stream_fullrow.py --n 500 --delay 0.05 --attack-ratio 0.5
"""

import time
import json
import argparse
import urllib.request
import numpy as np
import pandas as pd

API_URL = "http://127.0.0.1:8000/api/ingest/"
CSV_PATH = "dataset/cicids2017_sample.csv"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=300, help="număr de fluxuri de trimis")
    ap.add_argument("--delay", type=float, default=0.1, help="pauză între fluxuri (s)")
    ap.add_argument("--attack-ratio", type=float, default=0.5,
                    help="proporția de fluxuri de atac în stream")
    ap.add_argument("--url", default=API_URL)
    args = ap.parse_args()

    df = pd.read_csv(CSV_PATH, low_memory=False)
    df.columns = df.columns.str.strip()
    df = df.replace([np.inf, -np.inf], np.nan).fillna(0.0)

    benign = df[df["Label"].astype(str).str.upper() == "BENIGN"]
    attack = df[df["Label"].astype(str).str.upper() != "BENIGN"]

    n_attack = int(args.n * args.attack_ratio)
    n_benign = args.n - n_attack
    sample = pd.concat([
        benign.sample(n=min(n_benign, len(benign)), random_state=1),
        attack.sample(n=min(n_attack, len(attack)), random_state=2),
    ]).sample(frac=1, random_state=3)  # amestecă

    print(f"Trimit {len(sample)} fluxuri ({n_attack} atac / {n_benign} benign) către {args.url}")
    sent = alerts = 0

    for _, row in sample.iterrows():
        # payload = toate coloanele CSV + câmpuri de afișare
        payload = {col: (float(row[col]) if isinstance(row[col], (int, float, np.floating))
                         else str(row[col])) for col in df.columns}
        dport = int(row.get("Destination Port", 80))
        is_atk = str(row.get("Label", "")).upper() != "BENIGN"
        payload.update({
            "src_ip": f"192.168.1.{np.random.randint(2, 250)}",
            "dst_ip": "172.16.0.5",
            "src_port": int(np.random.randint(1024, 65535)),
            "dst_port": dport,
            "Destination Port": dport,
            "protocol": "TCP",
        })

        req = urllib.request.Request(
            args.url, data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                res = json.loads(resp.read().decode("utf-8"))
                sent += 1
                if res.get("alert_id"):
                    alerts += 1
                tag = "ATAC" if is_atk else "benign"
                print(f"[{sent:03d}] {tag:6s} port={dport:<6} "
                      f"risk={res.get('final_risk')} sev={res.get('severity')} "
                      f"mode={res.get('mode_used')}")
        except Exception as e:
            print(f"Eroare trimitere: {e}")
        time.sleep(args.delay)

    print(f"\nGata. {sent} fluxuri trimise, {alerts} alerte generate.")


if __name__ == "__main__":
    main()
