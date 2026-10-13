"""
edr_host_watcher.py
===================
Agent autonom de tip EDR Host File Watcher pentru platforma NIDS-XDR-SOAR.
Monitorizează folderul de descărcare al mașinii gazdă, interceptează artefactele
nou descărcate și le transmite automat în Sandbox pentru analiză YARA și fuziune de risc.
"""

import os
import sys
import time
import requests

API_ENDPOINT = "http://127.0.0.1:8000/api/inspect-artifact/"
WATCH_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "host_downloads")

# Extensii binare urmărite de agentul EDR
TARGET_EXTENSIONS = ('.exe', '.dll', '.bin', '.com', '.ps1', '.vbs', '.bat')


def ensure_watch_directory():
    """Asigură existența folderului monitorizat."""
    if not os.path.exists(WATCH_DIR):
        os.makedirs(WATCH_DIR)
        print(f"[EDR Init] S-a creat directorul monitorizat de descărcări: {WATCH_DIR}")
    else:
        print(f"[EDR Init] Monitorizare activă pe directorul: {WATCH_DIR}")


def upload_artifact_to_sandbox(file_path):
    """Transmite fișierul către Sandbox-ul XDR."""
    file_name = os.path.basename(file_path)
    print(f"\n[EDR Detectie] Fisiere nou detectat pe endpoint: {file_name}")
    print(f"[EDR Upload] Expediere binar catre SOC Sandbox ({API_ENDPOINT})...")

    # Așteptăm câteva milisecunde pentru finalizarea completă a scrierii fișierului pe disc
    time.sleep(0.5)

    try:
        with open(file_path, 'rb') as f:
            files = {'file': (file_name, f, 'application/octet-stream')}
            # Agentul trimite fișierul; views.py va face auto-corelarea cu ultima alertă activă
            response = requests.post(API_ENDPOINT, files=files, timeout=15)

        if response.status_code == 200:
            data = response.json()
            if data.get('status') == 'success':
                analysis = data.get('analysis', {})
                verdict = analysis.get('verdict', 'UNKNOWN')
                risk = analysis.get('file_risk_score', 0)
                mitigated = data.get('mitigated_automatically', False)
                yara_count = len(analysis.get('yara_matches', []))

                print(f"[EDR Rezultat] Verdict: {verdict} | Scor Risc: {risk} | YARA Matches: {yara_count}")
                if mitigated:
                    print("🚨 [SOAR AUTONOMOUS TRIGGER] IP-ul asociat a fost izolat automat pe Firewall!")
                else:
                    print("[SOC Info] Artefact inspectat și indexat în telemetrie.")
            else:
                print(f"[EDR Avertisment] Răspuns server fără succes: {data.get('message')}")
        else:
            print(f"[EDR Eroare HTTP] Serverul a răspuns cu codul {response.status_code}")

    except Exception as e:
        print(f"[EDR Eroare Conexiune] Nu s-a putut trimite fișierul la SOC: {e}")


def run_watcher():
    """Bucla principală de monitorizare pe fișiere (Polling rezistent fără biblioteci native externe)."""
    ensure_watch_directory()
    processed_files = set()

    # Pre-populăm fișierele deja existente pentru a nu le re-trimite la repornire
    for f in os.listdir(WATCH_DIR):
        processed_files.add(f)

    print("[EDR Agent Activ] Așteaptă scrieri de fișiere suspecte... (Apasă CTRL+C pentru oprire)")

    try:
        while True:
            current_files = os.listdir(WATCH_DIR)
            for f in current_files:
                if f not in processed_files:
                    file_path = os.path.join(WATCH_DIR, f)
                    if os.path.isfile(file_path):
                        _, ext = os.path.splitext(f)
                        if ext.lower() in TARGET_EXTENSIONS:
                            upload_artifact_to_sandbox(file_path)
                            processed_files.add(f)
            time.sleep(1.0)
    except KeyboardInterrupt:
        print("\n[EDR Agent] Oprit de utilizator.")
        sys.exit(0)


if __name__ == '__main__':
    run_watcher()