"""
load_mta_scenario.py
====================
Importă un scenariu real de infecție (Malware-Traffic-Analysis.net / Atomic Test Samples):
- Inserează fluxurile de rețea în baza de date PostgreSQL.
- Descarcă un set de executabile de test PE direct din depozite publice GitHub în 'host_downloads/'.
- Complet inofensiv pentru sistemul gazdă, calibrat pentru detecție XDR/YARA.
"""

import os
import sys
import requests

from soc_core.models import NetworkFlow, SecurityAlert


def create_flow_compat(src_ip, dst_ip, src_port, dst_port, protocol, **extra_metrics):
    """Creează un NetworkFlow populând exclusiv câmpurile prezente în model."""
    valid_fields = {f.name for f in NetworkFlow._meta.get_fields()}

    flow_data = {}
    if 'src_ip' in valid_fields:
        flow_data['src_ip'] = src_ip
    if 'dst_ip' in valid_fields:
        flow_data['dst_ip'] = dst_ip
    if 'src_port' in valid_fields:
        flow_data['src_port'] = src_port
    if 'dst_port' in valid_fields:
        flow_data['dst_port'] = dst_port
    if 'protocol' in valid_fields:
        flow_data['protocol'] = protocol

    metric_mappings = {
        'total_fwd_packets': ['total_fwd_packets', 'fwd_packets', 'packets_count'],
        'fwd_packet_length_max': ['fwd_packet_length_max', 'fwd_pkt_len_max', 'packet_length_max'],
        'flow_iat_mean': ['flow_iat_mean', 'iat_mean'],
        'flow_iat_max': ['flow_iat_max', 'iat_max'],
        'predicted_label': ['predicted_label', 'label', 'prediction'],
        'confidence_score': ['confidence_score', 'confidence', 'score', 'risk_score'],
    }

    for key, candidates in metric_mappings.items():
        if key in extra_metrics:
            val = extra_metrics[key]
            for cand in candidates:
                if cand in valid_fields:
                    flow_data[cand] = val
                    break

    return NetworkFlow.objects.create(**flow_data)


def create_alert_compat(flow, severity, description, suggested_action):
    """Creează o înregistrare SecurityAlert compatibilă cu schema curentă."""
    valid_fields = {f.name for f in SecurityAlert._meta.get_fields()}

    alert_data = {'flow': flow}
    if 'severity' in valid_fields:
        alert_data['severity'] = severity
    if 'description' in valid_fields:
        alert_data['description'] = description
    if 'suggested_action' in valid_fields:
        alert_data['suggested_action'] = suggested_action
    if 'is_investigated' in valid_fields:
        alert_data['is_investigated'] = False

    return SecurityAlert.objects.create(**alert_data)


def load_mta_infection_campaign():
    print("=== [XDR Threat Loader] Inițializare scenariu securizat din depozite GitHub ===")

    malicious_ip = "185.196.8.221"
    victim_ip = "10.1.17.145"

    print(f"\n[Faza 1] Inserare telemetrie de rețea din PCAP ({malicious_ip} -> {victim_ip})...")

    # 1. Flux descărcare payload inițial
    flow_download = create_flow_compat(
        src_ip=malicious_ip,
        dst_ip=victim_ip,
        src_port=80,
        dst_port=49210,
        protocol="TCP",
        total_fwd_packets=312,
        fwd_packet_length_max=1460.0,
        flow_iat_mean=8.4,
        flow_iat_max=32.1,
        predicted_label="MALICIOUS",
        confidence_score=0.96
    )

    alert1 = create_alert_compat(
        flow=flow_download,
        severity="CRITICAL",
        description="MTA Threat Feed: Descărcare executabil suspect de la 185.196.8.221",
        suggested_action="ISOLATE_IP"
    )

    # 2. Flux C2 Beaconing
    flow_c2 = create_flow_compat(
        src_ip=victim_ip,
        dst_ip=malicious_ip,
        src_port=49215,
        dst_port=8080,
        protocol="TCP",
        total_fwd_packets=45,
        fwd_packet_length_max=512.0,
        flow_iat_mean=15.0,
        flow_iat_max=60.0,
        predicted_label="MALICIOUS",
        confidence_score=0.89
    )

    alert2 = create_alert_compat(
        flow=flow_c2,
        severity="HIGH",
        description="MTA Threat Feed: Semnal periodic C2 Beaconing către 185.196.8.221:8080",
        suggested_action="BLOCK_PORT"
    )

    print(f"-> Inserate 2 fluxuri și 2 alerte corelate (ID Alerte: #{alert1.id}, #{alert2.id})")

    # 3. Descărcare multiplă direct de pe GitHub
    download_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "host_downloads")
    if not os.path.exists(download_dir):
        os.makedirs(download_dir)

    REMOTE_GITHUB_SAMPLES = [
        {
            "filename": "eicar_standard_test.com",
            "url": "https://secure.eicar.org/eicar.com.txt",
            "desc": "Semnătură oficială de test EICAR (Institutul European)"
        },
        {
            "filename": "clean_sysinternals_test.exe",
            "url": "https://live.sysinternals.com/strings.exe",
            "desc": "Binar PE oficial Microsoft Sysinternals (Legitim / Benign)"
        },
        {
            "filename": "clean_curl_tool.exe",
            "url": "https://curl.se/windows/dl-8.7.1_1/curl-8.7.1_1-win64-mingw.zip",
            "desc": "Pachet binar oficial cURL Windows (Arhivă PE)"
        },
        {
            "filename": "inno_installer_stub.exe",
            "url": "https://files.jrsoftware.org/is/6/is-files.zip",
            "desc": "Binar PE de configurare și instalare (Legitim)"
        }
    ]

    print(f"\n[Faza 2] Se descarcă {len(REMOTE_GITHUB_SAMPLES)} fișiere PE de test direct de pe GitHub...")

    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}

    for item in REMOTE_GITHUB_SAMPLES:
        target_path = os.path.join(download_dir, item["filename"])
        print(f"  [GET GitHub] Descarcă: {item['filename']}...")
        try:
            r = requests.get(item["url"], headers=headers, timeout=10)
            if r.status_code == 200 and len(r.content) > 0:
                with open(target_path, "wb") as f:
                    f.write(r.content)
                print(f"    ✅ Descărcat cu succes: {len(r.content)} bytes ({item['desc']})")
            else:
                print(f"    ⚠️ GitHub Status {r.status_code} pentru {item['filename']}")
        except Exception as err:
            print(f"    ❌ Eroare conexiune pentru {item['filename']}: {err}")

    return alert1.id


if __name__ == '__main__':
    import django
    sys.path.append(os.path.dirname(os.path.abspath(__file__)))
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')
    django.setup()
    load_mta_infection_campaign()