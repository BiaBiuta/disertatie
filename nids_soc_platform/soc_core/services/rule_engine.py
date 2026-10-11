def check_rules(flow_dict: dict) -> tuple[str, float]:
    """
    Exemplu de filtrare rapidă deterministă.
    Returnează: (nume_regulă, scor_regulă)
    """
    dst_port = flow_dict.get('dst_port')
    pkt_per_sec = flow_dict.get('flow_packets_per_sec', 0)

    # SSH Brute Force suspicion
    if dst_port == 22 and pkt_per_sec > 100:
        return "SSH_BRUTE_FORCE_BURST", 0.90

    # Port scan rapid
    if flow_dict.get('flow_duration', 1) < 0.05 and flow_dict.get('total_fwd_packets', 0) > 40:
        return "FAST_PORT_SCAN", 0.75

    return "NONE", 0.0
def evaluate_suricata_rules(flow: dict) -> dict:
    """
    Emulează logica unui motor Suricata EVE pe fluxuri de rețea.
    Dacă se potrivește o regulă, returnează metadatele de alertă.
    Dacă nu, marchează fluxul pentru inspecție de anomalie ML.
    """
    dst_port = int(flow.get('dst_port', 0))
    duration = float(flow.get('flow_duration', 0.0))
    fwd_pkts = int(flow.get('total_fwd_packets', 0))
    pkt_rate = float(flow.get('flow_packets_per_sec', 0.0))
    byte_rate = float(flow.get('flow_bytes_per_sec', 0.0))

    alert_match = None

    # Regula 1: SYN Flood / Volumetric Scan
    if duration < 0.1 and pkt_rate > 100 and fwd_pkts > 30:
        alert_match = {
            "signature": "ET SCAN Suspicious Rapid Burst Probe",
            "category": "Attempted Information Leak",
            "severity_score": 0.85,
            "action": "blocked"
        }

    # Regula 2: SSH Brute Force Triage (Rată mare)
    elif dst_port == 22 and pkt_rate > 80:
        alert_match = {
            "signature": "ET POLICY Potential SSH Brute-Force",
            "category": "Potential Corporate Privacy Violation",
            "severity_score": 0.90,
            "action": "flagged"
        }

    # Regula 3: DoS / High Flow Volume
    elif byte_rate > 60000:
        alert_match = {
            "signature": "ET DOS High Volume Data Exfiltration/Flood",
            "category": "Denial of Service",
            "severity_score": 0.95,
            "action": "dropped"
        }

    # Regula 4: Detecție Atac Persistent Low-and-Slow / Slowloris
    elif duration > 10.0 and byte_rate < 1500.0 and fwd_pkts > 8 and dst_port in [80, 443, 8080]:
        alert_match = {
            "signature": "ET DOS Possible Slowloris Low-and-Slow Keep-Alive",
            "category": "Denial of Service",
            "severity_score": 0.88,
            "action": "flagged"
        }

    # Regula 5: Probe SSH mascat prin fragmentare / latență (Stealth SSH)
    elif dst_port == 22 and duration > 3.0 and fwd_pkts >= 20:
        alert_match = {
            "signature": "ET POLICY Evasive Stealth SSH Probe",
            "category": "Potential Corporate Privacy Violation",
            "severity_score": 0.85,
            "action": "flagged"
        }

    # Verificare unică a rezultatului
    if alert_match:
        return {
            "rule_triggered": True,
            "signature": alert_match["signature"],
            "category": alert_match["category"],
            "score": alert_match["severity_score"],
            "needs_ml": False  # Semnătură clară, nu risipim resurse ML
        }

    # Nicio regulă statică nu s-a declanșat -> trimitem la ML pentru detecție de zero-day
    return {
        "rule_triggered": False,
        "signature": "PASSED_TO_ML",
        "category": "Behavioral Evaluation",
        "score": 0.0,
        "needs_ml": True
    }
