import os
import joblib
import numpy as np
from soc_core.services.rule_engine import evaluate_suricata_rules

print("=== Modul de Evaluare a Rezilienței Adversariale (Evasion Benchmark) ===\n")

# 1. Încărcare bundle ML salvat
bundle = joblib.load("models/calibrated_detector.pkl")
iforest = bundle['iforest']
autoencoder = bundle['autoencoder']
scaler = bundle['scaler']
threshold = bundle['threshold']

# 2. Definire Scenariu de Atac Brut vs. Atac Manipulat Adversarial
attack_scenarios = [
    {
        "name": "1. Atac Volumetric Brut (Fără Camuflaj)",
        "flow": {
            "dst_port": 80,
            "flow_duration": 0.05,
            "total_fwd_packets": 60,
            "total_bwd_packets": 2,
            "flow_bytes_per_sec": 85000.0,
            "flow_packets_per_sec": 300.0
        }
    },
    {
        "name": "2. Atac Adversarial Evaziv (Jitter Latență + Fragmentare - rate scăzute artificial)",
        "flow": {
            "dst_port": 22,  # Țintă SSH bruteforce / scan
            "flow_duration": 4.5,  # Crescută durata pentru a reduce viteza pachetelor
            "total_fwd_packets": 25,  # Redus numărul de pachete per secundă
            "total_bwd_packets": 1,
            "flow_bytes_per_sec": 3500.0,  # Octeți reduși artificial (sub profilul tipic de atac masiv)
            "flow_packets_per_sec": 5.5  # Rata scăzută drastic pentru a păcăli clasificatorul ML
        }
    },
    {
        "name": "3. Slowloris / Low-and-Slow Attack (Conexiuni persistente fără burst volumetric)",
        "flow": {
            "dst_port": 80,
            "flow_duration": 18.0,
            "total_fwd_packets": 12,
            "total_bwd_packets": 4,
            "flow_bytes_per_sec": 950.0,
            "flow_packets_per_sec": 0.8
        }
    }
]

print(f"{'Scenariu Test':<45} | {'Scor ML':<9} | {'ML Alert?':<10} | {'Suricata Alert?':<16} | {'Decizie Hibridă'}")
print("-" * 105)

for scenario in attack_scenarios:
    flow = scenario['flow']

    # Vector caracteristici scalat
    feat = np.array([[
        flow['flow_duration'],
        flow['total_fwd_packets'],
        flow['total_bwd_packets'],
        flow['flow_bytes_per_sec'],
        flow['flow_packets_per_sec']
    ]])
    feat_scaled = scaler.transform(feat)

    # Predicție Ansamblu ML (IForest + Autoencoder)
    score_if = float(iforest.decision_function(feat_scaled)[0])
    norm_if = 1 / (1 + np.exp(-score_if * 2))

    score_ae = float(autoencoder.decision_function(feat_scaled)[0])
    norm_ae = 1 / (1 + np.exp(-score_ae * 2))

    ml_score = round(0.5 * norm_if + 0.5 * norm_ae, 3)
    ml_triggered = ml_score >= threshold

    # Predicție Reguli Suricata
    rule_result = evaluate_suricata_rules(flow)
    rule_triggered = rule_result["rule_triggered"]

    # Fuziune Hibridă
    if rule_triggered:
        final_decision = f"BLOCKED by {rule_result['signature'][:22]}..."
    elif ml_triggered:
        final_decision = f"CAUGHT by PyOD Ensemble (Score: {ml_score})"
    else:
        final_decision = "EVADED (Bypassed both layers)"

    print(
        f"{scenario['name'][:43]:<45} | {ml_score:<9} | {str(ml_triggered):<10} | {str(rule_triggered):<16} | {final_decision}")

print("-" * 105)