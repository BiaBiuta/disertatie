import os
import json
import joblib
import numpy as np
from django.conf import settings

# Folosim BASE_DIR direct din setările Django pentru rădăcina proiectului
ARTIFACTS_DIR = os.path.join(settings.BASE_DIR, "artifacts")

MODEL_PATH = os.path.join(ARTIFACTS_DIR, "nids_model.joblib")
SCALER_PATH = os.path.join(ARTIFACTS_DIR, "scaler.joblib")
META_PATH = os.path.join(ARTIFACTS_DIR, "selected_features.json")

# Încărcare tolerantă la erori
model = None
scaler = None
SELECTED_FEATURES = []

if os.path.exists(MODEL_PATH):
    model = joblib.load(MODEL_PATH)

if os.path.exists(SCALER_PATH):
    scaler = joblib.load(SCALER_PATH)

if os.path.exists(META_PATH):
    with open(META_PATH, "r") as f:
        meta = json.load(f)
    SELECTED_FEATURES = meta.get("features", [])
else:
    print(f"[AVERTISMENT] Fișierul de metadate nu a fost găsit la: {META_PATH}")


def predict_anomaly(flow_data: dict):
    """
    Evaluează fluxul live folosind cele 4 trăsături optime selectate de GA + CPLEX.
    """
    if model is None or scaler is None or not SELECTED_FEATURES:
        return 0.0, False

    feature_map = {
        "Total Fwd Packets": float(flow_data.get("total_fwd_packets", 0)),
        "Fwd Packet Length Max": float(flow_data.get("fwd_pkt_len_max", flow_data.get("flow_bytes_per_sec", 0) / 100)),
        "Flow IAT Mean": float(flow_data.get("flow_iat_mean", flow_data.get("flow_duration", 0) / 2)),
        "Flow IAT Max": float(flow_data.get("flow_iat_max", flow_data.get("flow_duration", 0)))
    }

    vector = np.array([[feature_map.get(feat, 0.0) for feat in SELECTED_FEATURES]])
    vector_scaled = scaler.transform(vector)

    prob = float(model.predict_proba(vector_scaled)[0, 1])
    is_anomaly = prob >= 0.5

    return round(prob, 3), is_anomaly