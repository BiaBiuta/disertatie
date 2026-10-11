import os
import joblib
import numpy as np

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
MODEL_PATH = os.path.join(BASE_DIR, "models", "calibrated_detector.pkl")

bundle = None
if os.path.exists(MODEL_PATH):
    bundle = joblib.load(MODEL_PATH)

def predict_anomaly(flow_dict: dict) -> tuple[float, bool]:
    global bundle
    if bundle is None:
        if os.path.exists(MODEL_PATH):
            bundle = joblib.load(MODEL_PATH)
        else:
            return 0.0, False

    iforest = bundle['iforest']
    autoencoder = bundle['autoencoder']
    scaler = bundle.get('scaler')
    threshold = bundle['threshold']

    features = np.array([[
        float(flow_dict.get('flow_duration', 0.0)),
        float(flow_dict.get('total_fwd_packets', 0)),
        float(flow_dict.get('total_bwd_packets', 0)),
        float(flow_dict.get('flow_bytes_per_sec', 0.0)),
        float(flow_dict.get('flow_packets_per_sec', 0.0))
    ]])

    try:
        if scaler is not None:
            features = scaler.transform(features)

        # 1. Scor Isolation Forest
        score_if = float(iforest.decision_function(features)[0])
        norm_if = 1 / (1 + np.exp(-score_if * 2))

        # 2. Scor Autoencoder (eroare de reconstrucție)
        score_ae = float(autoencoder.decision_function(features)[0])
        norm_ae = 1 / (1 + np.exp(-score_ae * 2))

        # 3. Fuziune ponderată
        ensemble_score = round(0.5 * norm_if + 0.5 * norm_ae, 3)
        is_above = bool(ensemble_score >= threshold)

        return ensemble_score, is_above
    except Exception as e:
        print(f"Eroare inferență hibridă: {e}")
        return 0.0, False