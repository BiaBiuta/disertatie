import os
import json
import joblib
import numpy as np

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
ARTIFACTS_DIR = os.path.join(BASE_DIR, "artifacts")

MODEL_PATH = os.path.join(ARTIFACTS_DIR, "nids_model.joblib")
SCALER_PATH = os.path.join(ARTIFACTS_DIR, "scaler.joblib")
EXPLAINER_PATH = os.path.join(ARTIFACTS_DIR, "shap_explainer.joblib")
FEATURES_PATH = os.path.join(ARTIFACTS_DIR, "selected_features.json")

# Încărcare la nivel de modul (o singură dată în memorie)
_model = None
_scaler = None
_explainer = None
_features = []

def _load_components():
    global _model, _scaler, _explainer, _features
    if _model is None:
        if os.path.exists(MODEL_PATH) and os.path.exists(SCALER_PATH) and os.path.exists(EXPLAINER_PATH):
            _model = joblib.load(MODEL_PATH)
            _scaler = joblib.load(SCALER_PATH)
            _explainer = joblib.load(EXPLAINER_PATH)
            with open(FEATURES_PATH, "r") as f:
                _features = json.load(f).get("features", [])
        else:
            print("[Avertisment] Artefactele ML nu sunt găsite. Rulează train_detector.py!")

def predict_and_explain(flow_dict):
    """
    Evaluează fluxul brut, returnează scorul de risc (0.0 - 1.0)
    și contribuția fiecărei trăsături conform SHAP.
    """
    _load_components()

    if _model is None:
        # Fallback de urgență dacă modelul nu este încă antrenat
        return 0.1, False, {}

    # Mapare din câmpurile fluxului (NetworkFlow / JSON) la numele din dataset
    field_mapping = {
        "Total Fwd Packets": float(flow_dict.get("total_fwd_packets", 0)),
        "Fwd Packet Length Max": float(flow_dict.get("fwd_pkt_len_max", flow_dict.get("fwd_packet_length_max", 0.0))),
        "Flow IAT Mean": float(flow_dict.get("flow_iat_mean", 0.0)),
        "Flow IAT Max": float(flow_dict.get("flow_iat_max", 0.0)),
    }

    # Asigurare ordine trăsături
    row_values = []
    for feat in _features:
        row_values.append(field_mapping.get(feat, 0.0))

    X_raw = np.array([row_values])
    X_scaled = _scaler.transform(X_raw)

    # Inferență XGBoost
    proba = float(_model.predict_proba(X_scaled)[0, 1])
    is_anomaly = proba >= 0.5

    # Calcul TreeSHAP local pentru acest flux
    shap_values = _explainer.shap_values(X_scaled)
    if isinstance(shap_values, list):
        # Dacă returnează listă de clase, luăm clasa 1 (Atac)
        sv = shap_values[1][0]
    elif shap_values.ndim == 2:
        sv = shap_values[0]
    else:
        sv = shap_values

    # Structurăm contribuțiile relative pentru UI
    xai_explanation = {}
    for feat_name, val, s_val in zip(_features, row_values, sv):
        xai_explanation[feat_name] = {
            "value": round(float(val), 2),
            "shap_impact": round(float(s_val), 4),
            "direction": "Pushes towards ATTACK" if s_val > 0 else "Pushes towards BENIGN"
        }

    return round(proba, 4), is_anomaly, xai_explanation