import os
import json
import joblib
import numpy as np
import pandas as pd
import xgboost as xgb
import shap
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.metrics import classification_report, roc_auc_score, confusion_matrix

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATASET_PATH = os.path.join(BASE_DIR, "dataset", "cicids2017_sample.csv")
ARTIFACTS_DIR = os.path.join(BASE_DIR, "artifacts")
FEATURES_PATH = os.path.join(ARTIFACTS_DIR, "selected_features.json")

os.makedirs(ARTIFACTS_DIR, exist_ok=True)

print("[1/5] Încărcare dataset și filtrare trăsături optime GA+CPLEX...")
df = pd.read_csv(DATASET_PATH)

# Curatare spatii albe din numele coloanelor
df.columns = df.columns.str.strip()

# Citire trasaturi alese de optimizator
if os.path.exists(FEATURES_PATH):
    with open(FEATURES_PATH, "r") as f:
        meta = json.load(f)
        selected_features = [feat.strip() for feat in meta.get("features", [])]
else:
    # Fallback pe cele 4 trasaturi optime documentate
    selected_features = [
        "Total Fwd Packets",
        "Fwd Packet Length Max",
        "Flow IAT Mean",
        "Flow IAT Max"
    ]

print(f"Trăsături active ({len(selected_features)}): {selected_features}")

# Curățare NaN și valori infinite specifice CIC-IDS2017
df.replace([np.inf, -np.inf], np.nan, inplace=True)
df.dropna(subset=selected_features + ['Label'], inplace=True)

X = df[selected_features]
y_raw = df['Label'].astype(str)

# Clasificare binară: BENIGN vs ATAC (poate fi extinsă ușor la multi-class)
y = (y_raw != 'BENIGN').astype(int)

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.25, random_state=42, stratify=y
)

print("[2/5] Scalare trăsături...")
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

print("[3/5] Antrenare clasificator XGBoost...")
# Folosim hiperparametri calibrați pentru latență redusă și precizie ridicată
model = xgb.XGBClassifier(
    n_estimators=100,
    max_depth=4,
    learning_rate=0.08,
    subsample=0.8,
    colsample_bytree=0.8,
    scale_pos_weight=(len(y_train) - sum(y_train)) / sum(y_train),  # Compensează dezechilibrul claselor
    random_state=42,
    eval_metric="logloss"
)
model.fit(X_train_scaled, y_train)

y_pred = model.predict(X_test_scaled)
y_proba = model.predict_proba(X_test_scaled)[:, 1]

print("\n--- REZULTATE EVALUARE MODEL (TEST SET) ---")
print(classification_report(y_test, y_pred, target_names=["BENIGN", "ATTACK"]))
roc_auc = roc_auc_score(y_test, y_proba)
print(f"ROC-AUC Score: {roc_auc:.4f}")

print("\n[4/5] Inițializare TreeSHAP Explainer...")
# Folosim modelul nativ XGBoost pentru calcul instantaneu
explainer = shap.TreeExplainer(model)

print("[5/5] Salvare artefacte...")
joblib.dump(model, os.path.join(ARTIFACTS_DIR, "nids_model.joblib"))
joblib.dump(scaler, os.path.join(ARTIFACTS_DIR, "scaler.joblib"))
joblib.dump(explainer, os.path.join(ARTIFACTS_DIR, "shap_explainer.joblib"))

# Actualizare selected_features.json
with open(FEATURES_PATH, "w") as f:
    json.dump({
        "features": selected_features,
        "model_type": "XGBoost + TreeSHAP",
        "roc_auc": round(roc_auc, 4),
        "test_samples": len(X_test)
    }, f, indent=4)

print("Antrenare finalizată cu succes! Artefactele sunt salvate în artifacts/.")