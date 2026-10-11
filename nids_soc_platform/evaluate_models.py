import os
import joblib
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score, roc_curve
from sklearn.model_selection import train_test_split
from soc_core.services.rule_engine import evaluate_suricata_rules

print("[1/4] Încărcare dataset și model antrenat...")
df = pd.read_csv("dataset/cicids2017_sample.csv")
df.columns = df.columns.str.strip()

bundle = joblib.load("models/calibrated_detector.pkl")
iforest = bundle['iforest']
autoencoder = bundle['autoencoder']
scaler = bundle['scaler']
threshold = bundle['threshold']
feature_cols = bundle['features']

df['target'] = df['Label'].apply(lambda x: 0 if str(x).upper() == 'BENIGN' else 1)
X = df[feature_cols].values
y = df['target'].values

_, X_test, _, y_test, _, test_df = train_test_split(
    X, y, df, test_size=0.3, random_state=42, stratify=y
)

X_test_scaled = scaler.transform(X_test)

print("[2/4] Evaluare pipeline hibrid pe eșantionul de test...")
y_pred_hybrid = []
scores_hybrid = []

for idx, (_, row) in enumerate(test_df.iterrows()):
    flow_dict = {
        'dst_port': row.get('Destination Port', 80),
        'flow_duration': row.get('Flow Duration', 0.0),
        'total_fwd_packets': row.get('Total Fwd Packets', 0),
        'total_bwd_packets': row.get('Total Backward Packets', 0),
        'flow_bytes_per_sec': row.get('Flow Bytes/s', 0.0),
        'flow_packets_per_sec': row.get('Flow Packets/s', 0.0)
    }

    # 1. Verificare regulă Suricata
    rule_res = evaluate_suricata_rules(flow_dict)

    if not rule_res["needs_ml"]:
        pred = 1
        score = rule_res["score"]
    else:
        # 2. Inspecție ML Ensemble
        sample_scaled = X_test_scaled[idx].reshape(1, -1)
        score_if = float(iforest.decision_function(sample_scaled)[0])
        norm_if = 1 / (1 + np.exp(-score_if * 2))

        score_ae = float(autoencoder.decision_function(sample_scaled)[0])
        norm_ae = 1 / (1 + np.exp(-score_ae * 2))

        score = 0.5 * norm_if + 0.5 * norm_ae
        pred = 1 if score >= threshold else 0

    y_pred_hybrid.append(pred)
    scores_hybrid.append(score)

print("\n[3/4] Raport de Clasificare NIDS Hibrid:")
print(classification_report(y_test, y_pred_hybrid, target_names=['BENIGN', 'ATTACK'], digits=4))

cm = confusion_matrix(y_test, y_pred_hybrid)
tn, fp, fn, tp = cm.ravel()
fpr = fp / (fp + tn)
tpr = tp / (tp + fn)

print(f" -> False Positive Rate (FPR): {fpr * 100:.2f}%")
print(f" -> Detection Rate (Recall / TPR): {tpr * 100:.2f}%")
print(f" -> Alarme false înregistrate: {fp} dintr-un total de {tn + fp} fluxuri benigne")

print("\n[4/4] Generare grafic ROC pentru disertație...")
os.makedirs("reports", exist_ok=True)
fpr_vals, tpr_vals, _ = roc_curve(y_test, scores_hybrid)
roc_auc = roc_auc_score(y_test, scores_hybrid)

plt.figure(figsize=(8, 6))
plt.plot(fpr_vals, tpr_vals, color='#2563eb', lw=2, label=f'ROC Pipeline Hibrid (AUC = {roc_auc:.4f})')
plt.plot([0, 1], [0, 1], color='#94a3b8', lw=1, linestyle='--')
plt.axvline(x=0.01, color='#dc2626', linestyle=':', label='Target SOC (FPR <= 1%)')
plt.xlim([-0.01, 1.0])
plt.ylim([0.0, 1.05])
plt.xlabel('False Positive Rate (FPR)')
plt.ylabel('True Positive Rate (TPR / Recall)')
plt.title('Curba ROC - Evaluare Detecție Hibridă (CIC-IDS2017)')
plt.legend(loc="lower right")
plt.grid(alpha=0.3)
plt.tight_layout()
chart_path = "reports/roc_curve_soc.png"
plt.savefig(chart_path, dpi=300)
print(f"Grafic salvat în: {chart_path}")