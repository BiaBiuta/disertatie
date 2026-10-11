import os
import json
import joblib
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score, roc_curve

print("[1/3] Incarcare artefacte optime GA + CPLEX...")
artifacts_dir = "artifacts"
model = joblib.load(os.path.join(artifacts_dir, "nids_model.joblib"))
scaler = joblib.load(os.path.join(artifacts_dir, "scaler.joblib"))

with open(os.path.join(artifacts_dir, "selected_features.json"), "r", encoding="utf-8") as f:
    meta = json.load(f)
selected_features = meta["features"]

df = pd.read_csv("dataset/cicids2017_sample.csv", low_memory=False)
df.columns = df.columns.str.strip()
df = df.replace([np.inf, -np.inf], np.nan).dropna()

label_col = [c for c in df.columns if 'label' in c.lower()][0]
y_true = df[label_col].apply(lambda x: 0 if str(x).strip().upper() == 'BENIGN' else 1).values
X_raw = df[selected_features].values

print("[2/3] Scalare si inferenta...")
X_scaled = scaler.transform(X_raw)
y_pred = model.predict(X_scaled)
y_prob = model.predict_proba(X_scaled)[:, 1]

print("\nRaport Clasificare Model Optimizat:")
print(classification_report(y_true, y_pred, target_names=['BENIGN', 'ATTACK'], digits=4))

cm = confusion_matrix(y_true, y_pred)
tn, fp, fn, tp = cm.ravel()
print(f" -> False Positive Rate (FPR): {(fp / (fp + tn)) * 100:.4f}%")
print(f" -> Recall (TPR): {(tp / (tp + fn)) * 100:.2f}%")
print(f" -> Alarme false: {fp} / {tn + fp} benigne")

print("\n[3/3] Generare figuri pentru UI si teza...")
os.makedirs("reports", exist_ok=True)
os.makedirs("soc_core/static/figures", exist_ok=True)

# 1. Matrice de Confuzie
plt.figure(figsize=(6, 5), dpi=300)
plt.imshow(cm, interpolation='nearest', cmap=plt.cm.Blues)
plt.title('Matrice de Confuzie (Model Hibrid GA + CPLEX)')
plt.colorbar()
tick_marks = np.arange(2)
plt.xticks(tick_marks, ['BENIGN', 'ATTACK'])
plt.yticks(tick_marks, ['BENIGN', 'ATTACK'])

thresh = cm.max() / 2.
for i in range(cm.shape[0]):
    for j in range(cm.shape[1]):
        plt.text(j, i, format(cm[i, j], 'd'),
                 horizontalalignment="center",
                 color="white" if cm[i, j] > thresh else "black",
                 fontweight="bold")

plt.ylabel('Eticheta Reala')
plt.xlabel('Predictie')
plt.tight_layout()
plt.savefig("reports/confusion_matrix.png")
plt.savefig("soc_core/static/figures/confusion_matrix.png")
plt.close()

# 2. Curba ROC
fpr_vals, tpr_vals, _ = roc_curve(y_true, y_prob)
roc_auc = roc_auc_score(y_true, y_prob)

plt.figure(figsize=(7, 5), dpi=300)
plt.plot(fpr_vals, tpr_vals, color='#0284c7', lw=2.2, label=f'Model Calibrat (AUC = {roc_auc:.4f})')
plt.plot([0, 1], [0, 1], color='#94a3b8', lw=1, linestyle='--')
plt.axvline(x=0.0005, color='#dc2626', linestyle=':', label='Target SOC (FPR <= 0.05%)')
plt.xlim([-0.005, 0.05])  # Focus pe zona relevanta de low-FPR
plt.ylim([0.90, 1.01])
plt.xlabel('False Positive Rate (FPR)')
plt.ylabel('True Positive Rate (Recall)')
plt.title('Curba ROC (Low-FPR Regime)')
plt.legend(loc="lower right")
plt.grid(alpha=0.3)
plt.tight_layout()
plt.savefig("reports/roc_curve_soc.png")
plt.savefig("soc_core/static/figures/roc_curve_soc.png")
plt.close()

print("[OK] Figurile au fost actualizate.")