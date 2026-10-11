import os
import joblib
import pandas as pd
import numpy as np
from pyod.models.iforest import IForest
from pyod.models.auto_encoder import AutoEncoder
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from soc_core.services.threshold_tuner import find_soc_optimal_threshold

print("[1/5] Încărcare dataset...")
df = pd.read_csv("dataset/cicids2017_sample.csv")
df.columns = df.columns.str.strip()

feature_cols = [
    'Flow Duration',
    'Total Fwd Packets',
    'Total Backward Packets',
    'Flow Bytes/s',
    'Flow Packets/s'
]

df['target'] = df['Label'].apply(lambda x: 0 if str(x).upper() == 'BENIGN' else 1)

X = df[feature_cols].values
y = df['target'].values

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42, stratify=y)
X_train_benign = X_train[y_train == 0]

print("[2/5] Scalare date cu StandardScaler...")
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train_benign)
X_test_scaled = scaler.transform(X_test)

print("[3/5] Antrenare Model 1: Isolation Forest...")
iforest_model = IForest(contamination=0.01, random_state=42)
iforest_model.fit(X_train_scaled)

print("[4/5] Antrenare Model 2: PyTorch Deep Autoencoder...")
# Arhitectură simetrică: 5 intrări -> 3 -> 2 -> 3 -> 5 ieșiri
autoencoder_model = AutoEncoder(
    hidden_neuron_list=[3, 2, 3],
    epoch_num=25,
    batch_size=64,
    contamination=0.01,
    verbose=0
)
autoencoder_model.fit(X_train_scaled)
print("[5/5] Calibrare prag SOC bazat pe decizie de ansamblu...")
scores_iforest = iforest_model.decision_function(X_test_scaled)
scores_ae = autoencoder_model.decision_function(X_test_scaled)

# Normalizare scoruri brute pentru combinare
norm_iforest = (scores_iforest - scores_iforest.min()) / (scores_iforest.max() - scores_iforest.min() + 1e-6)
norm_ae = (scores_ae - scores_ae.min()) / (scores_ae.max() - scores_ae.min() + 1e-6)

# Ansamblu ponderat (50% arbori, 50% rețea neuronală)
ensemble_scores = 0.5 * norm_iforest + 0.5 * norm_ae

tune_results = find_soc_optimal_threshold(y_test, ensemble_scores, target_fpr=0.01)

print(f" -> Prag ansamblu: {tune_results['optimal_threshold']:.4f}")
print(f" -> FPR: {tune_results['achieved_fpr']}% | TPR: {tune_results['achieved_tpr']}%")

os.makedirs("models", exist_ok=True)
joblib.dump({
    'iforest': iforest_model,
    'autoencoder': autoencoder_model,
    'scaler': scaler,
    'features': feature_cols,
    'threshold': tune_results['optimal_threshold']
}, "models/calibrated_detector.pkl")

print("Ansamblul IForest + Autoencoder a fost salvat cu succes în models/calibrated_detector.pkl")