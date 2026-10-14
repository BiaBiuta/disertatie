"""
train_detector.py
=================
Antrenează modelele NIDS pe profilurile 'research' (Pareto 5-feat) sau 'baseline'.
Utilizare:
    python train_detector.py --mode research
    python train_detector.py --mode baseline
    python train_detector.py --mode all
"""

import os
import json
import argparse
import time
import joblib
import pandas as pd
from xgboost import XGBClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, roc_auc_score
from sklearn.model_selection import train_test_split

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ARTIFACTS_DIR = os.path.join(BASE_DIR, 'artifacts')
DATASET_PATH = os.path.join(BASE_DIR, 'dataset', 'cicids2017_sample.csv')


def train_single_model(mode='research'):
    print(f"\n=======================================================")
    print(f"  Antrenare Detector NIDS — Profil: {mode.upper()}")
    print(f"=======================================================")

    if mode == 'research':
        feat_file = os.path.join(ARTIFACTS_DIR, 'selected_features_research.json')
        if not os.path.exists(feat_file):
            feat_file = os.path.join(ARTIFACTS_DIR, 'selected_features.json')
        model_out = os.path.join(ARTIFACTS_DIR, 'nids_model_research.joblib')
        scaler_out = os.path.join(ARTIFACTS_DIR, 'scaler_research.joblib')
    else:
        feat_file = os.path.join(ARTIFACTS_DIR, 'selected_features_baseline.json')
        model_out = os.path.join(ARTIFACTS_DIR, 'nids_model_baseline.joblib')
        scaler_out = os.path.join(ARTIFACTS_DIR, 'scaler_baseline.joblib')

    with open(feat_file, 'r', encoding='utf-8-sig') as f:
        data = json.load(f)
        features = data.get('features', data) if isinstance(data, dict) else data

    print(f"-> Număr trăsături utilizate: {len(features)}")
    print(f"-> Trăsături: {features}")

    df = pd.read_csv(DATASET_PATH)
    df.columns = df.columns.str.strip()
    df['Label_Binary'] = (df['Label'] != 'BENIGN').astype(int)

    # Verificăm că toate trăsăturile există în dataset
    missing = [c for c in features if c not in df.columns]
    if missing:
        print(f"⚠️ Atenție, trăsături lipsă în CSV: {missing}")
        features = [c for c in features if c in df.columns]

    X = df[features].fillna(0)
    y = df['Label_Binary']

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    start_t = time.time()
    model = XGBClassifier(
        n_estimators=100,
        max_depth=5,
        learning_rate=0.1,
        eval_metric='logloss',
        random_state=42
    )
    model.fit(X_train_scaled, y_train)
    train_time = time.time() - start_t

    # Latență inferență per sample
    start_inf = time.time()
    y_pred = model.predict(X_test_scaled)
    inf_latency_ms = ((time.time() - start_inf) / len(X_test)) * 1000
    y_prob = model.predict_proba(X_test_scaled)[:, 1]

    print("\n--- Raport Clasificare ---")
    print(classification_report(y_test, y_pred, digits=4))
    print(f"ROC-AUC: {roc_auc_score(y_test, y_prob):.4f}")
    print(f"Latență medie inferență: {inf_latency_ms:.4f} ms / flux")

    joblib.dump(model, model_out)
    joblib.dump(scaler, scaler_out)

    # Copiază ca default dacă e research
    if mode == 'research':
        joblib.dump(model, os.path.join(ARTIFACTS_DIR, 'nids_model.joblib'))
        joblib.dump(scaler, os.path.join(ARTIFACTS_DIR, 'scaler.joblib'))

    print(f"✅ Model salvat cu succes în: {model_out}\n")


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--mode', choices=['research', 'baseline', 'all'], default='all')
    args = parser.parse_args()

    if args.mode == 'all':
        train_single_model('baseline')
        train_single_model('research')
    else:
        train_single_model(args.mode)