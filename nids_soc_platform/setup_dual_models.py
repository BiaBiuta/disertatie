"""
setup_dual_models.py
====================
Generează TOATE artefactele de care are nevoie UI-ul cu comutare de model
(research vs baseline). Rezolvă două simptome:
  - "nu comută între modele"  -> creează fișierele per-mod lipsă
  - "metricile/tabelele nu se populează" -> scrie reports/model_comparison.json

Ce produce (în artifacts/ și reports/):
  artifacts/selected_features_research.json   (trăsături optime NSGA-II, dacă e disponibil modulul research; altfel fallback)
  artifacts/selected_features_baseline.json   (set clasic, mai larg, pentru contrast)
  artifacts/nids_model_research.joblib  + scaler_research.joblib
  artifacts/nids_model_baseline.joblib  + scaler_baseline.joblib
  artifacts/nids_model.joblib + scaler.joblib + selected_features.json  (copie a profilului research = implicit)
  artifacts/active_model_config.json          ({"active_mode": "research"})
  reports/model_comparison.json               ({"research": {...}, "baseline": {...}})

Clasificator: XGBoost dacă e instalat (ca în train_detector.py), altfel RandomForest
(pentru a putea rula fără xgboost). Detectorul le încarcă identic (joblib + predict_proba).

Rulare (din folderul nids_soc_platform):
    python setup_dual_models.py
    python setup_dual_models.py --nsga-generations 20   # selecție research mai amplă
"""

import os
import sys
import json
import time
import argparse
import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import roc_auc_score, confusion_matrix, recall_score

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ARTIFACTS_DIR = os.path.join(BASE_DIR, "artifacts")
REPORTS_DIR = os.path.join(BASE_DIR, "reports")
DATASET_PATH = os.path.join(BASE_DIR, "dataset", "cicids2017_sample.csv")
RESEARCH_DIR = os.path.join(BASE_DIR, "research")

os.makedirs(ARTIFACTS_DIR, exist_ok=True)
os.makedirs(REPORTS_DIR, exist_ok=True)


# --- clasificator: xgboost dacă există, altfel RandomForest -------------------
def build_model():
    try:
        from xgboost import XGBClassifier
        return XGBClassifier(n_estimators=100, max_depth=5, learning_rate=0.1,
                             eval_metric="logloss", random_state=42), "XGBoost"
    except Exception:
        from sklearn.ensemble import RandomForestClassifier
        return RandomForestClassifier(n_estimators=120, max_depth=12, n_jobs=-1,
                                      random_state=42, class_weight="balanced"), "RandomForest"


# --- seturi de trăsături ------------------------------------------------------
def research_features(df, generations):
    """Trăsături optime NSGA-II (modul research). Fallback pe setul documentat."""
    fallback = ["Total Fwd Packets", "Fwd Packet Length Max", "Flow IAT Mean", "Flow IAT Max"]
    try:
        sys.path.insert(0, RESEARCH_DIR)
        from data_split import load_dataset, get_candidate_features, make_grouped_split
        from feature_selection import NSGA2FeatureSelector, evaluate_subset
        d = load_dataset(DATASET_PATH)
        feats = get_candidate_features(d)
        Xtr, Xte, ytr, yte, _ = make_grouped_split(d, feats, seed=42)
        nsga = NSGA2FeatureSelector(feats, Xtr, ytr, Xte, yte, pop_size=30,
                                    generations=generations, min_features=3,
                                    max_features=6, max_fpr=0.01, eval_seed=42,
                                    rng_seed=42, eval_subsample=8000)
        pareto = nsga.run()
        for s in pareto:
            m = evaluate_subset(s["chromosome"], Xtr, ytr, Xte, yte, scaler=True, seed=42)
            s["recall"], s["fpr"] = m["recall"], m["fpr"]
        feasible = [s for s in pareto if s["fpr"] <= 0.01] or pareto
        best = max(feasible, key=lambda s: (s["recall"], -s["fpr"], -s["n_features"]))
        chosen = [c for c in best["features"] if c in df.columns]
        if len(chosen) >= 2:
            print(f"   [research] NSGA-II a ales {len(chosen)} trăsături: {chosen}")
            return chosen
    except Exception as e:
        print(f"   [research] NSGA-II indisponibil ({e}); folosesc setul documentat.")
    return [c for c in fallback if c in df.columns]


def baseline_features(df):
    """Set 'baseline' clasic, mai larg, de trăsături volumetrice standard IDS."""
    candidate = [
        "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
        "Flow Bytes/s", "Flow Packets/s", "Fwd Packet Length Max",
        "Bwd Packet Length Max", "SYN Flag Count",
    ]
    present = [c for c in candidate if c in df.columns]
    return present or [c for c in df.columns if c not in ("Label",)][:8]


# --- antrenare + metrici ------------------------------------------------------
def train_and_eval(df, features, mode):
    features = [c for c in features if c in df.columns]
    X = df[features].replace([np.inf, -np.inf], np.nan).fillna(0.0)
    y = (df["Label"].astype(str).str.upper() != "BENIGN").astype(int)

    X_tr, X_te, y_tr, y_te = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y)

    scaler = StandardScaler().fit(X_tr)
    X_tr_s, X_te_s = scaler.transform(X_tr), scaler.transform(X_te)

    model, algo = build_model()
    model.fit(X_tr_s, y_tr)

    t0 = time.time()
    y_pred = model.predict(X_te_s)
    latency_ms = round((time.time() - t0) / max(len(X_te), 1) * 1000, 4)
    y_prob = model.predict_proba(X_te_s)[:, 1]

    tn, fp, fn, tp = confusion_matrix(y_te, y_pred).ravel()
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    recall = recall_score(y_te, y_pred)
    acc = (tp + tn) / (tp + tn + fp + fn)
    auc = roc_auc_score(y_te, y_prob)

    # salvare artefacte
    import joblib
    m_out = os.path.join(ARTIFACTS_DIR, f"nids_model_{mode}.joblib")
    s_out = os.path.join(ARTIFACTS_DIR, f"scaler_{mode}.joblib")
    f_out = os.path.join(ARTIFACTS_DIR, f"selected_features_{mode}.json")
    joblib.dump(model, m_out)
    joblib.dump(scaler, s_out)
    with open(f_out, "w", encoding="utf-8") as f:
        json.dump({"features": features, "mode": mode, "algo": algo}, f, indent=2)

    metrics = {
        "algo": algo,
        "n_features": len(features),
        "features": features,
        "accuracy": round(float(acc) * 100, 2),
        "recall": round(float(recall) * 100, 2),
        "fpr": round(float(fpr) * 100, 4),
        "roc_auc": round(float(auc), 4),
        "latency_ms": latency_ms,
    }
    print(f"   [{mode}] {algo} | feat={len(features)} | recall={metrics['recall']}% | "
          f"FPR={metrics['fpr']}% | AUC={metrics['roc_auc']} | lat={latency_ms}ms")
    return metrics


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--nsga-generations", type=int, default=15)
    ap.add_argument("--default-mode", choices=["research", "baseline"], default="research")
    args = ap.parse_args()

    print("=" * 64)
    print("  SETUP DUAL-MODEL (research vs baseline) + comparison")
    print("=" * 64)

    df = pd.read_csv(DATASET_PATH)
    df.columns = df.columns.str.strip()
    print(f"Dataset: {len(df)} fluxuri")

    r_feats = research_features(df, args.nsga_generations)
    b_feats = baseline_features(df)
    print(f"Baseline features ({len(b_feats)}): {b_feats}")

    comparison = {}
    comparison["research"] = train_and_eval(df, r_feats, "research")
    comparison["baseline"] = train_and_eval(df, b_feats, "baseline")

    # profilul implicit = copie în artefactele generice (nids_model.joblib etc.)
    import joblib, shutil
    dm = args.default_mode
    shutil.copy(os.path.join(ARTIFACTS_DIR, f"nids_model_{dm}.joblib"),
                os.path.join(ARTIFACTS_DIR, "nids_model.joblib"))
    shutil.copy(os.path.join(ARTIFACTS_DIR, f"scaler_{dm}.joblib"),
                os.path.join(ARTIFACTS_DIR, "scaler.joblib"))
    with open(os.path.join(ARTIFACTS_DIR, f"selected_features_{dm}.json")) as f:
        default_feats = json.load(f)
    with open(os.path.join(ARTIFACTS_DIR, "selected_features.json"), "w") as f:
        json.dump(default_feats, f, indent=2)

    # config model activ
    with open(os.path.join(ARTIFACTS_DIR, "active_model_config.json"), "w") as f:
        json.dump({"active_mode": dm}, f, indent=2)

    # tabel de comparație citit de UI
    with open(os.path.join(REPORTS_DIR, "model_comparison.json"), "w") as f:
        json.dump(comparison, f, indent=2)

    print("\n[OK] Artefacte generate:")
    for name in ["nids_model_research.joblib", "nids_model_baseline.joblib",
                 "selected_features_research.json", "selected_features_baseline.json",
                 "active_model_config.json"]:
        print(f"   artifacts/{name}")
    print("   reports/model_comparison.json")
    print(f"\nProfil implicit: {dm.upper()}. Comutarea din UI funcționează acum.")


if __name__ == "__main__":
    main()
