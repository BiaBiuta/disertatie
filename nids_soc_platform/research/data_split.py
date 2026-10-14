"""
data_split.py
=============
Repararea problemei de data leakage / separabilitate trivială din pipeline-ul NIDS.

Problema identificată (vezi raportul de diagnoză generat de diagnose_leakage()):
  - Split random pe un dataset mono-atac (doar PortScan) => clasele sunt trivial
    separabile, ROC-AUC ~ 1.0, care NU reflectă generalizarea.
  - 'Destination Port' memorează porturile vizitate (scanarea atinge porturi rare,
    traficul benign se concentrează pe 53/443/80) => leakage de identitate.

Soluția:
  1. GroupShuffleSplit pe grupuri de (Destination Port) astfel încât aceleași porturi
     NU apar simultan în train și test. Modelul e forțat să învețe comportament, nu
     să memoreze porturi. Aceasta este o estimare pesimistă, onestă, a generalizării.
  2. Excluderea explicită a coloanelor cu leakage de identitate din spațiul de
     trăsături candidate (Destination Port rămâne pentru grupare, nu ca feature).
  3. Raport de diagnoză (single-feature AUC) salvat pentru teză.

Autor: contribuție disertație (pipeline refăcut).
"""

import json
import numpy as np
import pandas as pd
from sklearn.model_selection import GroupShuffleSplit, StratifiedShuffleSplit
from sklearn.metrics import roc_auc_score


# Coloane excluse din spațiul de trăsături: identificatori / leakage de identitate.
# 'Destination Port' e folosit DOAR pentru grupare, nu ca trăsătură de învățare.
LEAKAGE_COLUMNS = {
    "Destination Port",   # memorează porturile scanate (leakage de identitate)
    "Label",
    "target",
}

GROUP_COLUMN = "Destination Port"


def load_dataset(csv_path):
    """Încarcă CIC-IDS2017, curăță numele coloanelor, construiește ținta binară."""
    df = pd.read_csv(csv_path, low_memory=False)
    df.columns = df.columns.str.strip()
    df = df.replace([np.inf, -np.inf], np.nan)

    if "Label" not in df.columns:
        raise ValueError("Coloana 'Label' lipsește din dataset.")

    df["target"] = (df["Label"].astype(str).str.upper() != "BENIGN").astype(int)
    return df


def get_candidate_features(df, max_features=None):
    """
    Returnează lista trăsăturilor candidate numerice, excluzând coloanele cu leakage.
    Elimină și coloanele constante (varianță zero) care nu aduc informație.
    """
    numeric = df.select_dtypes(include=[np.number]).columns.tolist()
    candidates = [c for c in numeric if c not in LEAKAGE_COLUMNS]

    # Elimină coloane complet constante sau aproape goale
    usable = []
    for c in candidates:
        col = df[c]
        if col.notna().sum() < 100:
            continue
        if col.nunique(dropna=True) <= 1:
            continue
        usable.append(c)

    if max_features is not None:
        usable = usable[:max_features]
    return usable


def diagnose_leakage(df, features, out_path=None):
    """
    Pentru fiecare trăsătură, calculează AUC-ul univariat vs. țintă.
    |AUC - 0.5| ~ 0.5 => trăsătura e un separator aproape perfect (potențial leakage
    sau separabilitate trivială pe acest eșantion).
    """
    report = []
    sub = df[features + ["target"]].dropna()
    y = sub["target"].values
    for f in features:
        try:
            auc = roc_auc_score(y, sub[f].values)
        except Exception:
            auc = float("nan")
        # scor de separabilitate simetric în [0, 0.5]
        sep = abs(auc - 0.5) if auc == auc else 0.0
        report.append({
            "feature": f,
            "univariate_auc": round(float(auc), 4) if auc == auc else None,
            "separability": round(float(sep), 4),
            "near_perfect_separator": bool(sep > 0.45),
        })
    report.sort(key=lambda r: r["separability"], reverse=True)

    if out_path:
        with open(out_path, "w") as fh:
            json.dump(report, fh, indent=2)
    return report


def make_grouped_split(df, features, test_size=0.3, seed=42):
    """
    Split anti-leakage: grupuri pe Destination Port.
    Garantează că niciun port din test nu apare în train.

    Returnează: X_train, X_test, y_train, y_test (numpy), plus indicii.
    """
    sub = df.dropna(subset=features + ["target", GROUP_COLUMN]).copy()
    X = sub[features].values
    y = sub["target"].values
    groups = sub[GROUP_COLUMN].values

    gss = GroupShuffleSplit(n_splits=1, test_size=test_size, random_state=seed)
    train_idx, test_idx = next(gss.split(X, y, groups))

    return (
        X[train_idx], X[test_idx],
        y[train_idx], y[test_idx],
        {"train_idx": train_idx, "test_idx": test_idx,
         "train_groups": int(len(set(groups[train_idx]))),
         "test_groups": int(len(set(groups[test_idx]))),
         "overlap_groups": int(len(set(groups[train_idx]) & set(groups[test_idx])))}
    )


def make_random_split(df, features, test_size=0.3, seed=42):
    """
    Split random stratificat (metoda ORIGINALĂ, cu leakage) — păstrat pentru
    comparație directă în teză: arată diferența dintre AUC-ul umflat și cel onest.
    """
    sub = df.dropna(subset=features + ["target"]).copy()
    X = sub[features].values
    y = sub["target"].values
    sss = StratifiedShuffleSplit(n_splits=1, test_size=test_size, random_state=seed)
    train_idx, test_idx = next(sss.split(X, y))
    return X[train_idx], X[test_idx], y[train_idx], y[test_idx]


if __name__ == "__main__":
    import sys, os
    _default = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                            "dataset", "cicids2017_sample.csv")
    path = sys.argv[1] if len(sys.argv) > 1 else _default
    df = load_dataset(path)
    feats = get_candidate_features(df)
    print(f"Dataset: {len(df)} rânduri | rată atac: {df['target'].mean():.3f}")
    print(f"Trăsături candidate (fără leakage): {len(feats)}")

    rep = diagnose_leakage(df, feats, out_path="research/outputs/leakage_report.json")
    print("\nTop 8 separatoare univariate (posibil separabilitate trivială):")
    for r in rep[:8]:
        flag = "  <== near-perfect" if r["near_perfect_separator"] else ""
        print(f"  {r['feature']:30s} AUC={r['univariate_auc']}  sep={r['separability']}{flag}")

    Xtr, Xte, ytr, yte, info = make_grouped_split(df, feats)
    print(f"\nSplit grouped pe '{GROUP_COLUMN}':")
    print(f"  train={len(ytr)} ({ytr.mean():.3f} atac) | test={len(yte)} ({yte.mean():.3f} atac)")
    print(f"  grupuri train={info['train_groups']} | test={info['test_groups']} | "
          f"overlap={info['overlap_groups']} (trebuie 0)")
