"""
optimize_features.py  —  Punctul de intrare al modulului de cercetare.
=====================================================================
Selecție optimă de trăsături NIDS cu NSGA-II (multi-obiectiv) peste un split
anti-leakage, și scrierea rezultatului în formatul pe care îl consumă restul
platformei (artifacts/selected_features.json).

Acest modul este NEINVAZIV: nu modifică niciun fișier existent al platformei
în afară de artifacts/selected_features.json, pe care îl actualizează exact cu
cheia "features" așteptată de train_detector.py.

Flux:
    1. Încarcă dataset/cicids2017_sample.csv (același folosit de platformă).
    2. Construiește split grouped anti-leakage pe Destination Port.
    3. Rulează NSGA-II -> frontieră Pareto (recall, FPR, nr. trăsături).
    4. Alege soluția recomandată: FPR <= buget SOC, recall maxim, apoi cele mai
       puține trăsături.
    5. Scrie:
         - artifacts/selected_features.json   (consumat de train_detector.py)
         - research/outputs/pareto_front.json  (frontiera completă, pentru teză)
         - research/outputs/selection_summary.json

Rulare (din folderul nids_soc_platform):
    python research/optimize_features.py
    python research/optimize_features.py --max-fpr 0.01 --max-features 6 --generations 20

Apoi, pipeline-ul existent folosește direct noile trăsături:
    python train_detector.py
"""

import os
import sys
import json
import time
import argparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from data_split import (load_dataset, get_candidate_features, diagnose_leakage,
                        make_grouped_split)
from feature_selection import NSGA2FeatureSelector, evaluate_subset


REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # .../nids_soc_platform
DATASET = os.path.join(REPO, "dataset", "cicids2017_sample.csv")
ARTIFACTS = os.path.join(REPO, "artifacts")
FEATURES_JSON = os.path.join(ARTIFACTS, "selected_features.json")
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "outputs")


def parse_args():
    p = argparse.ArgumentParser(description="Selecție trăsături NIDS cu NSGA-II.")
    p.add_argument("--dataset", default=DATASET)
    p.add_argument("--max-fpr", type=float, default=0.01, help="buget SOC pentru FPR")
    p.add_argument("--max-features", type=int, default=6)
    p.add_argument("--min-features", type=int, default=3,
                   help="minim de trăsături (robustețe; evită soluții cu 1 trăsătură)")
    p.add_argument("--pop-size", type=int, default=30)
    p.add_argument("--generations", type=int, default=20)
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--no-write-artifact", action="store_true",
                   help="nu suprascrie artifacts/selected_features.json")
    return p.parse_args()


def main():
    args = parse_args()
    os.makedirs(OUT, exist_ok=True)
    os.makedirs(ARTIFACTS, exist_ok=True)
    t0 = time.time()

    print("=" * 68)
    print("  SELECȚIE TRĂSĂTURI NIDS — NSGA-II multi-obiectiv (modul research)")
    print("=" * 68)

    df = load_dataset(args.dataset)
    feats = get_candidate_features(df)
    print(f"Dataset: {len(df)} fluxuri | rată atac: {df['target'].mean():.3f}")
    print(f"Trăsături candidate (fără leakage): {len(feats)}")

    # diagnoză leakage pentru teză
    diagnose_leakage(df, feats, out_path=os.path.join(OUT, "leakage_report.json"))

    # split anti-leakage
    Xtr, Xte, ytr, yte, info = make_grouped_split(df, feats, seed=args.seed)
    print(f"Split grouped: train={len(ytr)} test={len(yte)} "
          f"overlap_grupuri={info['overlap_groups']} (trebuie 0)")

    # NSGA-II
    print(f"\nRulare NSGA-II (pop={args.pop_size}, gen={args.generations}, "
          f"max_feat={args.max_features}, buget FPR={args.max_fpr*100:.0f}%)...")
    nsga = NSGA2FeatureSelector(
        feats, Xtr, ytr, Xte, yte,
        pop_size=args.pop_size, generations=args.generations,
        max_features=args.max_features, min_features=args.min_features,
        max_fpr=args.max_fpr,
        eval_seed=args.seed, rng_seed=args.seed, eval_subsample=8000)
    pareto = nsga.run(verbose=True)

    # re-evaluare onestă cu clasificatorul complet
    for s in pareto:
        m = evaluate_subset(s["chromosome"], Xtr, ytr, Xte, yte,
                            scaler=True, seed=args.seed, max_fpr=args.max_fpr)
        s["recall"], s["fpr"] = m["recall"], m["fpr"]

    with open(os.path.join(OUT, "pareto_front.json"), "w") as f:
        json.dump(pareto, f, indent=2)

    # soluția recomandată
    feasible = [s for s in pareto if s["fpr"] <= args.max_fpr] or pareto
    best = max(feasible, key=lambda s: (s["recall"], -s["fpr"], -s["n_features"]))

    print("\nFrontiera Pareto (soluții non-dominate):")
    for s in pareto:
        mark = "  <== RECOMANDATĂ" if s is best else ""
        print(f"  recall={s['recall']:.4f} FPR={s['fpr']*100:.3f}% "
              f"n={s['n_features']} {s['features']}{mark}")

    summary = {
        "method": "NSGA-II (multi-obiectiv) pe split anti-leakage",
        "max_fpr_budget": args.max_fpr,
        "selected_features": best["features"],
        "selected_recall": best["recall"],
        "selected_fpr": best["fpr"],
        "selected_n_features": best["n_features"],
        "pareto_size": len(pareto),
        "execution_time_sec": round(time.time() - t0, 2),
    }
    with open(os.path.join(OUT, "selection_summary.json"), "w") as f:
        json.dump(summary, f, indent=2)

    # scrie artefactul consumat de train_detector.py (format compatibil)
    if not args.no_write_artifact:
        payload = {
            "features": best["features"],
            "model_type": "selected_by_NSGA-II",
            "selection_method": "NSGA-II multi-objective (anti-leakage grouped split)",
            "soc_fpr_budget": args.max_fpr,
            "validation_recall": best["recall"],
            "validation_fpr": best["fpr"],
        }
        with open(FEATURES_JSON, "w") as f:
            json.dump(payload, f, indent=4)
        print(f"\n[OK] Actualizat {os.path.relpath(FEATURES_JSON, REPO)} cu "
              f"{len(best['features'])} trăsături.")
        print("     Rulează acum:  python train_detector.py")
    else:
        print("\n[info] --no-write-artifact: nu s-a modificat selected_features.json")

    print(f"\nFinalizat în {summary['execution_time_sec']}s. "
          f"Detalii în research/outputs/.")


if __name__ == "__main__":
    main()
