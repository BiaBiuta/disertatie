"""
experiment_xai_vs_rf.py
=======================
Experiment comparativ pentru contribuția "XAI în buclă": rulează ACELAȘI algoritm
genetic de selecție a trăsăturilor în trei moduri de ghidare a căutării locale și
compară sub-seturile alese, pe mai multe rulări, cu validare statistică.

Moduri comparate:
  - RandomForest (static) : importanță din feature_importances_, fără recalculare
  - SHAP (static)         : importanță SHAP, calculată o singură dată
  - SHAP (dinamic)        : importanță SHAP recalculată periodic pe elită (contribuția)

Pentru fiecare rulare (seed) și fiecare mod:
  1. se rulează GA-ul cu același seed (stocastica identică; diferă DOAR ghidarea),
  2. sub-setul ales este EVALUAT onest: un clasificator antrenat pe acele trăsături,
     iar recall-ul și FPR-ul sunt raportate la pragul SOC (recall maxim cu FPR <= 1%).

Ieșiri în reports/:
  xai_experiment_results.json   - rezultate brute + agregate + teste Wilcoxon
  xai_experiment_table.csv      - tabelul agregat (medie ± std)
  xai_experiment.png            - comparație FPR / nr. trăsături pe moduri

Rulare (din folderul nids_soc_platform):
  python experiment_xai_vs_rf.py                 # config teză (15 rulări, 20 generații)
  python experiment_xai_vs_rf.py --runs 5 --generations 10
  python experiment_xai_vs_rf.py --quick         # verificare rapidă (3 rulări, 6 generații)
"""

import os
import io
import json
import time
import random
import argparse
import contextlib
import warnings

# Avertismentele joblib/sklearn (ex. "sklearn.utils.parallel.delayed...") apar cand
# SHAP cheama RandomForest paralel; sunt inofensive, dar inunda output-ul. Le oprim.
warnings.filterwarnings("ignore")
os.environ.setdefault("PYTHONWARNINGS", "ignore")

import numpy as np
import pandas as pd
from scipy.stats import wilcoxon
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import roc_curve

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from hybrid_genetic_nids import load_data, HybridGeneticFeatureSelector

REPORTS = "reports"
os.makedirs(REPORTS, exist_ok=True)

MODES = {
    "RandomForest (static)": dict(importance_source="rf", shap_period=0),
    "SHAP (static)":         dict(importance_source="shap", shap_period=0),
    "SHAP (dinamic)":        dict(importance_source="shap", shap_period=3),
}
REF_MODE = "SHAP (dinamic)"   # modul de referință pentru testele Wilcoxon


def evaluate_subset(feature_idx, X_tr, y_tr, X_v, y_v, max_fpr=0.01, seed=42):
    """
    Evaluează onest un sub-set de trăsături: antrenează un clasificator pe ele și
    raportează recall-ul la pragul SOC (recall maxim cu FPR <= max_fpr).
    Returnează (recall, fpr) la acel prag.
    """
    if len(feature_idx) == 0:
        return 0.0, 1.0
    clf = RandomForestClassifier(n_estimators=60, max_depth=10, n_jobs=-1,
                                 random_state=seed, class_weight="balanced")
    clf.fit(X_tr[:, feature_idx], y_tr)
    scores = clf.predict_proba(X_v[:, feature_idx])[:, 1]

    fpr, tpr, _ = roc_curve(y_v, scores)
    eligible = np.where(fpr <= max_fpr)[0]
    if len(eligible) > 0:
        i = eligible[-1]           # cel mai mare TPR cu FPR în buget
        return float(tpr[i]), float(fpr[i])
    return float(tpr[0]), float(fpr[0])


def run_one(mode_cfg, feats, X_tr, y_tr, X_v, y_v, seed, generations):
    """O rulare GA într-un mod dat; întoarce (recall, fpr, n_features, timp)."""
    # Stocastica identică între moduri pentru același seed: doar ghidarea diferă.
    random.seed(seed)
    t0 = time.perf_counter()
    # GA-ul este verbose (constructie + run); suprimam toata iesirea in experiment.
    with contextlib.redirect_stdout(io.StringIO()):
        ga = HybridGeneticFeatureSelector(
            feature_names=feats, X_tr=X_tr, y_tr=y_tr, X_v=X_v, y_v=y_v,
            population_size=16, generations=generations, elite_size=2,
            crossover_rate=0.8, mutation_rate=0.08, stagnation_limit=max(3, generations),
            shap_sample=400, shap_temperature=0.5, rng_seed=seed, **mode_cfg)
        best_chrom, _ = ga.run()
    dt = time.perf_counter() - t0

    idx = [i for i, g in enumerate(best_chrom) if g == 1]
    recall, fpr = evaluate_subset(idx, X_tr, y_tr, X_v, y_v)
    return {"recall": round(recall, 4), "fpr": round(fpr, 6),
            "n_features": len(idx), "time_sec": round(dt, 2),
            "guidance": ga.importance_method}


def aggregate(raw):
    """raw[mode] = list de dicturi -> medie±std + Wilcoxon vs modul de referință."""
    agg = {}
    series = {m: {k: [r[k] for r in raw[m]] for k in ("recall", "fpr", "n_features", "time_sec")}
              for m in raw}
    for m in raw:
        rec = np.array(series[m]["recall"]); fpr = np.array(series[m]["fpr"])
        nf = np.array(series[m]["n_features"]); tm = np.array(series[m]["time_sec"])
        e = {
            "recall_mean": round(float(rec.mean()), 4), "recall_std": round(float(rec.std()), 4),
            "fpr_mean_pct": round(float(fpr.mean()) * 100, 4), "fpr_std_pct": round(float(fpr.std()) * 100, 4),
            "n_features_mean": round(float(nf.mean()), 2), "n_features_std": round(float(nf.std()), 2),
            "time_mean_sec": round(float(tm.mean()), 2),
        }
        if m != REF_MODE:
            for metric in ("fpr", "n_features", "recall"):
                try:
                    _, p = wilcoxon(series[REF_MODE][metric], series[m][metric], zero_method="zsplit")
                    e[f"wilcoxon_p_{metric}_vs_ref"] = round(float(p), 5) if p == p else None
                except ValueError:
                    e[f"wilcoxon_p_{metric}_vs_ref"] = None
        agg[m] = e
    return agg


def make_figure(agg, path):
    modes = list(agg.keys())
    fpr = [agg[m]["fpr_mean_pct"] for m in modes]
    fpr_e = [agg[m]["fpr_std_pct"] for m in modes]
    nf = [agg[m]["n_features_mean"] for m in modes]
    nf_e = [agg[m]["n_features_std"] for m in modes]
    colors = ["#2563eb" if "dinamic" in m else "#64748b" for m in modes]

    fig, (a1, a2) = plt.subplots(1, 2, figsize=(11, 4.4), dpi=150)
    x = np.arange(len(modes))
    a1.bar(x, fpr, yerr=fpr_e, color=colors, capsize=4, width=0.6)
    a1.axhline(1.0, color="#dc2626", ls="--", lw=1, label="Buget SOC (1%)")
    a1.set_xticks(x); a1.set_xticklabels(modes, rotation=15, ha="right", fontsize=8)
    a1.set_ylabel("FPR realizat (%)"); a1.set_title("Alarme false (mai mic = mai bine)")
    a1.legend(fontsize=8); a1.spines[["top", "right"]].set_visible(False)

    a2.bar(x, nf, yerr=nf_e, color=colors, capsize=4, width=0.6)
    a2.set_xticks(x); a2.set_xticklabels(modes, rotation=15, ha="right", fontsize=8)
    a2.set_ylabel("Nr. trăsături selectate"); a2.set_title("Cost (mai mic = mai bine)")
    a2.spines[["top", "right"]].set_visible(False)
    fig.suptitle("Ghidarea căutării locale a GA: SHAP dinamic vs static vs RandomForest", fontsize=11)
    fig.tight_layout(); fig.savefig(path); plt.close(fig)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs", type=int, default=15)
    ap.add_argument("--generations", type=int, default=20)
    ap.add_argument("--quick", action="store_true")
    args = ap.parse_args()
    if args.quick:
        args.runs, args.generations = 3, 6

    print("=" * 66)
    print("  EXPERIMENT: XAI în buclă (SHAP) vs RandomForest în GA")
    print(f"  Rulări: {args.runs} | Generații: {args.generations} | Moduri: {len(MODES)}")
    print("=" * 66)

    feats, X_tr, X_v, y_tr, y_v = load_data(verbose=True)
    t_start = time.time()

    raw = {m: [] for m in MODES}
    for run in range(args.runs):
        seed = 100 + run
        for mode, cfg in MODES.items():
            res = run_one(cfg, feats, X_tr, y_tr, X_v, y_v, seed, args.generations)
            raw[mode].append(res)
        line = " | ".join(
            f"{m.split()[0][:4]}:F={raw[m][-1]['fpr']*100:.2f}%,n={raw[m][-1]['n_features']}"
            for m in MODES)
        print(f"  run {run+1:02d}/{args.runs} (seed {seed}): {line}")

    agg = aggregate(raw)
    guidance_note = {m: raw[m][0]["guidance"] for m in MODES}

    with open(os.path.join(REPORTS, "xai_experiment_results.json"), "w") as f:
        json.dump({"runs": args.runs, "generations": args.generations,
                   "guidance_used": guidance_note, "aggregate": agg, "raw": raw}, f, indent=2)
    pd.DataFrame(agg).T.to_csv(os.path.join(REPORTS, "xai_experiment_table.csv"))
    make_figure(agg, os.path.join(REPORTS, "xai_experiment.png"))

    print("\n" + "=" * 66)
    print(f"  TABEL COMPARATIV (medie ± std pe {args.runs} rulări)")
    print("=" * 66)
    hdr = f"{'Mod':<24}{'Recall':<15}{'FPR (%)':<16}{'#feat':<12}{'p(FPR)'}"
    print(hdr); print("-" * len(hdr))
    for m, e in agg.items():
        p = e.get("wilcoxon_p_fpr_vs_ref", "ref")
        print(f"{m:<24}{e['recall_mean']:.3f}±{e['recall_std']:.3f}  "
              f"{e['fpr_mean_pct']:.3f}±{e['fpr_std_pct']:.3f}  "
              f"{e['n_features_mean']:.1f}±{e['n_features_std']:.1f}    {p}")

    print(f"\n[Ghidare efectiv folosită]")
    for m, g in guidance_note.items():
        print(f"  {m:<24}: {g}")
    print(f"\nFinalizat în {time.time()-t_start:.1f}s. Ieșiri în {REPORTS}/")
    print("Interpretare: p < 0.05 la FPR => SHAP-dinamic difera semnificativ de modul")
    print("comparat; pe dataset multi-atac diferenta este de regula mai pronuntata.")


if __name__ == "__main__":
    main()
