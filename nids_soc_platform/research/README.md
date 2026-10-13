# Modul `research/` — Selecție optimă de trăsături (contribuția originală)

Modul **neinvaziv** adăugat platformei NIDS-SOC. Rezolvă trei probleme ale
pipeline-ului original de selecție a trăsăturilor și se leagă de codul existent
fără a-l modifica.

## Ce rezolvă
1. **Data leakage** — split *grouped* pe `Destination Port` (zero overlap train/test)
   + excluderea coloanelor de identitate. ROC-AUC devine onest, nu umflat la 1.0.
2. **Lipsa validării** — baseline-uri (All / Mutual Info / RFE) comparate pe multiple
   rulări, cu medie ± std și test Wilcoxon (vezi scriptul de experiment din pachetul
   de disertație).
3. **Optimizare mono-obiectiv ad-hoc** — înlocuită cu **NSGA-II** multi-obiectiv
   (recall vs. FPR vs. nr. trăsături) → frontieră Pareto.

## Fișiere
- `data_split.py`         — încărcare dataset, diagnoză leakage, split anti-leakage.
- `feature_selection.py`  — baseline-uri + NSGA-II implementat de la zero.
- `optimize_features.py`  — **punctul de intrare**: rulează NSGA-II și scrie artefactul.
- `outputs/`              — rezultate generate (pareto_front.json, leakage_report.json, …).

## Cum se leagă de platformă
`optimize_features.py` scrie `../artifacts/selected_features.json` în **exact** formatul
pe care `train_detector.py` îl citește (cheia `"features"`). Deci fluxul complet e:

```bash
# din folderul nids_soc_platform/
python research/optimize_features.py --min-features 3 --max-features 6
python train_detector.py          # antrenează pe trăsăturile alese de NSGA-II
python evaluate_models.py         # figuri + metrici
```

## Opțiuni utile
```
--max-fpr 0.01        bugetul SOC de false positives (implicit 1%)
--min-features 3      minim de trăsături (robustețe; evită soluția cu 1 trăsătură)
--max-features 6      maxim de trăsături
--generations 20      generații NSGA-II
--pop-size 30         dimensiune populație
--no-write-artifact   rulează fără a atinge selected_features.json (doar raport)
```

## Dependențe
Doar `numpy`, `pandas`, `scipy`, `scikit-learn`. **Fără** pymoo / xgboost / CPLEX.

## Notă pentru dataset-ul complet
Pe eșantionul mono-atac (PortScan) recall-ul se saturează la ~100% la toate metodele;
diferențiatorul real este FPR-ul. Pentru rezultate non-degenerate, rulează același
modul pe **CIC-IDS2017 complet (multi-atac)**:

```bash
python research/optimize_features.py --dataset /cale/catre/cicids2017_full.csv
```

Nicio modificare de cod nu este necesară — doar fișierul CSV se schimbă.
