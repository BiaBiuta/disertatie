"""
feature_selection.py
=====================
Metode de selecție a trăsăturilor pentru NIDS, toate evaluate pe ACELAȘI split
anti-leakage (din data_split.py), astfel încât comparația să fie corectă.

Conține:
  - evaluate_subset()          : antrenează un clasificator pe un subset și întoarce
                                 (recall, fpr, n_features) la pragul optim SOC (FPR<=1%)
  - baseline_all()             : toate trăsăturile
  - baseline_mutual_info()     : top-k după Mutual Information
  - baseline_rfe()             : Recursive Feature Elimination
  - NSGA2FeatureSelector       : NSGA-II implementat de la zero (3 obiective)

NSGA-II (contribuția metodologică):
  Cromozom = vector binar peste trăsături.
  Obiective (toate de MINIMIZAT):
     f1 = 1 - recall          (atacuri ratate)
     f2 = fpr                 (alarme false - constrângerea tare SOC)
     f3 = n_features / N      (cost computațional)
  Rezultatul este o FRONTIERĂ PARETO: analistul SOC alege compromisul dorit
  (ex. cel mai mic FPR sub recall minim acceptabil), nu o singură soluție impusă.

Clasificatorul intern este RandomForest (din sklearn, fără dependențe externe);
poate fi înlocuit cu XGBoost schimbând o singură linie în build_classifier().
"""

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_selection import mutual_info_classif, RFE
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import roc_curve


# ----------------------------------------------------------------------------- #
#  Clasificator intern + evaluare la prag SOC
# ----------------------------------------------------------------------------- #

def build_classifier(seed=42, fast=False):
    """Clasificatorul folosit pentru a evalua un subset de trăsături.
    Rapid și deterministic. Înlocuiește cu xgboost.XGBClassifier dacă e disponibil.
    fast=True => pădure mai mică, folosită în interiorul căutării NSGA-II."""
    if fast:
        return RandomForestClassifier(
            n_estimators=25, max_depth=8, n_jobs=-1,
            random_state=seed, class_weight="balanced")
    return RandomForestClassifier(
        n_estimators=60, max_depth=10, n_jobs=-1,
        random_state=seed, class_weight="balanced"
    )


def _metrics_at_soc_threshold(y_true, scores, max_fpr=0.01):
    """
    Alege pragul care maximizează recall-ul sub constrângerea FPR <= max_fpr.
    Returnează (recall, fpr) la acel prag. Exact criteriul SOC din threshold_tuner.
    """
    fpr, tpr, _ = roc_curve(y_true, scores)
    eligible = np.where(fpr <= max_fpr)[0]
    if len(eligible) > 0:
        idx = eligible[-1]          # cel mai mare TPR cu FPR în buget
        return float(tpr[idx]), float(fpr[idx])
    # dacă nicio operare nu respectă bugetul, raportăm cel mai strict punct
    return float(tpr[0]), float(fpr[0])


def evaluate_subset(feature_mask, X_tr, y_tr, X_te, y_te, scaler=None,
                    seed=42, max_fpr=0.01, fast=False, subsample=None):
    """
    Evaluează un subset de trăsături (mask binar) pe splitul dat.
    Returnează dict cu recall, fpr, n_features la pragul SOC.

    fast=True      -> clasificator mai mic (pentru căutarea NSGA-II)
    subsample=int  -> antrenează pe un eșantion aleator de această mărime (viteză)
    """
    idx = np.where(np.asarray(feature_mask) == 1)[0]
    if len(idx) == 0:
        return {"recall": 0.0, "fpr": 1.0, "n_features": 0}

    Xtr = X_tr[:, idx]
    Xte = X_te[:, idx]
    ytr = y_tr
    if subsample is not None and subsample < len(ytr):
        rng = np.random.default_rng(seed)
        sel = rng.choice(len(ytr), size=subsample, replace=False)
        Xtr, ytr = Xtr[sel], ytr[sel]
    if scaler is not None:
        sc = StandardScaler().fit(Xtr)
        Xtr, Xte = sc.transform(Xtr), sc.transform(Xte)

    clf = build_classifier(seed, fast=fast)
    clf.fit(Xtr, ytr)
    scores = clf.predict_proba(Xte)[:, 1]
    recall, fpr = _metrics_at_soc_threshold(y_te, scores, max_fpr=max_fpr)

    return {"recall": round(recall, 4), "fpr": round(fpr, 6),
            "n_features": int(len(idx))}


# ----------------------------------------------------------------------------- #
#  Baseline-uri
# ----------------------------------------------------------------------------- #

def baseline_all(feature_names):
    """Toate trăsăturile active."""
    return [1] * len(feature_names)


def baseline_mutual_info(X_tr, y_tr, k, seed=42):
    """Top-k trăsături după Mutual Information cu ținta."""
    mi = mutual_info_classif(X_tr, y_tr, random_state=seed)
    top = np.argsort(mi)[::-1][:k]
    mask = [0] * X_tr.shape[1]
    for i in top:
        mask[i] = 1
    return mask


def baseline_rfe(X_tr, y_tr, k, seed=42):
    """Recursive Feature Elimination cu un estimator liniar rapid."""
    est = LogisticRegression(max_iter=200, random_state=seed)
    rfe = RFE(est, n_features_to_select=k, step=0.2)
    # scalare necesară pentru estimatorul liniar
    Xs = StandardScaler().fit_transform(X_tr)
    rfe.fit(Xs, y_tr)
    return [1 if s else 0 for s in rfe.support_]


# ----------------------------------------------------------------------------- #
#  NSGA-II (implementare de la zero, 3 obiective)
# ----------------------------------------------------------------------------- #

class NSGA2FeatureSelector:
    """
    NSGA-II multi-obiectiv pentru selecția de trăsături NIDS.

    Obiective minimizate: [1-recall, fpr, n_features/N].
    Produce o frontieră Pareto de subseturi non-dominate.
    """

    def __init__(self, feature_names, X_tr, y_tr, X_te, y_te,
                 pop_size=40, generations=25, crossover_rate=0.9,
                 mutation_rate=None, max_fpr=0.01, max_features=8,
                 min_features=1, eval_seed=42, rng_seed=0, eval_subsample=8000):
        self.features = feature_names
        self.N = len(feature_names)
        self.X_tr, self.y_tr = X_tr, y_tr
        self.X_te, self.y_te = X_te, y_te
        self.pop_size = pop_size
        self.generations = generations
        self.cx_rate = crossover_rate
        self.mut_rate = mutation_rate if mutation_rate is not None else 1.0 / self.N
        self.max_fpr = max_fpr
        self.max_features = max_features
        self.min_features = max(1, min_features)
        self.eval_seed = eval_seed
        self.eval_subsample = eval_subsample
        self.rng = np.random.default_rng(rng_seed)
        self._cache = {}

    # ---- obiective ----
    def _objectives(self, chrom):
        key = tuple(chrom)
        if key in self._cache:
            return self._cache[key]
        n = sum(chrom)
        if n < self.min_features or n > self.max_features:
            obj = (1.0, 1.0, 1.0)      # penalizare: soluție infezabilă
        else:
            m = evaluate_subset(chrom, self.X_tr, self.y_tr, self.X_te, self.y_te,
                                scaler=True, seed=self.eval_seed, max_fpr=self.max_fpr,
                                fast=True, subsample=self.eval_subsample)
            obj = (1.0 - m["recall"], m["fpr"], n / self.N)
        self._cache[key] = obj
        return obj

    # ---- dominanță Pareto ----
    @staticmethod
    def _dominates(a, b):
        return all(x <= y for x, y in zip(a, b)) and any(x < y for x, y in zip(a, b))

    def _fast_non_dominated_sort(self, objs):
        S = [[] for _ in objs]
        n = [0] * len(objs)
        fronts = [[]]
        for p in range(len(objs)):
            for q in range(len(objs)):
                if p == q:
                    continue
                if self._dominates(objs[p], objs[q]):
                    S[p].append(q)
                elif self._dominates(objs[q], objs[p]):
                    n[p] += 1
            if n[p] == 0:
                fronts[0].append(p)
        i = 0
        while fronts[i]:
            nxt = []
            for p in fronts[i]:
                for q in S[p]:
                    n[q] -= 1
                    if n[q] == 0:
                        nxt.append(q)
            i += 1
            fronts.append(nxt)
        return fronts[:-1]

    def _crowding_distance(self, front, objs):
        l = len(front)
        dist = {i: 0.0 for i in front}
        n_obj = len(objs[0])
        for m in range(n_obj):
            order = sorted(front, key=lambda i: objs[i][m])
            dist[order[0]] = dist[order[-1]] = float("inf")
            fmin, fmax = objs[order[0]][m], objs[order[-1]][m]
            span = (fmax - fmin) or 1e-12
            for k in range(1, l - 1):
                dist[order[k]] += (objs[order[k + 1]][m] - objs[order[k - 1]][m]) / span
        return dist

    # ---- operatori genetici ----
    def _init_pop(self):
        pop = []
        for _ in range(self.pop_size):
            k = self.rng.integers(self.min_features, self.max_features + 1)
            chrom = [0] * self.N
            for i in self.rng.choice(self.N, size=k, replace=False):
                chrom[i] = 1
            pop.append(chrom)
        return pop

    def _tournament(self, pop, ranks, crowd):
        a, b = self.rng.integers(0, len(pop), size=2)
        if ranks[a] < ranks[b]:
            return pop[a]
        if ranks[b] < ranks[a]:
            return pop[b]
        return pop[a] if crowd.get(a, 0) >= crowd.get(b, 0) else pop[b]

    def _crossover(self, p1, p2):
        if self.rng.random() > self.cx_rate:
            return p1[:], p2[:]
        mask = self.rng.integers(0, 2, size=self.N)   # uniform crossover
        c1 = [p1[i] if mask[i] else p2[i] for i in range(self.N)]
        c2 = [p2[i] if mask[i] else p1[i] for i in range(self.N)]
        return c1, c2

    def _mutate(self, chrom):
        c = chrom[:]
        for i in range(self.N):
            if self.rng.random() < self.mut_rate:
                c[i] = 1 - c[i]
        if sum(c) == 0:
            c[self.rng.integers(0, self.N)] = 1
        return c

    def run(self, verbose=False):
        pop = self._init_pop()
        for gen in range(self.generations):
            objs = [self._objectives(c) for c in pop]
            fronts = self._fast_non_dominated_sort(objs)
            ranks = {}
            crowd = {}
            for r, fr in enumerate(fronts):
                cd = self._crowding_distance(fr, objs)
                for i in fr:
                    ranks[i] = r
                    crowd[i] = cd[i]

            # descendenți
            offspring = []
            while len(offspring) < self.pop_size:
                p1 = self._tournament(pop, ranks, crowd)
                p2 = self._tournament(pop, ranks, crowd)
                c1, c2 = self._crossover(p1, p2)
                offspring.append(self._mutate(c1))
                if len(offspring) < self.pop_size:
                    offspring.append(self._mutate(c2))

            # combinare părinți + descendenți, selecție elitistă
            combined = pop + offspring
            cobjs = [self._objectives(c) for c in combined]
            cfronts = self._fast_non_dominated_sort(cobjs)
            new_pop = []
            for fr in cfronts:
                if len(new_pop) + len(fr) <= self.pop_size:
                    new_pop.extend(combined[i] for i in fr)
                else:
                    cd = self._crowding_distance(fr, cobjs)
                    ordered = sorted(fr, key=lambda i: cd[i], reverse=True)
                    new_pop.extend(combined[i] for i in ordered[:self.pop_size - len(new_pop)])
                    break
            pop = new_pop

            if verbose:
                best = min(self._objectives(c) for c in pop)
                print(f"  NSGA-II gen {gen+1:02d}/{self.generations} | "
                      f"best (1-recall, fpr, feat%)={tuple(round(x,3) for x in best)}")

        # extrage frontiera Pareto finală (front 0), unică
        objs = [self._objectives(c) for c in pop]
        f0 = self._fast_non_dominated_sort(objs)[0]
        seen = set()
        pareto = []
        for i in f0:
            key = tuple(pop[i])
            if key in seen:
                continue
            seen.add(key)
            o = objs[i]
            pareto.append({
                "chromosome": pop[i],
                "features": [self.features[j] for j, g in enumerate(pop[i]) if g == 1],
                "recall": round(1.0 - o[0], 4),
                "fpr": round(o[1], 6),
                "n_features": int(sum(pop[i])),
            })
        # sortare pe recall descrescător pentru lizibilitate
        pareto.sort(key=lambda d: (-d["recall"], d["fpr"], d["n_features"]))
        return pareto
