import os
import random
import time
import json
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import confusion_matrix, recall_score

def load_data(path="dataset/cicids2017_sample.csv", test_size=0.3, random_state=42, verbose=True):
    """
    Încarcă CIC-IDS2017, construiește ținta binară, selectează setul COMPLET de
    trăsături numerice (fără etichetă și fără coloane de identitate cu leakage) și
    face split anti-leakage: scaler potrivit DOAR pe train.

    Returnează: (available_features, X_train, X_val, y_train, y_val)
    """
    df = pd.read_csv(path)
    df.columns = df.columns.str.strip()
    df = df.replace([np.inf, -np.inf], np.nan)
    df['target'] = df['Label'].apply(lambda x: 0 if str(x).upper() == 'BENIGN' else 1)

    EXCLUDE = {'Label', 'target', 'Destination Port'}
    numeric_cols = df.select_dtypes(include=[np.number]).columns.tolist()
    available_features = [c for c in numeric_cols if c not in EXCLUDE]
    available_features = [c for c in available_features
                          if df[c].notna().sum() > 100 and df[c].nunique(dropna=True) > 1]

    df = df.dropna(subset=available_features + ['target'])
    X_raw = df[available_features].values
    y_raw = df['target'].values

    X_tr_raw, X_v_raw, y_tr, y_v = train_test_split(
        X_raw, y_raw, test_size=test_size, random_state=random_state, stratify=y_raw)
    sc = StandardScaler()
    X_tr = sc.fit_transform(X_tr_raw)
    X_v = sc.transform(X_v_raw)

    if verbose:
        print(f"Trasaturi candidate (set complet, fara leakage): {len(available_features)}")
    return available_features, X_tr, X_v, y_tr, y_v


class HybridGeneticFeatureSelector:
    """
    Transpunerea arhitecturii GeneticScheduler din licență:
    - Cromozom: vector binar (1 = feature activ, 0 = inactiv)
    - Hard KPI: Încălcarea pragului strict SOC de False Positives (FPR > 1.0%)
    - Soft KPI: Număr mare de trăsături (cost computațional) + Atacuri ratate (1 - Recall)
    - Local Improve & Fallback: Reparare deterministă pe cele mai informative trăsături
    """

    def __init__(self, feature_names, X_tr, y_tr, X_v, y_v,
                 population_size=20, generations=12,
                 elite_size=2, crossover_rate=0.75, mutation_rate=0.1,
                 stagnation_limit=4, max_allowed_fpr=0.01,
                 shap_period=3, shap_sample=400, shap_temperature=0.5,
                 importance_source="shap", rng_seed=42):
        self.features = feature_names
        self.num_genes = len(feature_names)
        self.X_train = X_tr
        self.y_train = y_tr
        self.X_val = X_v
        self.y_val = y_v

        self.pop_size = population_size
        self.generations = generations
        self.elite_size = elite_size
        self.crossover_rate = crossover_rate
        self.mutation_rate = mutation_rate
        self.stag_limit = stagnation_limit
        self.max_allowed_fpr = max_allowed_fpr

        # --- Parametri pentru ghidarea DINAMICA prin XAI (SHAP) ---
        self.shap_period = shap_period          # recalculare SHAP o data la K generatii
        self.shap_sample = shap_sample          # esantion pentru TreeSHAP (cost marginit)
        self.shap_temperature = shap_temperature  # temperatura operatorului probabilistic
        # sursa de importanta: "shap" (contributie) sau "rf" (baseline RandomForest).
        # Permite comparatia directa SHAP vs RandomForest in acelasi algoritm.
        self.importance_source = importance_source
        self.rng = np.random.default_rng(rng_seed)
        self._shap_cache = {}                   # cache: cheie = subsetul de trasaturi evaluat
        self.shap_recompute_count = 0

        # CONTRIBUTIE: ierarhia care ghideaza cautarea locala memetica este derivata
        # din valorile SHAP (TreeSHAP), NU din feature_importances_. In plus, importanta
        # NU este un prior static: se RECALCULEAZA periodic pe elita curenta (ghidare
        # dinamica), iar operatorii de cautare locala/mutatie o folosesc PROBABILISTIC.
        # Costul este marginit prin: (a) un singur calcul la fiecare K generatii, nu per
        # individ; (b) esantionare; (c) cache pe subsetul de trasaturi.
        self.importance_method = None
        self.feature_importance = None
        self.feature_rankings = None
        # importanta initiala pe TOATE trasaturile (generatia 0)
        vec = self._shap_importance(tuple(range(self.num_genes)), announce=True)
        self._set_importance(vec)

    def _shap_importance(self, active_idx, announce=False):
        """
        Importanța trăsăturilor pe sub-setul `active_idx` (tuple de indici), derivată
        din valorile SHAP (TreeSHAP) peste un model-bază antrenat DOAR pe acele coloane.
        Importanța = media |valorii SHAP| pe un eșantion (contribuția medie absolută la
        predicție). Rezultatul este un vector de lungime num_genes: trăsăturile din
        afara sub-setului primesc 0.

        Cost mărginit prin: eșantionare (shap_sample) si CACHE pe `active_idx` (daca
        aceeasi elita revine, nu se recalculeaza). Fallback pe feature_importances_
        (RandomForest) daca biblioteca `shap` nu e disponibila, ca modulul sa ruleze.
        """
        if len(active_idx) == 0:
            active_idx = tuple(range(self.num_genes))
        if active_idx in self._shap_cache:
            return self._shap_cache[active_idx]

        cols = list(active_idx)
        base_clf = RandomForestClassifier(n_estimators=40, random_state=42, n_jobs=-1)
        base_clf.fit(self.X_train[:, cols], self.y_train)

        n = min(self.shap_sample, len(self.X_train))
        idx = self.rng.choice(len(self.X_train), size=n, replace=False)
        X_bg = self.X_train[idx][:, cols]

        if self.importance_source == "rf":
            # Baseline explicit: importanța RandomForest (pentru comparație cu SHAP)
            imp_sub = base_clf.feature_importances_
            method = "RandomForest feature_importances_ (baseline)"
        else:
            try:
                import shap
                explainer = shap.TreeExplainer(base_clf)
                sv = explainer.shap_values(X_bg)
                if isinstance(sv, list):
                    sv = sv[1] if len(sv) > 1 else sv[0]
                sv = np.asarray(sv)
                if sv.ndim == 3:
                    sv = sv[:, :, 1] if sv.shape[2] > 1 else sv[:, :, 0]
                imp_sub = np.abs(sv).mean(axis=0)
                method = "SHAP (TreeSHAP, media |valoare| per trăsătură)"
            except Exception as e:
                imp_sub = base_clf.feature_importances_
                method = f"RandomForest feature_importances_ (fallback: {type(e).__name__})"

        # Mapare inapoi in spatiul complet de trasaturi
        full = np.zeros(self.num_genes, dtype=float)
        for col_pos, feat_idx in enumerate(cols):
            full[feat_idx] = float(imp_sub[col_pos])

        self.importance_method = method
        self._shap_cache[active_idx] = full
        self.shap_recompute_count += 1
        if announce:
            print(f"[Importanță trăsături] Metodă: {method} | eșantion={n}")
        return full

    def _set_importance(self, vec):
        """Fixeaza vectorul de importanta curent si ierarhia derivata din el."""
        self.feature_importance = np.asarray(vec, dtype=float)
        self.feature_rankings = np.argsort(self.feature_importance)[::-1]

    def _update_importance_dynamic(self, elite_pop, gen):
        """
        GHIDARE DINAMICA: recalculeaza importanta SHAP pe UNIUNEA trasaturilor active
        din elita curenta, apoi actualizeaza ierarhia. Pe masura ce populatia se
        concentreaza pe un sub-set, SHAP reflecta importanta IN ACEL context, nu un
        prior fix. Apelata o data la K generatii -> cost marginit.
        """
        union = set()
        for ind in elite_pop:
            union.update(self.decode(ind))
        key = tuple(sorted(union)) if union else tuple(range(self.num_genes))
        vec = self._shap_importance(key)
        self._set_importance(vec)
        top = [self.features[i] for i in self.feature_rankings[:3]]
        print(f"   [XAI dinamic] Gen {gen}: SHAP recalculat pe {len(key)} trăsături din elită; top: {top}")

    # ---- Operatori probabilistici ghidați de importanța SHAP ----

    def _weights(self, importance):
        """Normalizeaza importanta la o distributie de probabilitate, cu temperatura."""
        w = np.clip(np.asarray(importance, dtype=float), 1e-9, None)
        w = w ** (1.0 / max(self.shap_temperature, 1e-3))  # T mic -> mai lacom
        s = w.sum()
        return w / s if s > 0 else np.ones_like(w) / len(w)

    def _sample_feature(self, candidates, importance, invert=False):
        """Alege o trasatura dintr-o lista de candidati, proportional cu importanta
        (sau cu inversul ei, daca invert=True pentru eliminare)."""
        if not candidates:
            return None
        imp = np.array([importance[i] for i in candidates], dtype=float)
        if invert:
            imp = imp.max() - imp + 1e-9  # importanta mica -> sansa mare de eliminare
        p = self._weights(imp)
        return int(self.rng.choice(candidates, p=p))

    def initialize_population(self):
        pop = []
        for _ in range(self.pop_size):
            chrom = [random.choice([0, 1]) for _ in range(self.num_genes)]
            if sum(chrom) == 0:
                chrom[random.randrange(self.num_genes)] = 1
            pop.append(chrom)
        return pop

    def decode(self, chromosome):
        return [i for i, gene in enumerate(chromosome) if gene == 1]

    def fitness(self, chromosome):
        selected_idx = self.decode(chromosome)
        if len(selected_idx) == 0:
            return 999.0, 999.0  # Penalizare maximă

        clf = RandomForestClassifier(n_estimators=15, max_depth=6, random_state=42, n_jobs=-1)
        clf.fit(self.X_train[:, selected_idx], self.y_train)
        y_pred = clf.predict(self.X_val[:, selected_idx])

        cm = confusion_matrix(self.y_val, y_pred)
        tn, fp, fn, tp = cm.ravel()
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 1.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0

        # 1. HARD KPI: Câte zecimi de procent depășește FPR pragul critic SOC de 1%
        hard_violation = max(0.0, fpr - self.max_allowed_fpr) * 1000.0

        # 2. SOFT KPI: Atacuri ratate (1 - Recall) + Penalizare număr mare de trăsături
        feature_cost = len(selected_idx) / self.num_genes
        soft_cost = ((1.0 - recall) * 100.0) + (feature_cost * 10.0)

        return round(hard_violation, 4), round(soft_cost, 4)

    def local_improve(self, chromosome):
        """
        Memetic Local Search PROBABILISTIC, ghidat de importanța SHAP curentă:
        - adaugă o trăsătură inactivă aleasă proporțional cu |SHAP| (prioritate la
          cele influente, dar nu determinist - pastreaza explorarea);
        - dacă sunt prea multe trăsături active, elimină una aleasă proporțional cu
          INVERSUL importanței (candidate slabe au șansă mai mare de eliminare).
        """
        improved = chromosome[:]
        selected_idx = self.decode(improved)
        inactive_idx = [i for i in range(self.num_genes) if improved[i] == 0]

        # Injecteaza o trasatura influenta (probabilistic) daca lipseste cea de top
        top_feature = int(self.feature_rankings[0])
        if improved[top_feature] == 0:
            pick = self._sample_feature(inactive_idx, self.feature_importance, invert=False)
            if pick is not None:
                improved[pick] = 1
                return improved

        # Prea multe trasaturi active -> elimina una slaba (probabilistic)
        if len(selected_idx) > 5:
            drop = self._sample_feature(selected_idx, self.feature_importance, invert=True)
            if drop is not None:
                improved[drop] = 0

        return improved

    def tournament_selection(self, population, fitnesses, k=3):
        candidates = random.sample(range(len(population)), k)
        # Comparare lexicografică ca în licență: minim hard, apoi minim soft
        return population[min(candidates, key=lambda i: fitnesses[i])]

    def crossover(self, p1, p2):
        if random.random() > self.crossover_rate:
            return p1[:], p2[:]
        pt = random.randrange(1, len(p1))
        return p1[:pt] + p2[pt:], p2[:pt] + p1[pt:]

    def mutate(self, chrom):
        mutated = chrom[:]
        for i in range(len(mutated)):
            if random.random() < self.mutation_rate:
                mutated[i] = 1 - mutated[i]
        # Daca mutatia a golit cromozomul, reactiveaza o trasatura aleasa probabilistic
        # dupa importanta SHAP (nu mereu cea de top -> pastreaza diversitatea).
        if sum(mutated) == 0:
            pick = self._sample_feature(list(range(self.num_genes)), self.feature_importance)
            mutated[pick if pick is not None else int(self.feature_rankings[0])] = 1
        return mutated

    def _fallback_to_repair(self, best_chrom):
        """
        Fallback (echivalent _fallback_to_mip): la stagnare pe constrangerea tare,
        forteaza activarea primelor 4 trasaturi dupa importanta SHAP curenta.
        """
        repaired = best_chrom[:]
        for top_idx in self.feature_rankings[:4]:
            repaired[int(top_idx)] = 1
        return repaired

    def run(self):
        pop = self.initialize_population()
        best_hard, best_soft = float('inf'), float('inf')
        best = None
        no_improve = 0

        print(f"Pornire căutare genetică memetică ({self.generations} generații)...")

        for gen in range(1, self.generations + 1):
            fits = [self.fitness(ind) for ind in pop]

            # Găsire cel mai bun individ din generație
            idx = min(range(len(pop)), key=lambda i: fits[i])
            hard, soft = fits[idx]

            if hard < best_hard or (hard == best_hard and soft < best_soft):
                best_hard, best_soft = hard, soft
                best = pop[idx][:]
                no_improve = 0
            else:
                no_improve += 1

            # GHIDARE DINAMICA: recalculeaza importanta SHAP pe elita curenta, o data
            # la K generatii (cost marginit prin perioada + esantion + cache).
            if self.shap_period > 0 and gen % self.shap_period == 0:
                elite_now = [pop[i] for i in sorted(range(len(pop)), key=lambda i: fits[i])[:self.elite_size]]
                self._update_importance_dynamic(elite_now, gen)

            # Memetic Step pe cel mai bun individ
            memetic_candidate = self.local_improve(best)
            m_hard, m_soft = self.fitness(memetic_candidate)
            if m_hard < best_hard or (m_hard == best_hard and m_soft < best_soft):
                best = memetic_candidate[:]
                best_hard, best_soft = m_hard, m_soft
                print(f"   [Memetic LS] Îmbunătățire locală aplicată la gen {gen}!")

            active_feats = sum(best)
            print(
                f"Gen {gen:02d}: Best Hard Violation={best_hard:.2f} | Soft Cost={best_soft:.2f} | Trăsături={active_feats} | Stagnări={no_improve}")

            # Fallback determinist dacă stagnează pe constrângerea tare
            if no_improve >= self.stag_limit and best_hard > 0:
                print("   [GA Fallback] Declansare fallback determinist din cauza stagnării pe constrângeri tari.")
                best = self._fallback_to_repair(best)
                best_hard, best_soft = self.fitness(best)
                break

            # Elitism + Generare Populație Nouă
            elite_idx = sorted(range(len(pop)), key=lambda i: fits[i])[:self.elite_size]
            new_pop = [pop[i][:] for i in elite_idx]

            while len(new_pop) < self.pop_size:
                p1 = self.tournament_selection(pop, fits)
                p2 = self.tournament_selection(pop, fits)
                c1, c2 = self.crossover(p1, p2)
                new_pop.append(self.mutate(c1))
                if len(new_pop) < self.pop_size:
                    new_pop.append(self.mutate(c2))

            pop = new_pop

        # Dacă la final încă avem hard > 0, fallback final
        if best_hard > 0:
            print("   [GA Fallback Final] Aplicare reglaj de siguranță...")
            best = self._fallback_to_repair(best)

        chosen_features = [self.features[i] for i, gene in enumerate(best) if gene == 1]
        return best, chosen_features


if __name__ == '__main__':
    print("=== Modul Hibrid Genetic NIDS (Inspirat din Algoritmul de Licență) ===\n")
    available_features, X_train, X_val, y_train, y_val = load_data()

    start_t = time.perf_counter()
    optimizer = HybridGeneticFeatureSelector(
        feature_names=available_features,
        X_tr=X_train, y_tr=y_train,
        X_v=X_val, y_v=y_val,
        population_size=16,
        generations=8,
        elite_size=2,
        crossover_rate=0.8,
        mutation_rate=0.08,
        stagnation_limit=3,
        shap_period=3,          # recalculare SHAP o data la 3 generatii
        shap_sample=400,        # esantion TreeSHAP
        shap_temperature=0.5,   # <1 -> operator mai lacom spre trasaturile importante
        importance_source="shap"
    )

    best_chromosome, selected_features = optimizer.run()
    total_time = time.perf_counter() - start_t

    print(f"\nOptimizare finalizată în {total_time:.2f} secunde!")
    print(f"Trăsături inițiale: {len(available_features)}")
    print(f"Trăsături reținute ({len(selected_features)}):")
    for f in selected_features:
        print(f"  -> [OK] {f}")

    os.makedirs("reports", exist_ok=True)
    with open("reports/hybrid_genetic_results.json", "w") as f:
        json.dump({
            "execution_time_seconds": round(total_time, 2),
            "total_initial_features": len(available_features),
            "selected_feature_count": len(selected_features),
            "selected_features": selected_features,
            "chromosome": best_chromosome,
            "local_search_guidance": optimizer.importance_method,
            "xai_dynamic": {
                "shap_period_generations": optimizer.shap_period,
                "shap_sample": optimizer.shap_sample,
                "shap_temperature": optimizer.shap_temperature,
                "shap_recompute_count": optimizer.shap_recompute_count,
                "probabilistic_operator": True
            },
            "feature_importance_final": {
                optimizer.features[i]: round(float(optimizer.feature_importance[i]), 6)
                for i in range(len(optimizer.features))
            }
        }, f, indent=4)

    print("\nRezultatele au fost salvate în: reports/hybrid_genetic_results.json")