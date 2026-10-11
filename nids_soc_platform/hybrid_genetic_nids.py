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

print("=== Modul Hibrid Genetic NIDS (Inspirat din Algoritmul de Licență) ===\n")

# 1. Încărcare Dataset CIC-IDS2017
df = pd.read_csv("dataset/cicids2017_sample.csv")
df.columns = df.columns.str.strip()

candidate_features = [
    'Flow Duration',
    'Total Fwd Packets',
    'Total Backward Packets',
    'Total Length of Fwd Packets',
    'Total Length of Bwd Packets',
    'Flow Bytes/s',
    'Flow Packets/s',
    'Fwd Packet Length Max',
    'Bwd Packet Length Max',
    'FIN Flag Count',
    'SYN Flag Count',
    'ACK Flag Count'
]

available_features = [f for f in candidate_features if f in df.columns]
df['target'] = df['Label'].apply(lambda x: 0 if str(x).upper() == 'BENIGN' else 1)

X_raw = df[available_features].values
y_raw = df['target'].values

scaler = StandardScaler()
X_all = scaler.fit_transform(X_raw)

X_train, X_val, y_train, y_val = train_test_split(
    X_all, y_raw, test_size=0.3, random_state=42, stratify=y_raw
)


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
                 stagnation_limit=4, max_allowed_fpr=0.01):
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

        # Calcul importanță prealabilă (ghidaj pentru Local Improve / Fallback)
        base_clf = RandomForestClassifier(n_estimators=20, random_state=42, n_jobs=-1)
        base_clf.fit(self.X_train, self.y_train)
        self.feature_rankings = np.argsort(base_clf.feature_importances_)[::-1]

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
        Memetic Local Search: activează cea mai influentă trăsătură dacă cromozomul
        are penalizare hard sau elimină trăsături redundante de coadă.
        """
        improved = chromosome[:]
        selected_idx = self.decode(improved)

        # Dacă are prea puține trăsături sau ratează constrângerea tare, injectăm trăsătura de top
        top_feature = self.feature_rankings[0]
        if improved[top_feature] == 0:
            improved[top_feature] = 1
            return improved

        # Dacă are prea multe trăsături active (> 6), oprim trăsătura cu cea mai slabă relevanță
        if len(selected_idx) > 5:
            worst_feature = self.feature_rankings[-1]
            improved[worst_feature] = 0

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
        if sum(mutated) == 0:
            mutated[self.feature_rankings[0]] = 1
        return mutated

    def _fallback_to_repair(self, best_chrom):
        """
        Fallback determinist (echivalent _fallback_to_mip):
        Dacă s-a stagnat cu hard > 0, forțăm activarea primelor 4 caracteristici fundamentale.
        """
        repaired = best_chrom[:]
        for top_idx in self.feature_rankings[:4]:
            repaired[top_idx] = 1
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
# Instanțiere și execuție algoritm
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
    stagnation_limit=3
)

best_chromosome, selected_features = optimizer.run()
total_time = time.perf_counter() - start_t

print(f"\nOptimizare finalizată în {total_time:.2f} secunde!")
print(f"Trăsături inițiale: {len(available_features)}")
print(f"Trăsături reținute ({len(selected_features)}):")
for f in selected_features:
    print(f"  -> [OK] {f}")

# Salvare raport json
os.makedirs("reports", exist_ok=True)
with open("reports/hybrid_genetic_results.json", "w") as f:
    json.dump({
        "execution_time_seconds": round(total_time, 2),
        "total_initial_features": len(available_features),
        "selected_feature_count": len(selected_features),
        "selected_features": selected_features,
        "chromosome": best_chromosome
    }, f, indent=4)

print("\nRezultatele au fost salvate în: reports/hybrid_genetic_results.json")