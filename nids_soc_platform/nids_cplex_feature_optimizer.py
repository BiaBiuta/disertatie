import os
import time
import numpy as np
import pandas as pd
import pyomo.environ as pyo
from pyomo.opt import SolverFactory, SolverStatus, TerminationCondition
from sklearn.feature_selection import mutual_info_classif
from sklearn.preprocessing import StandardScaler

print("=== Modul MIP/CPLEX pentru Optimizarea Trăsăturilor NIDS ===\n")

# Calea executabilului CPLEX din licență
CPLEX_EXE_PATH = r"C:\Program Files\IBM\ILOG\CPLEX_Studio2212\cplex\bin\x64_win64\cplex.exe"


class NIDSCplexOptimizer:
    """
    Optimizator matematic MIP bazat pe Pyomo și CPLEX.
    Rezolvă problema selecției optime de trăsături NIDS prin
    maximizarea relevanței informaționale și minimizarea redundanței și costului computațional.
    """

    def __init__(self, df, feature_cols, target_col='target',
                 min_features=3, max_features=4,
                 lambda_relevance=10.0, mu_redundancy=4.0):
        self.df = df
        self.features = feature_cols
        self.target_col = target_col
        self.min_k = min_features
        self.max_k = max_features
        self.lambda_rel = lambda_relevance
        self.mu_red = mu_redundancy

        self.X = df[self.features].values
        self.y = df[self.target_col].values

        # Calcul coeficienți matematici
        self.relevance = {}
        self.redundancy = {}
        self.cost = {}
        self._compute_information_metrics()

    def _compute_information_metrics(self):
        """Calculează Relevanța (Mutual Information) și Matricea de Redundanță (Corelație)."""
        print("[1/4] Calcul metrici informaționale (Relevanță & Redundanță)...")
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(self.X)

        mi_scores = mutual_info_classif(X_scaled, self.y, random_state=42)
        corr_matrix = np.abs(np.corrcoef(X_scaled, rowvar=False))

        for idx, feat in enumerate(self.features):
            self.relevance[feat] = float(mi_scores[idx])
            # Cost simulat de procesare pe pachete în bufferul SOC
            self.cost[feat] = 1.0 if "Duration" in feat else 1.5

        for i, f1 in enumerate(self.features):
            for j, f2 in enumerate(self.features):
                if i < j:
                    self.redundancy[(f1, f2)] = float(corr_matrix[i, j])

    def initialize_mip(self):
        """Construiește modelul matematic Pyomo exact ca în OptimizerIteration.initialize_mip."""
        print("[2/4] Inițializare model Pyomo (0-1 MIP)...")
        model = pyo.ConcreteModel(name="NIDS_Feature_Selection_MIP")

        # Mulțimi
        model.F = pyo.Set(initialize=self.features)

        pairs = [(f1, f2) for i, f1 in enumerate(self.features) for j, f2 in enumerate(self.features) if i < j]
        model.PAIRS = pyo.Set(dimen=2, initialize=pairs)

        # Variabile de decizie binare
        model.z = pyo.Var(model.F, domain=pyo.Binary)
        model.w = pyo.Var(model.PAIRS, domain=pyo.NonNegativeReals, bounds=(0, 1))

        # Constrângeri tari (Hard Constraints)
        # 1. Dimensiune minimă și maximă sub-set de trăsături
        model.constraint_min_features = pyo.Constraint(
            expr=sum(model.z[f] for f in model.F) >= self.min_k
        )
        model.constraint_max_features = pyo.Constraint(
            expr=sum(model.z[f] for f in model.F) <= self.max_k
        )

        # 2. Liniarizare termen pătratic w_jk >= z_j + z_k - 1 (penalizare redundanță doar dacă ambele sunt selectate)
        def rule_redundancy_linearization(m, f1, f2):
            return m.w[f1, f2] >= m.z[f1] + m.z[f2] - 1.0

        model.constraint_linearize = pyo.Constraint(model.PAIRS, rule=rule_redundancy_linearization)

        # 3. Constrângere logică specifică de rețea:
        # Dacă se alege o rată ('Flow Bytes/s' sau 'Flow Packets/s'), 'Flow Duration' devine obligatorie
        if 'Flow Duration' in self.features:
            for rate_feat in ['Flow Bytes/s', 'Flow Packets/s']:
                if rate_feat in self.features:
                    model.add_component(
                        f"constraint_dep_{rate_feat.replace(' ', '_').replace('/', '_')}",
                        pyo.Constraint(expr=model.z[rate_feat] <= model.z['Flow Duration'])
                    )

        # Funcție Obiectiv
        def objective_rule(m):
            cost_term = sum(self.cost[f] * m.z[f] for f in m.F)
            relevance_term = self.lambda_rel * sum(self.relevance[f] * m.z[f] for f in m.F)
            redundancy_term = self.mu_red * sum(self.redundancy[p] * m.w[p] for p in m.PAIRS)
            return cost_term - relevance_term + redundancy_term

        model.objective = pyo.Objective(sense=pyo.minimize, rule=objective_rule)
        return model

    def solve_mip(self, model, is_debug=False):
        """Invocă solverul CPLEX configurat cu calea din licență."""
        print("[3/4] Lansare execuție solver CPLEX...")
        solve_start = time.time()

        opt = pyo.SolverFactory('cplex')

        # Validare executabil CPLEX local
        if os.path.exists(CPLEX_EXE_PATH):
            opt.set_executable(CPLEX_EXE_PATH, validate=False)
            print(f" -> CPLEX detectat la: {CPLEX_EXE_PATH}")
        else:
            print(" -> [Avertisment] CPLEX nu a fost găsit la calea fixă. Se caută în PATH-ul sistemului...")

        if not opt.available():
            print(
                " -> CPLEX nu este disponibil ca solver activ în PATH. Verificăm solverul implicit glpk/cbc sau simulăm...")

        debug_dir = os.path.join(os.getcwd(), 'debug_output')
        os.makedirs(debug_dir, exist_ok=True)

        if is_debug:
            lp_path = os.path.join(debug_dir, 'nids_features.lp')
            log_path = os.path.join(debug_dir, 'cplex_log.txt')
            model.write(filename=lp_path, io_options={"symbolic_solver_labels": True})
            results = opt.solve(model, logfile=log_path)
        else:
            results = opt.solve(model)

        solve_duration = time.time() - solve_start
        print(f" -> Timp rezolvare solver MIP: {solve_duration:.4f} secunde")
        return model, results

    def handle_result(self, model, results):
        """Prelucrează rezultatele solverului exact ca în handle_result din licență."""
        print("[4/4] Extragere decizie optimă din solver...")
        if (results.solver.status == SolverStatus.ok) and (
                results.solver.termination_condition == TerminationCondition.optimal):
            selected_features = []
            for f in model.F:
                val = pyo.value(model.z[f])
                if val is not None and val > 0.5:
                    selected_features.append(f)

            obj_val = pyo.value(model.objective)
            print(f" -> Solver Status: OPTIMAL")
            print(f" -> Valoare Funcție Obiectiv: {obj_val:.4f}")
            print(f" -> Trăsături optime selectate ({len(selected_features)}): {selected_features}")
            return selected_features
        else:
            print(" -> Solverul nu a atins starea optimă!")
            return []


if __name__ == "__main__":
    df_data = pd.read_csv("dataset/cicids2017_sample.csv")
    df_data.columns = df_data.columns.str.strip()
    df_data['target'] = df_data['Label'].apply(lambda x: 0 if str(x).upper() == 'BENIGN' else 1)

    candidate_cols = [
        'Flow Duration',
        'Total Fwd Packets',
        'Total Backward Packets',
        'Flow Bytes/s',
        'Flow Packets/s'
    ]
    present_cols = [c for c in candidate_cols if c in df_data.columns]

    optimizer = NIDSCplexOptimizer(
        df=df_data,
        feature_cols=present_cols,
        min_features=3,
        max_features=4,
        lambda_relevance=8.0,
        mu_redundancy=2.5
    )

    model_mip = optimizer.initialize_mip()
    _, solver_results = optimizer.solve_mip(model_mip, is_debug=True)
    chosen_subset = optimizer.handle_result(model_mip, solver_results)