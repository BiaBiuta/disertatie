import os
import kagglehub
import pandas as pd

print("=== Descărcare Set Complet CIC-IDS2017 via kagglehub ===")

# 1. Descărcare depozit complet (toate cele 8 fișiere)
path = kagglehub.dataset_download("chethuhn/network-intrusion-dataset")
print(f"Fișiere descărcate în folderul: {path}")

# 2. Identificare fișiere CSV
csv_files = []
for root, dirs, files in os.walk(path):
    for f in files:
        if f.endswith(".csv"):
            csv_files.append(os.path.join(root, f))

print(f"\nAu fost găsite {len(csv_files)} fișiere CSV:")
for cf in csv_files:
    print(f"  * {os.path.basename(cf)}")

# 3. Extragere eșantion compozit (Benign + Atacuri volumetrice + Atacuri subtile Slowloris / Web)
samples = []
for cf in csv_files:
    fname = os.path.basename(cf).lower()
    try:
        # Citim primele 8.000 de linii din fiecare fișier
        sub_df = pd.read_csv(cf, nrows=8000, low_memory=False)
        sub_df.columns = sub_df.columns.str.strip()
        samples.append(sub_df)
        print(f"Încărcat eșantion din {os.path.basename(cf)} ({len(sub_df)} linii)")
    except Exception as e:
        print(f"Eroare la citirea {fname}: {e}")

# Unire subseturi
full_df = pd.concat(samples, ignore_index=True)
full_df.columns = full_df.columns.str.strip()

# Curățare valori infinite și nule specifice CIC-IDS2017
full_df = full_df.replace([float('inf'), float('-inf')], float('nan')).dropna()

# Salvare ca set de date unificat de benchmark
out_file = "dataset/cicids2017_sample.csv"
os.makedirs("dataset", exist_ok=True)
full_df.to_csv(out_file, index=False)

print(f"\nSet compozit salvat cu succes în: {out_file}")
print(f"Total fluxuri combinate: {len(full_df)}")
print(f"Total coloane: {full_df.shape[1]}")

# Afișare distribuție clase de trafic
label_col = [c for c in full_df.columns if 'label' in c.lower()][0]
print("\nDistribuție etichete / tipuri de atacuri:")
print(full_df[label_col].value_counts())