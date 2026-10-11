import os
import glob
import pandas as pd

# Pune calea către folderul unde se află cele 8 fișiere CSV extrase
# Dacă le-ai extras chiar în dataset/ sau altundeva, ajustează calea:
RAW_FOLDER = "dataset"

print("=== Creare Set Compozit CIC-IDS2017 ===")
csv_files = glob.glob(os.path.join(RAW_FOLDER, "*.csv"))
# Excludem sample-ul vechi dacă există deja
csv_files = [f for f in csv_files if "cicids2017_sample.csv" not in f]

if not csv_files:
    # Caută recursiv în subdirectoare (de exemplu dacă s-a extras într-un subfolder)
    csv_files = glob.glob(os.path.join(RAW_FOLDER, "**", "*.csv"), recursive=True)
    csv_files = [f for f in csv_files if "cicids2017_sample.csv" not in f]

print(f"Fișiere CSV identificate ({len(csv_files)}):")
for f in csv_files:
    print(f"  * {os.path.basename(f)}")

dfs = []
for f in csv_files:
    try:
        # Luăm câte 6.000 de linii din fiecare zi/fișier pentru un mix echilibrat
        chunk = pd.read_csv(f, nrows=6000, low_memory=False)
        chunk.columns = chunk.columns.str.strip()
        dfs.append(chunk)
        print(f"Încărcat: {os.path.basename(f)} -> {len(chunk)} rânduri")
    except Exception as e:
        print(f"Eroare citire {f}: {e}")

if dfs:
    full_df = pd.concat(dfs, ignore_index=True)
    full_df = full_df.replace([float('inf'), float('-inf')], float('nan')).dropna()

    out_path = "dataset/cicids2017_sample.csv"
    os.makedirs("dataset", exist_ok=True)
    full_df.to_csv(out_path, index=False)
    print(f"\nSet compozit salvat cu succes în: {out_path}")
    print(f"Total înregistrări: {len(full_df)} | Total coloane: {full_df.shape[1]}")

    label_col = [c for c in full_df.columns if 'label' in c.lower()][0]
    print("\nDistribuție clase de trafic în setul compozit:")
    print(full_df[label_col].value_counts())
else:
    print("Nu s-au găsit fișiere CSV de procesat! Verifică calea din RAW_FOLDER.")