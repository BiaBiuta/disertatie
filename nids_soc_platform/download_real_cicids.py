import os
import shutil
import kagglehub
import pandas as pd

print("=== Descărcare Set CIC-IDS2017 via kagglehub ===")

# 1. Descărcare prin kagglehub
download_path = kagglehub.dataset_download("ishasingh03/friday-workinghours-afternoon-ddos")
print("Descărcat în cache la:", download_path)

# 2. Căutare fișier CSV în folderul descărcat
csv_files = [f for f in os.listdir(download_path) if f.endswith(".csv")]
if not csv_files:
    raise FileNotFoundError("Nu a fost găsit niciun fișier CSV în arhiva descărcată!")

source_csv = os.path.join(download_path, csv_files[0])
print(f"Găsit fișier brut: {csv_files[0]}")

# 3. Pregătire eșantion reprezentativ (pentru a rula rapid la testare)
target_path = "dataset/cicids2017_sample.csv"
os.makedirs("dataset", exist_ok=True)

print("Citire și verificare coloane...")
# Citim primele 25.000 de linii pentru un spațiu combinatorial bogat
df = pd.read_csv(source_csv, nrows=25000)
df.columns = df.columns.str.strip()

# Curățare valori infinite / lipsă standard din CIC-IDS2017
df = df.replace([float('inf'), float('-inf')], float('nan')).dropna()

df.to_csv(target_path, index=False)
print(f"\nSalvat cu succes în: {target_path}")
print(f"Număr de înregistrări: {len(df)}")
print(f"Număr total de caracteristici (Features): {df.shape[1] - 1}")
print("Distribuție etichete:")
print(df['Label'].value_counts())