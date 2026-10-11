import os
import pandas as pd

CACHE_DIR = r"C:\Users\bianc\.cache\kagglehub\datasets\chethuhn\network-intrusion-dataset\versions\1"
portscan_file = os.path.join(CACHE_DIR, "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv")

print(f"Încărcare eșantion din zona activă a atacului...")

# Citim antetul separat pentru a păstra numele corecte ale coloanelor
header_df = pd.read_csv(portscan_file, nrows=1)
columns = header_df.columns.str.strip()

# Sărim peste primele 60.000 de linii (trafic matinal) și citim 40.000 de linii din mijlocul atacului
df = pd.read_csv(
    portscan_file,
    skiprows=range(1, 65000),
    nrows=40000,
    header=0,
    names=columns,
    low_memory=False
)

# Curățare valori infinite și nule
df = df.replace([float('inf'), float('-inf')], float('nan')).dropna()

out_path = "dataset/cicids2017_sample.csv"
os.makedirs("dataset", exist_ok=True)
df.to_csv(out_path, index=False)

print(f"\nSalvat cu succes în: {out_path}")
print(f"Total înregistrări: {len(df)}")
print(f"Total coloane: {df.shape[1]}")

label_col = [c for c in df.columns if 'label' in c.lower()][0]
print("\nDistribuția reală a claselor:")
print(df[label_col].value_counts())