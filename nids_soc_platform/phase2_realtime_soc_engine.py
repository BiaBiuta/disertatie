import os
import time
import json
import joblib
import numpy as np
import pandas as pd

print("======================================================================")
print("  FAZA 2: REAL-TIME SOC INFERENCE ENGINE & STREAMING DETECTION")
print("======================================================================\n")

artifacts_dir = "artifacts"
model = joblib.load(os.path.join(artifacts_dir, "nids_model.joblib"))
scaler = joblib.load(os.path.join(artifacts_dir, "scaler.joblib"))

with open(os.path.join(artifacts_dir, "selected_features.json"), "r") as f:
    meta = json.load(f)

selected_features = meta["features"]
print(f"Trăsături active în inspecția live ({len(selected_features)}):")
for sf in selected_features:
    print(f"  * {sf}")

df_stream = pd.read_csv("dataset/cicids2017_sample.csv", low_memory=False)
df_stream.columns = df_stream.columns.str.strip()
df_stream = df_stream.replace([np.inf, -np.inf], np.nan).dropna()

label_col = [c for c in df_stream.columns if 'label' in c.lower()][0]
ground_truth = df_stream[label_col].apply(lambda x: 0 if str(x).strip().upper() == 'BENIGN' else 1).values

X_live_raw = df_stream[selected_features].values

BATCH_SIZE = 1000
total_flows = len(X_live_raw)
total_batches = total_flows // BATCH_SIZE

print(f"\nInițiere inspecție live: {total_flows} fluxuri analizate în loturi de {BATCH_SIZE}...")
print("-" * 75)
print(f"{'Lot':<6} | {'Fluxuri/sec':<14} | {'Latență medie (µs)':<22} | {'Alerte Detecție':<15}")
print("-" * 75)

latencies = []
detected_alerts = 0
correct_detections = 0
false_positives = 0

t_start_stream = time.perf_counter()

for b in range(total_batches):
    start_idx = b * BATCH_SIZE
    end_idx = start_idx + BATCH_SIZE
    
    batch_raw = X_live_raw[start_idx:end_idx]
    batch_truth = ground_truth[start_idx:end_idx]
    
    t_batch_start = time.perf_counter()
    batch_scaled = scaler.transform(batch_raw)
    preds = model.predict(batch_scaled)
    t_batch_end = time.perf_counter()
    
    batch_duration = t_batch_end - t_batch_start
    throughput = BATCH_SIZE / batch_duration if batch_duration > 0 else 0
    avg_latency_us = (batch_duration / BATCH_SIZE) * 1e6
    latencies.append(avg_latency_us)
    
    batch_alerts = int(np.sum(preds == 1))
    detected_alerts += batch_alerts
    
    correct_detections += int(np.sum((preds == 1) & (batch_truth == 1)))
    false_positives += int(np.sum((preds == 1) & (batch_truth == 0)))
    
    if (b + 1) % 5 == 0 or (b + 1) == total_batches:
        print(f"#{b+1:<5} | {throughput:>11.0f} fps | {avg_latency_us:>19.2f} µs | {batch_alerts:>12} alerte")

total_stream_time = time.perf_counter() - t_start_stream
overall_throughput = total_flows / total_stream_time

total_attacks = int(np.sum(ground_truth))
recall = (correct_detections / total_attacks) * 100 if total_attacks > 0 else 0.0
total_benign = int(np.sum(ground_truth == 0))
fpr = (false_positives / total_benign) * 100 if total_benign > 0 else 0.0

print("-" * 75)
print("\n=== RAPORT FINAL PERFORMANȚĂ REAL-TIME SOC ===")
print(f"Total fluxuri inspectate:         {total_flows:,}")
print(f"Timp total execuție:              {total_stream_time:.3f} secunde")
print(f"Throughput mediu global:          {overall_throughput:.0f} fluxuri/secundă")
print(f"Latență medie per flux analizat:  {np.mean(latencies):.2f} µs")
print(f"Total atacuri prezente:           {total_attacks:,}")
print(f"True Positive (Atacuri prinse):   {correct_detections:,} (Recall: {recall:.2f}%)")
print(f"False Positive (Alarme false):    {false_positives:,} (FPR: {fpr:.4f}%)")

os.makedirs("reports", exist_ok=True)
soc_report = {
    "engine": "Real-Time SOC Inference Engine (Phase 2)",
    "total_flows_inspected": total_flows,
    "selected_features_count": len(selected_features),
    "throughput_fps": round(overall_throughput, 2),
    "average_latency_microseconds": round(float(np.mean(latencies)), 2),
    "true_positives": correct_detections,
    "false_positives": false_positives,
    "recall_percent": round(recall, 2),
    "fpr_percent": round(fpr, 4)
}

with open("reports/soc_realtime_metrics.json", "w") as f:
    json.dump(soc_report, f, indent=4)

print("\nRaport salvat în: reports/soc_realtime_metrics.json")
