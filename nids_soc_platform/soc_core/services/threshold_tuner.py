import numpy as np
from sklearn.metrics import roc_curve, precision_recall_curve


def find_soc_optimal_threshold(y_true: np.ndarray, anomaly_scores: np.ndarray, target_fpr: float = 0.01) -> dict:
    """
    Identifică pragul strict pentru cerințele unui SOC:
    Maximizarea detecției (TPR) sub o constrângere strictă de False Positive Rate (<= 1%).
    """
    fpr, tpr, roc_thresholds = roc_curve(y_true, anomaly_scores)

    # Căutăm cel mai mare TPR unde FPR <= target_fpr (1%)
    eligible_indices = np.where(fpr <= target_fpr)[0]

    if len(eligible_indices) > 0:
        best_idx = eligible_indices[-1]
        best_threshold = float(roc_thresholds[best_idx])
        achieved_fpr = float(fpr[best_idx])
        achieved_tpr = float(tpr[best_idx])
    else:
        # Fallback conservator: percentila 99
        best_threshold = float(np.percentile(anomaly_scores, 99))
        achieved_fpr = 0.01
        achieved_tpr = 0.0

    return {
        "optimal_threshold": best_threshold,
        "achieved_fpr": round(achieved_fpr * 100, 2),
        "achieved_tpr": round(achieved_tpr * 100, 2),
    }