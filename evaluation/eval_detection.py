"""Detection evaluation harness.

Benchmarks OmniShield's own streaming rolling z-score detector against four
baselines on the labeled NSL-KDD dataset (normal vs attack), reporting
accuracy / precision / recall / F1 / confusion-matrix and throughput.

Detectors are trained one-class (on normal traffic only) — the realistic SOC
setting where you model "normal" and flag deviations.

Usage:
    python -m evaluation.eval_detection --limit 40000
    python -m evaluation.eval_detection            # full dataset (~126k rows)
"""

import argparse
import time

import numpy as np
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    precision_recall_fscore_support,
)
from sklearn.model_selection import train_test_split

from evaluation._common import print_table, save_results  # noqa: E402
from omnishield.datasets import DATASET_NAME, load_feature_matrix  # noqa: E402
from omnishield.detection import (  # noqa: E402
    EWMADetector,
    HybridZScoreIForestDetector,
    IsolationForestDetector,
    OneClassSVMDetector,
    PCAReconstructionDetector,
    RollingZScoreDetector,
)


def build_split(limit):
    X, y, byte_signal = load_feature_matrix(limit=limit)
    normal_mask = y == 0
    attack_mask = y == 1

    X_norm, y_norm, b_norm = X[normal_mask], y[normal_mask], byte_signal[normal_mask]
    X_atk, y_atk, b_atk = X[attack_mask], y[attack_mask], byte_signal[attack_mask]

    # 60% of normals for one-class training; remainder + all attacks for test.
    idx = np.arange(len(X_norm))
    train_idx, test_norm_idx = train_test_split(idx, test_size=0.4, random_state=42)

    X_train = X_norm[train_idx]

    X_test = np.vstack([X_norm[test_norm_idx], X_atk])
    y_test = np.concatenate([y_norm[test_norm_idx], y_atk])
    b_test = np.concatenate([b_norm[test_norm_idx], b_atk])

    # Shuffle test set so the streaming detectors see a realistic interleaving.
    order = np.random.RandomState(7).permutation(len(y_test))
    return X_train, X_test[order], y_test[order], b_test[order]


def evaluate(detector, X_train, X_test, y_test, b_test, streaming):
    t0 = time.perf_counter()
    detector.fit(X_train)
    fit_s = time.perf_counter() - t0

    t1 = time.perf_counter()
    preds = detector.predict(b_test if streaming else X_test)
    pred_s = time.perf_counter() - t1

    p, r, f1, _ = precision_recall_fscore_support(
        y_test, preds, average="binary", zero_division=0
    )
    tn, fp, fn, tp = confusion_matrix(y_test, preds, labels=[0, 1]).ravel()
    n = len(y_test)
    return {
        "detector": detector.name,
        "type": "streaming" if streaming else "batch",
        "accuracy": round(accuracy_score(y_test, preds), 4),
        "precision": round(float(p), 4),
        "recall": round(float(r), 4),
        "f1": round(float(f1), 4),
        "tp": int(tp),
        "fp": int(fp),
        "fn": int(fn),
        "tn": int(tn),
        "fit_sec": round(fit_s, 3),
        "predict_sec": round(pred_s, 3),
        "throughput_eps": round(n / pred_s) if pred_s > 0 else None,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=40000, help="max rows (0 = all)")
    args = ap.parse_args()
    limit = None if args.limit == 0 else args.limit

    print(f"[eval_detection] Loading {DATASET_NAME} feature matrix (limit={limit})...")
    X_train, X_test, y_test, b_test = build_split(limit)
    print(
        f"[eval_detection] train(normal)={len(X_train)}  "
        f"test={len(y_test)}  attacks_in_test={int(y_test.sum())}\n"
    )

    detectors = [
        (RollingZScoreDetector(), True),
        (EWMADetector(), True),
        (IsolationForestDetector(), False),
        (OneClassSVMDetector(), False),
        (PCAReconstructionDetector(), False),
        (HybridZScoreIForestDetector(), False),  # the live pipeline's rule
    ]

    results = []
    for det, streaming in detectors:
        print(f"  running {det.name} ...")
        results.append(evaluate(det, X_train, X_test, y_test, b_test, streaming))

    results.sort(key=lambda r: r["f1"], reverse=True)

    print("\n=== Detection Benchmark (NSL-KDD, one-class training) ===\n")
    print_table(
        results,
        ["detector", "type", "accuracy", "precision", "recall", "f1", "throughput_eps"],
    )

    payload = {
        "dataset": DATASET_NAME,
        "limit": limit,
        "train_normal": len(X_train),
        "test_size": len(y_test),
        "test_attacks": int(y_test.sum()),
        "results": results,
    }
    path = save_results("detection", payload)
    print(f"\n[eval_detection] Results saved to {path}")


if __name__ == "__main__":
    main()
