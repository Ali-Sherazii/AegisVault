"""
Drift monitoring for the deployed ML classifier.

A WAF is a classic concept-drift case: attack patterns evolve over time, so
the confidence-score distribution the model produces on live traffic should
be expected to drift away from what it produced on its own held-out test set
at training time. This module compares the two via the Population Stability
Index (PSI), a standard drift metric.

The baseline distribution is written by waf/Training/train.py (see
baseline_stats.json) at training time; this module never fits anything
itself, so it stays a light import (numpy only) safe to load into the
request-serving dashboard process.
"""
from datetime import datetime, timedelta, timezone

import numpy as np

# waf/Training/train.py produces one predictor_*.joblib per key; keep this in
# sync with that mapping (and with predictor.py's own display_map).
MODEL_FILE_TO_KEY = {
    "predictor_svc.joblib": "svm",
    "predictor_lr.joblib": "lr",
    "predictor_rf.joblib": "rf",
}

DEFAULT_PSI_THRESHOLD = 0.2
DEFAULT_WINDOW_HOURS = 24
N_BINS = 10


def request_confidence(ml_prediction: dict) -> float | None:
    """Extract a single representative confidence score from a logged request's
    ml_prediction blob (mirrors the max-of-confidence_scores logic waf/app.py
    uses to decide `prediction_result.confidence`)."""
    if not ml_prediction:
        return None
    scores = ml_prediction.get("confidence_scores") or {}
    if not scores:
        return None
    return max(scores.values())


def confidence_histogram(confidences, n_bins: int = N_BINS) -> list:
    edges = np.linspace(0.0, 1.0, n_bins + 1)
    counts, _ = np.histogram(np.asarray(confidences, dtype=float), bins=edges)
    return counts.tolist()


def population_stability_index(baseline_counts, current_counts, epsilon: float = 1e-4) -> float:
    baseline = np.array(baseline_counts, dtype=float)
    current = np.array(current_counts, dtype=float)
    baseline_pct = np.clip(baseline / baseline.sum(), epsilon, None) if baseline.sum() else None
    current_pct = np.clip(current / current.sum(), epsilon, None) if current.sum() else None
    if baseline_pct is None or current_pct is None:
        return 0.0
    return float(np.sum((current_pct - baseline_pct) * np.log(current_pct / baseline_pct)))


def compute_drift(
    collection,
    baseline_stats: dict,
    active_model_file: str,
    window_hours: int = DEFAULT_WINDOW_HOURS,
    psi_threshold: float = DEFAULT_PSI_THRESHOLD,
) -> dict:
    """Compare the confidence-score distribution of recent requests against
    the training-time baseline for the currently active model.

    Returns a dict always safe to `jsonify` directly.
    """
    model_key = MODEL_FILE_TO_KEY.get(active_model_file)
    baseline = baseline_stats.get(model_key) if model_key else None
    if not baseline:
        return {
            "available": False,
            "reason": f"no baseline stats for active model '{active_model_file}' "
                      f"(train it with waf/Training/train.py)",
        }

    since = datetime.now(timezone.utc) - timedelta(hours=window_hours)
    cursor = collection.find(
        {"timestamp": {"$gte": since}, "ml_prediction": {"$ne": None}},
        {"ml_prediction": 1, "blocked": 1},
    )

    confidences = []
    blocked_count = 0
    total = 0
    for doc in cursor:
        confidence = request_confidence(doc.get("ml_prediction"))
        if confidence is None:
            continue
        confidences.append(confidence)
        total += 1
        if doc.get("blocked"):
            blocked_count += 1

    if total == 0:
        return {
            "available": False,
            "reason": "no ML-evaluated requests logged in this window yet",
            "window_hours": window_hours,
        }

    current_histogram = confidence_histogram(confidences)
    psi = population_stability_index(baseline["confidence_histogram"], current_histogram)

    return {
        "available": True,
        "window_hours": window_hours,
        "sample_size": total,
        "block_rate": blocked_count / total,
        "baseline_block_rate": baseline.get("block_rate"),
        "confidence_histogram": current_histogram,
        "baseline_confidence_histogram": baseline["confidence_histogram"],
        "psi": psi,
        "psi_threshold": psi_threshold,
        "drift_flag": psi > psi_threshold,
    }
