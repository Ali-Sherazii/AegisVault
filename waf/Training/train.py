#!/usr/bin/env python3
"""
Reproducible training pipeline for AegisVault's text-based WAF classifiers.

Replaces the ad-hoc TrainSVM/TrainLR/TrainRF notebooks with a single script:
stratified 75/25 split (random_state=42, matching the documented split),
trains SVM/LR/RF with the hyperparameters already validated via grid search
(see README's "Hyperparameter Search Results"), logs each run to MLflow
(params, per-class + overall metrics, false-positive rate, and the model
artifact), writes the deployable predictor_*.joblib files, and writes
baseline_stats.json (the confidence-score distribution drift.py compares
live traffic against - see waf/monitoring/drift.py).

Usage:
    python waf/Training/preprocess.py   # first, if complete_clean.json is missing
    python waf/Training/train.py [--models svm,lr,rf]
"""
import argparse
import json
from pathlib import Path

import joblib
import mlflow
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.svm import SVC
from sklearn.feature_extraction.text import TfidfVectorizer

TRAINING_DIR = Path(__file__).resolve().parent
WAF_DIR = TRAINING_DIR.parent
DATASETS_DIR = WAF_DIR / "Datasets"
COMPLETE_CLEAN_JSON = DATASETS_DIR / "complete_clean.json"
MODEL_OUTPUT_DIR = WAF_DIR / "ml_model" / "waf_text"
BASELINE_STATS_JSON = MODEL_OUTPUT_DIR / "baseline_stats.json"

RANDOM_STATE = 42
TEST_SIZE = 0.25

MODEL_SPECS = {
    "svm": {
        "output_file": "predictor_svc.joblib",
        "build": lambda: SVC(kernel="rbf", C=10, probability=True, random_state=RANDOM_STATE),
        "ngram_range": (1, 2),
    },
    "lr": {
        "output_file": "predictor_lr.joblib",
        "build": lambda: LogisticRegression(
            solver="saga", penalty="l2", C=100, max_iter=5000, random_state=RANDOM_STATE
        ),
        "ngram_range": (1, 4),
    },
    "rf": {
        "output_file": "predictor_rf.joblib",
        "build": lambda: RandomForestClassifier(
            n_estimators=200, max_depth=30, min_samples_split=2, random_state=RANDOM_STATE
        ),
        "ngram_range": (1, 2),
    },
}


def load_split():
    if not COMPLETE_CLEAN_JSON.exists():
        raise SystemExit(
            f"Missing {COMPLETE_CLEAN_JSON}. Run waf/Training/preprocess.py first."
        )
    records = json.loads(COMPLETE_CLEAN_JSON.read_text())
    X = [r["pattern"] for r in records]
    y = [r["type"] for r in records]
    return train_test_split(
        X, y, test_size=TEST_SIZE, random_state=RANDOM_STATE, stratify=y
    )


def false_positive_rate(y_true, y_pred) -> float:
    """Share of truly-benign ('valid') test samples misclassified as an attack."""
    valid_mask = [t == "valid" for t in y_true]
    total_valid = sum(valid_mask)
    if total_valid == 0:
        return 0.0
    false_positives = sum(
        1 for t, p, is_valid in zip(y_true, y_pred, valid_mask) if is_valid and p != "valid"
    )
    return false_positives / total_valid


def confidence_histogram(confidences: np.ndarray, n_bins: int = 10) -> list[int]:
    edges = np.linspace(0.0, 1.0, n_bins + 1)
    counts, _ = np.histogram(confidences, bins=edges)
    return counts.tolist()


def train_one(name: str, X_train, X_test, y_train, y_test, mlflow_experiment: str) -> dict:
    spec = MODEL_SPECS[name]
    ngram_range = spec["ngram_range"]

    pipeline = Pipeline([
        ("tfidf", TfidfVectorizer(analyzer="char", lowercase=True, max_features=1024, ngram_range=ngram_range)),
        ("clf", spec["build"]()),
    ])

    mlflow.set_experiment(mlflow_experiment)
    with mlflow.start_run(run_name=name):
        pipeline.fit(X_train, y_train)
        y_pred = pipeline.predict(X_test)
        proba = pipeline.predict_proba(X_test)
        confidences = proba.max(axis=1)

        accuracy = accuracy_score(y_test, y_pred)
        fp_rate = false_positive_rate(y_test, y_pred)
        report = classification_report(y_test, y_pred, output_dict=True, zero_division=0)

        mlflow.log_params({
            "model": name,
            "ngram_range": str(ngram_range),
            "max_features": 1024,
            **{f"clf__{k}": v for k, v in pipeline.named_steps["clf"].get_params().items()
               if isinstance(v, (int, float, str, bool)) or v is None},
        })
        mlflow.log_metric("accuracy", accuracy)
        mlflow.log_metric("false_positive_rate", fp_rate)
        for label, metrics in report.items():
            if isinstance(metrics, dict):
                for metric_name in ("precision", "recall", "f1-score"):
                    if metric_name in metrics:
                        mlflow.log_metric(f"{label}_{metric_name}".replace(" ", "_"), metrics[metric_name])

        output_path = MODEL_OUTPUT_DIR / spec["output_file"]
        MODEL_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        joblib.dump(pipeline, output_path)
        mlflow.log_artifact(str(output_path))

        print(f"[{name}] accuracy={accuracy:.4f} fp_rate={fp_rate:.4f} -> {output_path}")

        return {
            "output_file": spec["output_file"],
            "accuracy": accuracy,
            "false_positive_rate": fp_rate,
            "block_rate": float(np.mean(np.array(y_pred) != "valid")),
            "confidence_histogram": confidence_histogram(confidences),
        }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--models", default="svm,lr,rf", help="Comma-separated subset of svm,lr,rf")
    parser.add_argument("--mlflow-experiment", default="aegisvault-waf-classifiers")
    args = parser.parse_args()

    models = [m.strip() for m in args.models.split(",") if m.strip()]
    for m in models:
        if m not in MODEL_SPECS:
            raise SystemExit(f"Unknown model '{m}'. Choose from: {', '.join(MODEL_SPECS)}")

    X_train, X_test, y_train, y_test = load_split()
    print(f"Train: {len(X_train):,} samples | Test: {len(X_test):,} samples")

    baseline_stats = {}
    if BASELINE_STATS_JSON.exists():
        baseline_stats = json.loads(BASELINE_STATS_JSON.read_text())

    for name in models:
        baseline_stats[name] = train_one(name, X_train, X_test, y_train, y_test, args.mlflow_experiment)

    BASELINE_STATS_JSON.parent.mkdir(parents=True, exist_ok=True)
    BASELINE_STATS_JSON.write_text(json.dumps(baseline_stats, indent=2))
    print(f"\nBaseline stats (for drift monitoring) written to {BASELINE_STATS_JSON}")


if __name__ == "__main__":
    main()
