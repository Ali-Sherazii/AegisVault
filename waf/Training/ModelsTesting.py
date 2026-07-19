#!/usr/bin/env python3
"""
Interactive tester for saved models in waf/Training.
Prompts the user for a URL and model choice, loads the chosen joblib
model, and prints the model's prediction and class probabilities (if available).
"""
import os
import sys
import joblib
from pathlib import Path


MODEL_DIR = Path(__file__).resolve().parent

MODELS = {
    "1": (MODEL_DIR / "predictor_rf.joblib", "Random Forest"),
    "2": (MODEL_DIR / "predictor_lr.joblib", "Logistic Regression"),
    "3": (MODEL_DIR / "predictor.joblib", "SVM / Original Predictor"),
    "4": (MODEL_DIR / "waf_improved_model.pkl", "Naive Bayes Text Model"),
}


def load_model(path):
    if not path.exists():
        print(f"Model file not found: {path}")
        return None
    try:
        return joblib.load(path)
    except Exception as e:
        print(f"Failed to load model {path}: {e}")
        return None


def print_prediction(model, text):
    try:
        pred = model.predict([text])
    except Exception as e:
        # If model is a GridSearchCV or wraps estimator differently, try best_estimator_
        try:
            pred = model.best_estimator_.predict([text])
        except Exception:
            print(f"Prediction failed: {e}")
            return

    print("\n=== Prediction ===")
    print(pred[0])

    # Try probabilities
    proba = None
    try:
        proba = model.predict_proba([text])
    except Exception:
        try:
            proba = model.best_estimator_.predict_proba([text])
        except Exception:
            proba = None

    if proba is not None:
        # Get class labels if available
        classes = None
        try:
            classes = getattr(model, 'classes_', None)
            if classes is None and hasattr(model, 'best_estimator_'):
                classes = getattr(model.best_estimator_, 'classes_', None)
            # If still None and model is a pipeline, try last step
            if classes is None and hasattr(model, 'steps'):
                classes = getattr(model.steps[-1][1], 'classes_', None)
        except Exception:
            classes = None

        print('\n=== Prediction Probabilities ===')
        if classes is not None:
            for cls, p in zip(classes, proba[0]):
                print(f"{cls}: {p:.4f}")
        else:
            # Fallback: print raw probabilities
            print(proba)


def choose_model():
    print("Choose a model to use:")
    for k, (p, name) in MODELS.items():
        print(f"  {k}. {name} ({p.name})")
    choice = input("Enter choice (1/2/3) [default 1]: ").strip() or "1"
    if choice not in MODELS:
        print("Invalid choice, defaulting to 1.")
        choice = "1"
    return MODELS[choice][0]


def main():
    print("Model tester for WAF - enter a URL or payload to classify.")
    text = input("Enter URL or payload: ").strip()
    if not text:
        print("No input provided. Exiting.")
        sys.exit(0)

    model_path = choose_model()
    model = load_model(model_path)
    if model is None:
        sys.exit(1)

    print_prediction(model, text)


if __name__ == "__main__":
    main()
