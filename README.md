# AegisVault

**A Machine Learning Based Web Application Firewall**

AegisVault is an intelligent, layered Web Application Firewall (WAF) that combines traditional rule-based security with trained machine learning models to detect and block malicious HTTP traffic in real time. It operates as a reverse proxy, inspecting every incoming request before it reaches the backend application.

<img width="1403" height="590" alt="image" src="https://github.com/user-attachments/assets/0e122cd4-3164-423d-8f0a-acbd21df41d3" />

<img width="865" height="478" alt="image" src="https://github.com/user-attachments/assets/6e62d03d-1d35-4c09-b037-1ba042e6ad7d" />

---

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Features](#features)
- [Components](#components)
- [Tech Stack](#tech-stack)
- [ML Models](#ml-models)
- [Dataset](#dataset)
- [Model Performance](#model-performance)
- [Getting Started](#getting-started)
- [Project Structure](#project-structure)
- [API Endpoints](#api-endpoints)
- [Industry Standards](#industry-standards)

---

## Overview

Web applications are continuously exposed to attacks including SQL Injection, Cross-Site Scripting (XSS), path traversal, OS command injection, and denial-of-service attempts. Traditional firewalls rely on static rule sets and predefined signatures, which limits effectiveness against evolving or obfuscated payloads.

AegisVault addresses these limitations by:

- Layering multiple security mechanisms (IP blocking, rate limiting, plugins, rules, and ML)
- Using character-level TF-IDF features to detect obfuscated and encoded attack payloads
- Training on a diverse, multi-source dataset to minimize false positives in production
- Providing a real-time monitoring dashboard and detailed request logs

---

## Architecture

AegisVault follows a three-tier architectural design:

| Tier | Component | Port |
|------|-----------|------|
| Presentation | Admin Dashboard | 5001 |
| Application (Logic) | WAF Reverse Proxy | 5000 |
| Data | MongoDB | 27017 |

The WAF intercepts all HTTP traffic on port 5000, applies a multi-stage security pipeline, and forwards allowed requests to the backend application on port 8000.

### Decision Pipeline

Every request passes through the following stages in order:

```
HTTP Request
     │
     ▼
IP Block Check  ──► Blocked? ──► HTTP 429
     │
     ▼
Rate Limiting   ──► Exceeded? ──► Block IP + HTTP 429
     │
     ▼
Plugin Checks   ──► Blocked? ──► HTTP 403
     │
     ▼
Rule Engine     ──► Matched? ──► HTTP 403
     │
     ▼
ML Classifier   ──► Attack? ──► HTTP 403
     │
     ▼
Log to MongoDB
     │
     ▼
Forward to Backend
```

---

## Features

- **Multi-layer security** — IP blocking, sliding-window rate limiting, plugin checks, regex rule engine, and ML inference all run in sequence
- **ML-based detection** — TF-IDF + classifier pipeline detects novel and obfuscated attack payloads beyond fixed signatures
- **Three trained models** — SVM, Logistic Regression, and Random Forest, all selectable via configuration
- **Confidence thresholding** — ML blocking decisions are gated by a configurable confidence score to reduce false positives
- **Real-time dashboard** — Live request monitoring, attack type visualization, and configuration management via SocketIO
- **Extensible plugin system** — Modular checks for admin path blocking, IP blocklists, and user agent filtering
- **YAML rule engine** — Declarative regex rules with `block` or `log` actions, evaluated against decoded and lowercased request variants
- **Full request logging** — Every request (allowed and blocked) is logged to MongoDB with metadata, decision reason, and ML prediction scores

---

## Components

### ML Model Component

Processes request text derived from the URL, query string, body parameters, and selected headers (Cookie, User-Agent, Accept-Encoding, Accept-Language). Applies iterative URL decoding to expose encoded payloads before TF-IDF feature extraction.

Supports three serialized models:
- `predictor.joblib` — SVM
- `predictor_rf.joblib` — Random Forest
- `predictor_lr.joblib` — Logistic Regression

### Rate Limiting

Sliding window counter per IP address. Configurable via `waf_settings.json`:
- `max_requests` — request limit per window
- `window_seconds` — rolling time window
- `block_time` — temporary block duration on violation

### Rule Engine

Evaluates YAML-defined regular expressions against the request path, query string, and body. Creates multiple variants (original, lowercase, URL-decoded) to improve pattern matching coverage.

### Plugin System

Modular, independently toggled security checks including admin path blocking, known malicious IP rejection, and suspicious user agent filtering.

### Database Logger and Dashboard

MongoDB stores all request logs and blocked IP state. The Flask-based dashboard with SocketIO provides live traffic statistics, request inspection, rule management, IP management, and model information.

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| WAF & Backend | Python, Flask |
| Real-time Updates | Flask-SocketIO |
| ML Training & Inference | scikit-learn (TF-IDF, SVM, LR, RF) |
| Model Serialization | joblib |
| Database | MongoDB (PyMongo) |
| Dashboard Frontend | HTML, CSS, JavaScript, SocketIO client |
| Data Processing | pandas, NumPy |

---

## ML Models

All three models use the same feature extraction pipeline:

- **Vectorizer:** TF-IDF with `analyzer='char'`, `lowercase=True`, `max_features=1024`
- **Input:** Combined request text from URL, query params, body, and selected headers
- **Preprocessing:** Iterative URL decoding (up to 100 passes), lowercase normalization, whitespace collapsing

### Hyperparameter Search Results

| Model | CV Folds | Combinations Searched | Best CV Score | Final n-gram Range |
|-------|----------|-----------------------|---------------|--------------------|
| SVM | 2-fold | 12 | 0.994 | (1, 2) |
| Logistic Regression | 3-fold | 24 | 0.991 | (1, 4) |
| Random Forest | 3-fold | 8 | 0.989 | (1, 2) |

**SVM final config:** RBF kernel, C=10, n-gram (1,2)

**Logistic Regression final config:** saga solver, l2 penalty, C=100, n-gram (1,4)

**Random Forest final config:** 200 estimators, max depth 30, min samples split 2, n-gram (1,2)

---

## Dataset

Training data was assembled from three sources to ensure both attack coverage and benign traffic diversity:

| Dataset | Format | Total Samples | Benign | Attack Types |
|---------|--------|--------------|--------|--------------|
| ECML/PKDD 2007 | XML | 45,500 | 35,006 | XSS, SQLi, Path Traversal, OS Commanding |
| HTTPParams | CSV | 31,067 | 19,304 | SQLi, XSS, Path Traversal, CMDi |
| XSS-specific | CSV | 13,686 | 6,313 | XSS |

**Total merged dataset:** 90,253 samples — 67,689 training / 22,564 test (75/25 stratified split, `random_state=42`)

### Attack Classes

After label standardization and merging, five attack classes are used: `valid`, `xss`, `sqli`, `path-traversal`, `cmdi`.

### Why Multiple Sources?

Early testing with only the ECML/PKDD dataset produced a 23%+ false positive rate in production because the benign samples were primarily synthetic. Adding HTTPParams and XSS datasets contributed over 25,000 additional benign samples with realistic patterns — email addresses, special characters, URL-encoded strings, natural language with accents and punctuation — reducing false positives to under 3.2%.

---

## Model Performance

### Standard Test Set (held-out from training data)

| Model | Test Accuracy |
|-------|--------------|
| SVM | 99.6% |
| Logistic Regression | 99.07% |
| Random Forest | 98.9% |

### Real-World Test Set (independent external payloads)

| Model | Accuracy | Precision | Recall | F1 Score |
|-------|----------|-----------|--------|----------|
| Random Forest | 0.844 | **1.000** | 0.767 | 0.868 |
| Logistic Regression | **0.889** | 0.879 | **0.967** | **0.921** |
| SVM | 0.844 | 0.926 | 0.833 | 0.877 |

**Logistic Regression was selected for deployment** because the primary objective of a WAF is to maximize recall — catching as many attacks as possible — while maintaining acceptable precision.

---

## Getting Started

### Prerequisites

- Python 3.8+
- MongoDB running on `localhost:27017`

### Installation

```bash
git clone https://github.com/Ali-Sherazii/AegisVault.git
cd AegisVault
pip install -r requirements.txt
```

### Running the WAF

```bash
# Start the backend application
python backend/app.py          # Runs on port 8000

# Start the WAF reverse proxy
python waf/waf.py              # Runs on port 5000

# Start the dashboard
python waf/dashboard.py        # Runs on port 5001
```

### Training Models

Training notebooks are located in the `notebooks/` directory. Run them in order:

1. `MergeAndClean.ipynb` — parse, clean, and merge raw datasets into `complete_clean.json`
2. `TrainTestSplit.ipynb` — create the stratified split and save to `dataset.npz`
3. `TrainSVM.ipynb` — grid search and train SVM, export `predictor.joblib`
4. `TrainLR.ipynb` — grid search and train Logistic Regression, export `predictor_lr.joblib`
5. `TrainRF.ipynb` — grid search and train Random Forest, export `predictor_rf.joblib`

### Configuration

WAF behavior is configured in `waf_settings.json`:

```json
{
  "max_requests": 100,
  "window_seconds": 60,
  "block_time": 300,
  "ml_confidence_threshold": 0.7,
  "active_model": "lr"
}
```

---

## Project Structure

```
AegisVault/
├── waf/
│   ├── waf.py                  # Main WAF reverse proxy (port 5000)
│   ├── dashboard.py            # Admin dashboard (port 5001)
│   ├── predictor.joblib        # SVM model
│   ├── predictor_lr.joblib     # Logistic Regression model
│   ├── predictor_rf.joblib     # Random Forest model
│   ├── waf_settings.json       # WAF configuration
│   ├── rules/                  # YAML rule definitions
│   └── plugins/                # Modular security plugins
├── backend/
│   └── app.py                  # Protected backend app (port 8000)
├── notebooks/
│   ├── MergeAndClean.ipynb
│   ├── TrainTestSplit.ipynb
│   ├── TrainSVM.ipynb
│   ├── TrainLR.ipynb
│   └── TrainRF.ipynb
├── data/
│   └── complete_clean.json     # Merged, cleaned dataset
└── requirements.txt
```

---

## API Endpoints

The dashboard exposes the following REST API on port 5001:

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/stats` | Real-time WAF statistics |
| GET | `/api/requests` | Paginated request logs with filtering |
| GET/POST | `/api/settings` | Read or update WAF settings |
| GET | `/api/blocked-ips` | List currently blocked IPs |
| POST | `/api/block-ip` | Block an IP address |
| POST | `/api/unblock-ip/<ip>` | Unblock an IP address |
| GET | `/api/rules` | Get all WAF rules |
| POST | `/api/rules` | Update all rules |
| POST | `/api/rule` | Add or edit an individual rule |
| DELETE | `/api/delete-rule/<rule_id>` | Delete a rule |
| GET | `/api/ml-models` | ML model information |
| GET | `/api/analytics` | Analytics data |

---

## Industry Standards

- **Version Control:** Git with structured `.gitignore`; Git LFS for large model artifacts
- **API Design:** RESTful endpoints with standard HTTP methods, JSON payloads, and semantic status codes
- **Security Coverage:** Aligned with OWASP Top 10 categories (SQLi, XSS, path traversal, command injection)
- **ML Deployment:** Offline training, joblib serialization, confidence-thresholded inference
- **Database:** Structured MongoDB logs with timestamps for auditing and analysis; fallback logging on DB unavailability
- **Reproducibility:** Shared `dataset.npz` split ensures all three models are evaluated on identical data partitions

---

## Conclusion

AegisVault demonstrates that combining layered conventional security with machine learning significantly improves both detection coverage and false positive rates compared to rule-only approaches. The key lesson from this project: production WAF performance depends heavily on benign sample diversity in training data. Dataset augmentation reduced false positives from 23% to under 3.2% while maintaining attack detection rates above 89% on real-world unseen traffic.

---

*CS245 - Machine Learning | National University of Sciences & Technology*
