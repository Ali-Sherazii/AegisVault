"""Tests for the /api/model-health drift-monitoring endpoint (waf/dashboard.py).

The dashboard_client fixture lives in tests/conftest.py so test_demo.py can
reuse it too.
"""
from datetime import datetime, timezone


def test_compute_drift_unavailable_without_baseline_for_active_model():
    from monitoring.drift import compute_drift

    class _EmptyCollection:
        def find(self, *args, **kwargs):
            return []

    result = compute_drift(_EmptyCollection(), {}, "predictor_lr.joblib")
    assert result["available"] is False


def test_model_health_endpoint_returns_expected_shape(dashboard_client):
    resp = dashboard_client.get("/api/model-health")
    assert resp.status_code == 200
    data = resp.get_json()
    assert "drift" in data
    assert "active_model_file" in data
    assert isinstance(data["drift"]["available"], bool)


def test_model_health_computes_drift_once_baseline_and_logs_exist(dashboard_client):
    dashboard_module = dashboard_client.application_module
    active_file = dashboard_module._ACTIVE_MODEL_FILE

    from monitoring.drift import MODEL_FILE_TO_KEY
    model_key = MODEL_FILE_TO_KEY[active_file]
    baseline_stats = {
        model_key: {
            "confidence_histogram": [0, 0, 0, 0, 0, 0, 0, 0, 0, 50],
            "block_rate": 0.1,
        }
    }
    for i in range(20):
        dashboard_module.mongo_logger.collection.insert_one({
            "timestamp": datetime.now(timezone.utc),
            "blocked": i % 2 == 0,
            "ml_prediction": {"confidence_scores": {"valid" if i % 2 else "sqli": 0.95}},
        })

    import monitoring.drift as drift_module
    result = drift_module.compute_drift(dashboard_module.mongo_logger.collection, baseline_stats, active_file)
    assert result["available"] is True
    assert result["sample_size"] == 20
    assert 0.0 <= result["block_rate"] <= 1.0
    assert isinstance(result["psi"], float)
