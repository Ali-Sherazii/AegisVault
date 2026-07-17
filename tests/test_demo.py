"""Tests for the live decision-pipeline demo (waf/dashboard.py's /demo and
/api/demo-analyze), used for the hosted demo (see README's Live Demo section).
"""


def test_demo_page_renders(dashboard_client):
    resp = dashboard_client.get("/demo")
    assert resp.status_code == 200
    assert b"Live Decision Pipeline" in resp.data


def test_demo_analyze_requires_payload(dashboard_client):
    resp = dashboard_client.post("/api/demo-analyze", json={"payload": ""})
    assert resp.status_code == 400


def test_demo_analyze_sqli_caught_by_rules(dashboard_client):
    resp = dashboard_client.post("/api/demo-analyze", json={"payload": "id=1=1"})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["blocked"] is True
    assert data["layer"] == "rules"
    assert data["rule_id"] == "1"


def test_demo_analyze_benign_allowed(dashboard_client):
    resp = dashboard_client.post("/api/demo-analyze", json={"payload": "category=shoes&page=2"})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["blocked"] is False
    assert data["layer"] == "none"
