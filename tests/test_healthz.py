"""Tests for the /healthz endpoints added for platform health probes
(Render, Docker Compose, Northflank, ...)."""


def test_waf_healthz_ok(waf_client):
    resp = waf_client.get("/healthz")
    assert resp.status_code == 200
    assert resp.get_json() == {"status": "ok"}


def test_waf_healthz_bypasses_rate_limit(waf_client):
    # conftest.py's waf_client fixture caps max_requests at 3; hitting
    # /healthz repeatedly from the same IP must never trip the rate limiter.
    ip = "10.2.0.1"
    for _ in range(10):
        resp = waf_client.get("/healthz", environ_overrides={"REMOTE_ADDR": ip})
        assert resp.status_code == 200


def test_dashboard_healthz_ok(dashboard_client):
    resp = dashboard_client.get("/healthz")
    assert resp.status_code == 200
    assert resp.get_json() == {"status": "ok"}
