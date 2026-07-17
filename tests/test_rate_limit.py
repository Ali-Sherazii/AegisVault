"""Pipeline tests for rate limiting and IP blocking (waf/app.py's before_request)."""


def test_rate_limit_trips_after_n_requests(waf_client):
    ip = "10.1.0.1"
    headers = {"User-Agent": "Mozilla/5.0"}
    # tests/conftest.py's waf_client fixture sets max_requests=3 in the test settings.
    for _ in range(3):
        resp = waf_client.get("/search?q=hello", headers=headers, environ_overrides={"REMOTE_ADDR": ip})
        assert resp.status_code == 200

    # 4th request exceeds the window -> rate limit trips -> IP gets blocked
    resp = waf_client.get("/search?q=hello", headers=headers, environ_overrides={"REMOTE_ADDR": ip})
    assert resp.status_code == 429

    # IP is now blocked, so even a benign request short-circuits before rules/ML
    resp = waf_client.get("/search?q=hello", headers=headers, environ_overrides={"REMOTE_ADDR": ip})
    assert resp.status_code == 429


def test_blocked_ip_short_circuits_before_rules(waf_client):
    ip = "10.1.0.2"
    waf_client.application_module.mongo_logger.block_ip(ip, 60)

    resp = waf_client.get("/anything", environ_overrides={"REMOTE_ADDR": ip})
    assert resp.status_code == 429
