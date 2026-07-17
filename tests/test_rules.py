"""Payload tests for the WAF's rule engine and plugin layer.

These exercise waf/rules/rules.yaml and waf/plugins/*.py as they exist today.
ML-based detection (the classifier catching XSS/path-traversal/CMDi payloads
that have no matching rule) is covered separately in test_ml_model.py, which
is skipped until a trained model is present.
"""


def test_sqli_literal_tautology_blocked(waf_client):
    # Matches rules.yaml rule id '1' (pattern "1=1")
    resp = waf_client.get("/products?id=1=1", environ_overrides={"REMOTE_ADDR": "10.0.0.1"})
    assert resp.status_code == 403


def test_sqli_union_select_blocked(waf_client):
    # Matches rules.yaml rule id 'block_sql_injection'
    resp = waf_client.get(
        "/products?q=' UNION SELECT username, password FROM users --",
        environ_overrides={"REMOTE_ADDR": "10.0.0.2"},
    )
    assert resp.status_code == 403


def test_api_php_scan_blocked(waf_client):
    # Matches rules.yaml rule id 'block_api_scan'
    resp = waf_client.get("/api/users", environ_overrides={"REMOTE_ADDR": "10.0.0.3"})
    assert resp.status_code == 403


def test_admin_path_blocked_by_plugin(waf_client):
    # No rule matches "/admin/config"; waf/plugins/block_admin.py should catch it
    resp = waf_client.get("/admin/config", environ_overrides={"REMOTE_ADDR": "10.0.0.4"})
    assert resp.status_code == 403


def test_sqlmap_user_agent_blocked_by_plugin(waf_client):
    # No rule matches "/search?q=hello"; waf/plugins/block_user_agent.py should catch the UA
    resp = waf_client.get(
        "/search?q=hello",
        headers={"User-Agent": "sqlmap/1.6"},
        environ_overrides={"REMOTE_ADDR": "10.0.0.5"},
    )
    assert resp.status_code == 403


def test_benign_request_allowed(waf_client):
    resp = waf_client.get(
        "/search?q=hello",
        headers={"User-Agent": "Mozilla/5.0"},
        environ_overrides={"REMOTE_ADDR": "10.0.0.6"},
    )
    assert resp.status_code == 200
