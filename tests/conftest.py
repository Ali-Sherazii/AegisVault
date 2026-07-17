import json
import sys
from pathlib import Path
from types import SimpleNamespace

import mongomock
import pymongo
import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
WAF_DIR = REPO_ROOT / "waf"

# waf/app.py and its siblings (rules, database, plugins, ml_model, proxy) use
# imports that assume the `waf/` directory itself is on sys.path (that's how
# they resolve when run as `python waf/app.py`). Replicate that for tests.
if str(WAF_DIR) not in sys.path:
    sys.path.insert(0, str(WAF_DIR))

# waf/app.py, waf/proxy.py, and MongoLogger all talk to MongoDB at import
# time. Point pymongo at an in-memory mongomock client so this suite never
# needs a real MongoDB instance (there isn't one in CI or in this checkout).
pymongo.MongoClient = mongomock.MongoClient


def _fake_backend_request(method, url, **kwargs):
    return SimpleNamespace(content=b"OK", status_code=200, headers={})


@pytest.fixture
def waf_client(monkeypatch, tmp_path):
    """Flask test client for the live WAF proxy (waf/app.py).

    Each test gets a disposable waf_settings.json (so tests never touch the
    real project settings file) and a stubbed backend call (so "allowed"
    requests don't need a live backend_app running on :8000).
    """
    settings_file = tmp_path / "waf_settings.json"
    settings_file.write_text(json.dumps({
        "rate_limiting": {"enabled": True, "max_requests": 3, "window_seconds": 60, "block_time": 5},
        "ml_model": {"enabled": True, "confidence_threshold": 0.7},
        "plugins": {"block_admin": True, "block_ip": True, "block_user_agent": True},
        "rules": {"enabled": True, "auto_update": False},
    }))
    monkeypatch.setenv("WAF_SETTINGS_FILE", str(settings_file))
    monkeypatch.setenv("MONGODB_URI", "mongodb://localhost:27017")

    sys.modules.pop("app", None)
    import app as waf_app_module  # noqa: this is waf/app.py, importable via sys.path above

    import proxy as proxy_module
    monkeypatch.setattr(proxy_module.requests, "request", _fake_backend_request)

    waf_app_module.app.config.update(TESTING=True)
    with waf_app_module.app.test_client() as client:
        client.application_module = waf_app_module
        yield client
