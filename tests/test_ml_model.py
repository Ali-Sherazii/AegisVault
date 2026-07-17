"""ML classifier tests.

Skipped until a trained model exists under waf/ml_model/waf_text/ (there
currently isn't one in this checkout - see waf/Training/train.py). Once a
model is trained, these start running automatically and cover the payload
classes the rule engine doesn't (XSS, path-traversal, CMDi).
"""
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
MODEL_DIR = REPO_ROOT / "waf" / "ml_model" / "waf_text"
AVAILABLE_MODELS = sorted(MODEL_DIR.glob("predictor*.joblib")) if MODEL_DIR.exists() else []

pytestmark = pytest.mark.skipif(
    not AVAILABLE_MODELS,
    reason="no trained .joblib model in waf/ml_model/waf_text/ yet (run waf/Training/train.py)",
)

MALICIOUS_PAYLOADS = {
    "xss": "<script>alert(document.cookie)</script>",
    "path-traversal": "../../../../etc/passwd",
    "cmdi": "; cat /etc/passwd; ls -la",
}
BENIGN_PAYLOADS = [
    "hello world",
    "user@example.com",
    "/products?category=shoes&page=2",
]


@pytest.fixture
def predictor():
    waf_dir = REPO_ROOT / "waf"
    if str(waf_dir) not in sys.path:
        sys.path.insert(0, str(waf_dir))
    from ml_model.waf_text.predictor import WafPredictor
    return WafPredictor(str(AVAILABLE_MODELS[0]))


@pytest.mark.parametrize("attack_class,payload", MALICIOUS_PAYLOADS.items())
def test_known_attack_payloads_flagged(predictor, attack_class, payload):
    threats, _ = predictor.predict_request(payload, [], {})
    assert any(label != "valid" for label in threats), f"expected {attack_class} payload to be flagged: {payload!r}"


@pytest.mark.parametrize("payload", BENIGN_PAYLOADS)
def test_benign_payloads_not_flagged(predictor, payload):
    threats, _ = predictor.predict_request(payload, [], {})
    assert list(threats.keys()) == ["valid"], f"expected benign payload to pass: {payload!r}"
