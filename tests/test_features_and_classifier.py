import time

import pytest

from app.classifier import Detector, is_trusted, noisy_or
from app.config import BACKEND_DIR
from app.features import (BehaviourTracker, ClientNXTracker, MODEL_FEATURES, lexical_features,
                          shannon_entropy, split_domain)

MODEL = str(BACKEND_DIR / "models" / "dga_rf.joblib")


@pytest.fixture(scope="module")
def det():
    d = Detector(MODEL)
    assert d.model_loaded, "trained model must ship with the backend"
    return d


# ------------------------------------------------------------------ features
def test_entropy_values():
    assert shannon_entropy("") == 0
    assert shannon_entropy("aaaa") == 0
    assert shannon_entropy("abcd") == pytest.approx(2.0)


def test_split_uses_private_suffixes():
    sub, sld, suffix = split_domain("cvyh1po636avyrsxebwbkn7.ddns.net")
    assert sld == "cvyh1po636avyrsxebwbkn7" and suffix == "ddns.net"
    assert split_domain("www.bbc.co.uk") == ("www", "bbc", "co.uk")


def test_lexical_vector_is_complete_and_deterministic(det):
    f = lexical_features("a8f9c1b3e204.exfil-tunnel.co", det.lm)
    assert list(f) == MODEL_FEATURES
    assert f == lexical_features("a8f9c1b3e204.exfil-tunnel.co", det.lm)
    assert f["subdomain_count"] == 1 and f["sld_hyphen_ratio"] > 0


def test_behaviour_tracker_rates_and_ratios():
    t = BehaviourTracker()
    b = {}
    for i in range(6):
        b = t.observe("x.example", "10.0.0.1", "TXT", is_nxdomain=i % 2 == 0, now=1000.0 + i * 10)
    assert b["domain_frequency"] == 6 and b["unique_client_count"] == 1
    assert b["txt_query_ratio"] == 1.0 and b["nxdomain_ratio"] == 0.5
    assert b["beaconing"] == 1.0          # perfectly regular 10 s interval


def test_irregular_queries_are_not_beaconing():
    t = BehaviourTracker()
    for ts in (0, 1, 9, 10, 31, 33):
        b = t.observe("y.example", "c", now=float(ts))
    assert b["beaconing"] == 0.0


def test_client_nx_burst_counts_distinct_domains():
    t = ClientNXTracker()
    for i in range(12):
        r = t.observe("10.0.0.9", f"d{i}.biz", True, now=100.0 + i)
    assert r["client_nxdomain_60s"] == 12
    assert t.observe("10.0.0.9", "d1.biz", True, now=500.0)["client_nxdomain_60s"] == 1   # window expired


# ---------------------------------------------------------------- classifier
@pytest.mark.parametrize("domain", ["google.com", "github.com", "docs.python.org", "wikipedia.org",
                                    "stackoverflow.com", "www.amazon.com", "mail.example-shop.com"])
def test_common_benign_domains_are_not_flagged(det, domain):
    assert det.assess(domain)["classification"] == "benign"


@pytest.mark.parametrize("domain", ["xk910zp2a88q093.biz", "qwzxvbnmkjhgfd.top",
                                    "cvyh1po636avyrsxebwbkn7.ddns.net"])
def test_obvious_dga_domains_are_flagged(det, domain):
    a = det.assess(domain)
    assert a["classification"] in ("suspicious", "malicious")
    assert "DGA" in a["category"]


def test_cdn_hash_names_are_not_false_positives(det):
    for d in ("e1234abcd.a.akamaiedge.net", "d3k2jx9a8zq1.cloudfront.net", "ab12cd34ef56.s3.amazonaws.com"):
        assert is_trusted(d) and det.assess(d)["classification"] == "benign"


def test_tunnelling_detected_even_on_unknown_model_input(det):
    a = det.assess("a8f9c1b3e204d80a11f592c900.stage1.exfil-tunnel.co")
    assert a["classification"] != "benign" and "Tunnelling" in a["category"]
    long_label = "a" * 45 + ".evil.example"
    assert det.assess(long_label)["category"].startswith("DNS Tunnelling")


def test_phishing_style_name(det):
    a = det.assess("login-verify-secure-account-update.xyz")
    assert a["classification"] != "benign" and "Phishing" in a["category"]


def test_nxdomain_burst_raises_risk(det):
    base = det.assess("zzz-plain-name.com", {}, False)["risk_score"]
    burst = det.assess("zzz-plain-name.com", {"client_nxdomain_60s": 30}, True)
    assert burst["risk_score"] > base and burst["classification"] == "malicious"


def test_beaconing_alone_is_not_enough(det):
    assert det.assess("time.nist.gov", {"beaconing": 1.0})["classification"] == "benign"


def test_noisy_or():
    assert noisy_or([]) == 0
    assert noisy_or([0.5, 0.5]) == pytest.approx(0.75)


def test_fallback_mode_when_model_missing(tmp_path):
    d = Detector(str(tmp_path / "missing.joblib"))
    assert not d.model_loaded
    assert d.assess("xk910zp2a88q093zzqx.biz")["classification"] != "benign"
    assert d.assess("google.com")["classification"] == "benign"


def test_corrupt_model_does_not_crash(tmp_path):
    bad = tmp_path / "bad.joblib"
    bad.write_bytes(b"not a model")
    assert not Detector(str(bad)).model_loaded


def test_inference_latency_under_report_limit(det):
    det.assess("warmup.com")
    t = time.perf_counter()
    for _ in range(100):
        det.assess("xk910zp2a88q093.biz")
    assert (time.perf_counter() - t) / 100 < 0.050   # NFR: < 50 ms per query


def test_tc05_random_forest_model_loads_without_error():            # report TC-05
    import json
    import joblib
    from sklearn.ensemble import RandomForestClassifier
    bundle = joblib.load(MODEL)                                       # raises on any serialization error
    assert isinstance(bundle["model"], RandomForestClassifier) and bundle["features"] == MODEL_FEATURES
    card = json.load(open(MODEL.replace("dga_rf.joblib", "model_card.json")))
    assert card["quick_mode"] is False and card["dataset"]["rows_used"] > 600_000   # production, not a smoke model
    assert card["A_random_split_test"]["at_0.5"]["roc_auc"] > 0.95
