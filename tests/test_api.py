import os
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select

from app.main import create_app
from app.models import DNSEvent, FeatureVector, MLPrediction, SecurityAlert, utcnow

DGA = {"domain": "xk910zp2a88q093.biz", "client_ip": "192.168.1.144"}


def test_health(client):                                          # basic liveness + model info
    h = client.get("/api/v1/health").json()
    assert h["status"] == "healthy" and h["model_loaded"] and h["database"] == "ok"


def test_tc01_rest_inference_returns_200_with_prediction(client):  # report TC-01
    r = client.post("/api/v1/dns/test-query", json=DGA)
    assert r.status_code == 200
    body = r.json()
    assert body["prediction"]["classification"] in ("suspicious", "malicious")
    assert 0 <= body["prediction"]["risk_score"] <= 1 and body["alert"]["domain"] == DGA["domain"]


def test_tc04_event_features_prediction_persisted(client):         # report TC-04
    client.post("/api/v1/dns/test-query", json=DGA)
    with client.app.state.session_factory() as s:
        assert s.scalar(select(func.count()).select_from(DNSEvent)) == 1
        fv = s.scalars(select(FeatureVector)).one()
        assert fv.domain_len == len(DGA["domain"]) and fv.entropy > 3 and "sld_lm_mean" in fv.features
        assert s.scalars(select(MLPrediction)).one().classification != "benign"


def test_benign_creates_no_alert(client):
    client.post("/api/v1/dns/test-query", json={"domain": "github.com"})
    assert client.get("/api/v1/alerts").json()["alerts"] == []


def test_repeat_queries_are_deduplicated_into_one_alert(client):
    for _ in range(3):
        client.post("/api/v1/dns/test-query", json=DGA)
    alerts = client.get("/api/v1/alerts").json()["alerts"]
    assert len(alerts) == 1 and alerts[0]["occurrences"] == 3


def test_input_validation(client):
    for bad in ({"domain": ""}, {"domain": "evil.com\nx"}, {"domain": "ok.com", "query_type": "BOGUS"},
                {"domain": "ok.com", "response_code": "NOPE"}, {}):
        assert client.post("/api/v1/dns/test-query", json=bad).status_code == 422


def test_block_unblock_writes_resolver_file(client):
    path = client.cfg.DNS_BLOCKLIST_PATH
    r = client.post("/api/v1/domains/block", json={"domain": "Evil.Example.COM", "reason": "test"})
    assert r.json() == {"success": True, "domain": "evil.example.com", "enforced": True}
    assert "server=/evil.example.com/" in open(path).read()
    assert client.get("/api/v1/domains/blocklist").json()["blocked_domains"][0]["domain"] == "evil.example.com"
    # queries to a blocked domain (or its subdomains) are marked blocked
    q = client.post("/api/v1/dns/test-query", json={"domain": "sub.evil.example.com"}).json()["query"]
    assert q["blocked"] is True
    assert client.post("/api/v1/domains/unblock", json={"domain": "evil.example.com"}).status_code == 200
    assert "evil.example.com" not in open(path).read()
    assert client.post("/api/v1/domains/unblock", json={"domain": "evil.example.com"}).status_code == 404


def test_cannot_block_trusted_or_allowlisted(client):
    assert client.post("/api/v1/domains/block", json={"domain": "google.com"}).status_code == 409
    client.post("/api/v1/domains/allowlist", json={"domain": "mycorp.example"})
    assert client.post("/api/v1/domains/block", json={"domain": "intranet.mycorp.example"}).status_code == 409


def test_allowlist_overrides_detection_and_closes_alerts(client):
    client.post("/api/v1/dns/test-query", json=DGA)
    client.post("/api/v1/domains/allowlist", json={"domain": DGA["domain"], "reason": "fp"})
    assert client.get("/api/v1/alerts").json()["alerts"][0]["status"] == "false_positive"
    r = client.post("/api/v1/dns/test-query", json=DGA).json()
    assert r["prediction"]["classification"] == "benign" and r["alert"] is None
    assert client.post("/api/v1/domains/allowlist/remove", json={"domain": DGA["domain"]}).status_code == 200


def test_state_survives_restart(cfg):
    with TestClient(create_app(cfg)) as c1:
        c1.post("/api/v1/domains/block", json={"domain": "persist.example"})
    os.remove(cfg.DNS_BLOCKLIST_PATH)          # simulate lost resolver file
    with TestClient(create_app(cfg)) as c2:
        assert "server=/persist.example/" in open(cfg.DNS_BLOCKLIST_PATH).read()   # rebuilt from DB
        assert c2.get("/api/v1/domains/blocklist").json()["blocked_domains"][0]["domain"] == "persist.example"


def test_alert_triage_and_explanation(client):
    aid = client.post("/api/v1/dns/test-query", json=DGA).json()["alert"]["id"]
    r = client.patch(f"/api/v1/alerts/{aid}", json={"status": "investigating", "analyst_notes": "looking"})
    assert r.json()["status"] == "investigating" and r.json()["analyst_notes"] == "looking"
    assert client.patch(f"/api/v1/alerts/{aid}", json={"status": "bogus"}).status_code == 422
    exp = client.post(f"/api/v1/alerts/{aid}/analyze").json()      # no API key -> offline explanation
    assert exp["provider"] == "local_rules" and exp["recommendations"]
    assert client.get(f"/api/v1/alerts/{aid}").json()["analysis"]["provider"] == "local_rules"
    assert client.get("/api/v1/alerts/doesnotexist").status_code == 404


def test_simulated_dga_burst_triggers_nxdomain_burst_rule(client):
    r = client.post("/api/v1/dns/simulate", json={"scenario": "dga_burst"}).json()
    assert r["queries"] == 14 and r["alerts"] >= 5
    cats = {a["category"] for a in client.get("/api/v1/alerts?limit=100").json()["alerts"]}
    assert any("DGA" in c or "NXDOMAIN" in c for c in cats)


def test_simulated_benign_traffic_raises_no_alerts(client):
    assert client.post("/api/v1/dns/simulate", json={"scenario": "benign"}).json()["alerts"] == 0
    assert client.post("/api/v1/dns/simulate", json={"scenario": "nope"}).status_code == 422


def test_stats_queries_and_csv(client):
    client.post("/api/v1/dns/simulate", json={"scenario": "benign"})
    client.post("/api/v1/dns/test-query", json=DGA)
    st = client.get("/api/v1/stats").json()
    assert st["total_queries"] == 6 and st["open_alerts"] == 1 and len(st["timeseries"]) == 24
    assert sum(p["queries"] for p in st["timeseries"]) == 6 and st["top_domains"]
    ql = client.get("/api/v1/queries?classification=malicious").json()["queries"]
    assert all(q["classification"] == "malicious" for q in ql)
    assert len(client.get("/api/v1/queries?search=github").json()["queries"]) == 1
    csv_text = client.get("/api/v1/reports/alerts.csv").text
    assert csv_text.splitlines()[0].startswith("created_at,domain") and DGA["domain"] in csv_text


def test_zeek_import_endpoint(client):
    tsv = ("#fields\tts\tid.orig_h\tquery\tqtype_name\trcode_name\n"
           "1.0\t10.0.0.3\txk910zp2a88q093.biz\tA\tNXDOMAIN\n1.0\t10.0.0.3\tgithub.com\tA\tNOERROR\n")
    r = client.post("/api/v1/import/zeek", content=tsv, headers={"content-type": "text/plain"}).json()
    assert r["imported"] == 2 and r["alerts"] == 1


def test_tc02_websocket_pushes_alert_instantly(client):            # report TC-02
    with client.websocket_connect("/ws/alerts") as ws:
        client.post("/api/v1/dns/test-query", json={"domain": "github.com"})   # benign -> no alert push
        client.post("/api/v1/dns/test-query", json=DGA)
        msg = ws.receive_json()
    assert msg["event"] == "alert" and msg["data"]["domain"] == DGA["domain"]


def test_traffic_websocket_streams_every_query(client):
    with client.websocket_connect("/ws/traffic") as ws:
        client.post("/api/v1/dns/test-query", json={"domain": "github.com"})
        assert ws.receive_json()["data"]["domain"] == "github.com"


def test_auto_block_only_when_policy_allows(client):
    big = {"domain": "qwzxvbnmkjhgfd.top"}
    client.post("/api/v1/dns/test-query", json=big)                          # alert-only by default
    assert client.get("/api/v1/domains/blocklist").json()["blocked_domains"] == []
    s = client.patch("/api/v1/settings", json={"alert_only_mode": False, "auto_block_confirmed": True}).json()
    assert s["alert_only_mode"] is False
    client.post("/api/v1/dns/test-query", json={"domain": "qwzxvbnmkjhgfd.top", "client_ip": "10.9.9.9"})
    blocked = client.get("/api/v1/domains/blocklist").json()["blocked_domains"]
    assert blocked and blocked[0]["source"] == "auto"
    assert client.patch("/api/v1/settings", json={"evil": 1}).status_code == 422


def test_retention_prunes_old_events_but_keeps_alerts(client):
    client.post("/api/v1/dns/test-query", json=DGA)
    svc = client.app.state.service
    with client.app.state.session_factory() as s:
        old = utcnow() - timedelta(days=30)
        for ev in s.scalars(select(DNSEvent)):
            ev.timestamp = old
        for p in s.scalars(select(MLPrediction)):
            p.timestamp = old
        s.commit()
    assert svc.prune(7) == 1
    with client.app.state.session_factory() as s:
        assert s.scalar(select(func.count()).select_from(DNSEvent)) == 0
        assert s.scalar(select(func.count()).select_from(FeatureVector)) == 0
        assert s.scalar(select(func.count()).select_from(SecurityAlert)) == 1   # alert history preserved


def test_api_key_protects_everything_but_health(cfg):
    cfg.API_KEY = "s3cret"
    with TestClient(create_app(cfg)) as c:
        assert c.get("/api/v1/health").status_code == 200
        assert c.get("/api/v1/stats").status_code == 401
        assert c.post("/api/v1/domains/block", json={"domain": "x.example"}).status_code == 401
        assert c.get("/api/v1/stats", headers={"x-api-key": "wrong"}).status_code == 401
        assert c.get("/api/v1/stats", headers={"x-api-key": "s3cret"}).status_code == 200
        with pytest.raises(Exception):
            with c.websocket_connect("/ws/alerts"):
                pass
        with c.websocket_connect("/ws/alerts?api_key=s3cret"):
            pass
