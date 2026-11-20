"""DNS Defender AI - FastAPI application (REST + WebSocket)."""
from __future__ import annotations

import asyncio
import csv
import io
import logging
import random
import string
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import Depends, FastAPI, HTTPException, Query, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse, Response
from sqlalchemy import select, text

from . import stats
from .blocking import BlocklistFile
from .classifier import TRUSTED_ROOTS, Detector
from .config import Settings, settings as default_settings
from .db import init_db, make_engine, make_session_factory
from .hub import EventHub
from .ingest import ScapySniffer, parse_zeek_dns_log
from .models import AllowlistedDomain, BlockedDomain, DNSEvent, MLPrediction, SecurityAlert, utcnow
from .monitor import DnsmasqTailer
from .nim import NimClient
from .schemas import AlertPatch, DomainIn, QueryIn, SettingsPatch, SimulateIn
from .security import make_api_key_dependency, ws_authorized
from .service import DefenderService, DomainPolicyError, iso

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("defender")

SIM_CLIENT = "192.168.1.144"


def _simulate(scenario: str) -> list:
    rnd = random.Random()
    if scenario == "dga_burst":   # a bot cycling through generated names that do not exist
        tlds = [".biz", ".info", ".top", ".cc", ".su", ".xyz"]
        return [dict(domain="".join(rnd.choices(string.ascii_lowercase + string.digits, k=rnd.randint(11, 16)))
                     + tlds[i % len(tlds)], client_ip=SIM_CLIENT, response_code="NXDOMAIN") for i in range(14)]
    if scenario == "tunnelling":
        return [dict(domain="".join(rnd.choices("0123456789abcdef", k=44)) + f".s{i}.exfil-tunnel.co",
                     client_ip="192.168.1.180", query_type="TXT") for i in range(4)]
    if scenario == "phishing":
        return [dict(domain=d, client_ip="192.168.1.105") for d in
                ("login-verify-secure-account-update.xyz", "paypal-account-suspend-confirm-login.top")]
    return [dict(domain=d, client_ip="192.168.1.102") for d in
            ("github.com", "docs.python.org", "wikipedia.org", "npmjs.com", "stackoverflow.com")]


def create_app(cfg: Optional[Settings] = None) -> FastAPI:
    cfg = cfg or default_settings
    engine = make_engine(cfg.DATABASE_URL)
    session_factory = make_session_factory(engine)
    hub = EventHub()
    detector = Detector(cfg.ML_MODEL_PATH, cfg.SUSPICIOUS_THRESHOLD, cfg.MALICIOUS_THRESHOLD)
    service = DefenderService(detector, session_factory, BlocklistFile(cfg.DNS_BLOCKLIST_PATH), hub,
                              cfg.ALERT_ONLY_MODE, cfg.AUTO_BLOCK_CONFIRMED, cfg.AUTO_BLOCK_MIN_RISK)
    nim = NimClient(cfg.NVIDIA_API_KEY, cfg.NVIDIA_MODEL, cfg.NVIDIA_BASE_URL)
    tailer_ref = {"tailer": None, "sniffer": None}

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        init_db(engine)
        service.load_state()
        hub.bind(asyncio.get_running_loop())
        tasks = []
        if cfg.CAPTURE_MODE == "dnsmasq":
            async def handle(batch):
                await asyncio.to_thread(service.process_batch, batch)
            tailer = DnsmasqTailer(cfg.DNSMASQ_LOG_PATH, handle, cfg.MONITOR_IGNORE_LOCALHOST)
            tailer_ref["tailer"] = tailer
            tasks.append(asyncio.create_task(tailer.run()))
        elif cfg.CAPTURE_MODE == "scapy":
            sniffer = ScapySniffer(service.process_query_dict, cfg.SCAPY_INTERFACE)
            tailer_ref["sniffer"] = sniffer
            sniffer.start()

        async def retention():
            while True:
                try:
                    await asyncio.to_thread(service.prune, cfg.RETENTION_DAYS)
                except Exception:
                    log.exception("retention failed")
                await asyncio.sleep(3600)
        tasks.append(asyncio.create_task(retention()))
        log.info("DNS Defender AI %s started (capture=%s, model_loaded=%s)",
                 cfg.VERSION, cfg.CAPTURE_MODE, detector.model_loaded)
        yield
        for t in tasks:
            t.cancel()
        if tailer_ref["sniffer"]:
            tailer_ref["sniffer"].stop()
        engine.dispose()

    app = FastAPI(title=cfg.PROJECT_NAME, version=cfg.VERSION, lifespan=lifespan,
                  description="AI-powered DNS behaviour analysis for malicious domain detection")
    app.state.service, app.state.session_factory, app.state.cfg = service, session_factory, cfg
    app.add_middleware(CORSMiddleware, allow_origins=[o.strip() for o in cfg.CORS_ORIGINS.split(",") if o.strip()],
                       allow_methods=["*"], allow_headers=["*"])
    auth = [Depends(make_api_key_dependency(cfg.API_KEY))]

    def db():
        with session_factory() as s:
            yield s

    # service helper for the scapy thread
    service.process_query_dict = lambda q: service.process_batch([q])

    # ------------------------------------------------------------------ health
    @app.get("/api/v1/health")
    def health():
        try:
            with session_factory() as s:
                s.execute(text("SELECT 1"))
            db_ok = True
        except Exception:
            db_ok = False
        t = tailer_ref["tailer"]
        return {"status": "healthy" if db_ok else "degraded", "timestamp": iso(utcnow()),
                "service": cfg.PROJECT_NAME, "version": cfg.VERSION, "database": "ok" if db_ok else "error",
                "model_loaded": detector.model_loaded, "model_version": detector.model_version,
                "thresholds": {"suspicious": detector.thr_suspicious, "malicious": detector.thr_malicious},
                "capture_mode": cfg.CAPTURE_MODE,
                "monitor": ({"running": t.running, "queries_processed": t.queries_processed,
                             "last_error": t.last_error} if t else None),
                "llm_configured": nim.configured, "auth_required": bool(cfg.API_KEY)}

    # ------------------------------------------------------------- dashboards
    @app.get("/api/v1/stats", dependencies=auth)
    def get_stats(hours: int = Query(24, ge=1, le=168), s=Depends(db)):
        return {**stats.overview(s, hours), "timeseries": stats.timeseries(s, min(hours, 48)),
                "top_domains": stats.top_domains(s, hours)}

    @app.get("/api/v1/queries", dependencies=auth)
    def list_queries(limit: int = Query(50, ge=1, le=500), search: str = "", classification: str = "all",
                     s=Depends(db)):
        q = (select(DNSEvent, MLPrediction).join(MLPrediction, MLPrediction.event_id == DNSEvent.id)
             .order_by(DNSEvent.timestamp.desc()).limit(limit))
        if classification != "all":
            q = q.where(MLPrediction.classification == classification)
        if search:
            like = f"%{search.lower()}%"
            q = q.where(DNSEvent.domain.like(like) | DNSEvent.src_ip.like(like))
        rows = s.execute(q).all()
        return {"queries": [{"id": e.id, "timestamp": iso(e.timestamp), "domain": e.domain, "client_ip": e.src_ip,
                             "query_type": e.query_type, "response_code": e.response_code, "source": e.source,
                             "classification": p.classification, "risk_score": p.risk_score,
                             "category": p.category, "blocked": e.blocked} for e, p in rows]}

    @app.post("/api/v1/dns/test-query", dependencies=auth)
    def test_query(body: QueryIn):
        return service.process_query(body.domain, body.client_ip, body.query_type, body.response_code, "api")

    @app.post("/api/v1/dns/simulate", dependencies=auth)
    def simulate(body: SimulateIn):
        res = service.process_batch([{**q, "source": "simulation"} for q in _simulate(body.scenario)])
        return {"scenario": body.scenario, "queries": len(res), "alerts": sum(1 for r in res if r["alert"])}

    @app.post("/api/v1/import/zeek", dependencies=auth)
    async def import_zeek(request: Request):
        raw = await request.body()
        if len(raw) > 20_000_000:
            raise HTTPException(413, "File too large")
        rows = parse_zeek_dns_log(raw.decode(errors="replace"))
        res = await asyncio.to_thread(service.process_batch, rows)
        return {"imported": len(res), "alerts": sum(1 for r in res if r["alert"])}

    # ------------------------------------------------------------------ alerts
    @app.get("/api/v1/alerts", dependencies=auth)
    def list_alerts(limit: int = Query(50, ge=1, le=500), severity: str = "all", status: str = "all",
                    s=Depends(db)):
        q = select(SecurityAlert).order_by(SecurityAlert.last_seen.desc()).limit(limit)
        if severity != "all":
            q = q.where(SecurityAlert.severity == severity)
        if status != "all":
            q = q.where(SecurityAlert.status == status)
        return {"alerts": [service.alert_to_dict(a) for a in s.scalars(q)]}

    def _alert_or_404(s, alert_id):
        al = s.get(SecurityAlert, alert_id)
        if not al:
            raise HTTPException(404, "Alert not found")
        return al

    @app.get("/api/v1/alerts/{alert_id}", dependencies=auth)
    def get_alert(alert_id: str, s=Depends(db)):
        return service.alert_to_dict(_alert_or_404(s, alert_id))

    @app.patch("/api/v1/alerts/{alert_id}", dependencies=auth)
    def patch_alert(alert_id: str, body: AlertPatch, s=Depends(db)):
        al = _alert_or_404(s, alert_id)
        if body.status is not None:
            al.status = body.status
        if body.analyst_notes is not None:
            al.analyst_notes = body.analyst_notes
        s.commit()
        return service.alert_to_dict(al)

    @app.post("/api/v1/alerts/{alert_id}/analyze", dependencies=auth)
    async def analyze_alert(alert_id: str):
        with session_factory() as s:
            data = service.alert_to_dict(_alert_or_404(s, alert_id))
        result = await nim.explain(data)
        with session_factory() as s:
            al = _alert_or_404(s, alert_id)
            al.analysis = result
            s.commit()
        return result

    # ----------------------------------------------------------------- domains
    @app.get("/api/v1/domains/blocklist", dependencies=auth)
    def blocklist(s=Depends(db)):
        return {"blocked_domains": [{"domain": b.domain, "reason": b.reason, "source": b.source,
                                     "blocked_at": iso(b.blocked_at)} for b in
                                    s.scalars(select(BlockedDomain).order_by(BlockedDomain.blocked_at.desc()))]}

    def _policy(fn, *a):
        try:
            return fn(*a)
        except DomainPolicyError as exc:
            raise HTTPException(409, str(exc))

    @app.post("/api/v1/domains/block", dependencies=auth)
    def block(body: DomainIn):
        return {"success": True, **_policy(service.block_domain, body.domain, body.reason or "Manual block")}

    @app.post("/api/v1/domains/unblock", dependencies=auth)
    def unblock(body: DomainIn):
        if not _policy(service.unblock_domain, body.domain):
            raise HTTPException(404, "Domain is not blocked")
        return {"success": True, "domain": body.domain}

    @app.get("/api/v1/domains/allowlist", dependencies=auth)
    def allowlist(s=Depends(db)):
        return {"allowlisted_domains": [{"domain": a.domain, "reason": a.reason, "added_at": iso(a.added_at)}
                                        for a in s.scalars(select(AllowlistedDomain))],
                "trusted_infrastructure": list(TRUSTED_ROOTS)}

    @app.post("/api/v1/domains/allowlist", dependencies=auth)
    def allow(body: DomainIn):
        return {"success": True, **_policy(service.allow_domain, body.domain, body.reason or "Manual exemption")}

    @app.post("/api/v1/domains/allowlist/remove", dependencies=auth)
    def allow_remove(body: DomainIn):
        if not _policy(service.remove_allow, body.domain):
            raise HTTPException(404, "Domain is not on the allowlist")
        return {"success": True}

    # ---------------------------------------------------------------- settings
    def _settings_view():
        return {"alert_only_mode": service.alert_only, "auto_block_confirmed": service.auto_block,
                "auto_block_min_risk": service.auto_block_min_risk, "retention_days": cfg.RETENTION_DAYS,
                "thresholds": {"suspicious": detector.thr_suspicious, "malicious": detector.thr_malicious}}

    @app.get("/api/v1/settings", dependencies=auth)
    def get_settings():
        return _settings_view()

    @app.patch("/api/v1/settings", dependencies=auth)
    def patch_settings(body: SettingsPatch):
        if body.alert_only_mode is not None:
            service.alert_only = body.alert_only_mode
        if body.auto_block_confirmed is not None:
            service.auto_block = body.auto_block_confirmed
        return _settings_view()   # runtime only; restart restores the environment defaults

    # ----------------------------------------------------------------- reports
    @app.get("/api/v1/reports/alerts.csv", dependencies=auth)
    def alerts_csv(s=Depends(db)):
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["created_at", "domain", "client_ip", "category", "classification", "severity",
                    "risk_score", "status", "occurrences", "blocked"])
        for a in s.scalars(select(SecurityAlert).order_by(SecurityAlert.created_at.desc()).limit(5000)):
            w.writerow([iso(a.created_at), a.domain, a.client_ip, a.category, a.classification, a.severity,
                        a.risk_score, a.status, a.occurrences, a.blocked])
        return Response(buf.getvalue(), media_type="text/csv",
                        headers={"Content-Disposition": "attachment; filename=dns-defender-alerts.csv"})

    # --------------------------------------------------------------- websockets
    async def _ws(channel: str, ws: WebSocket):
        if not ws_authorized(cfg.API_KEY, ws.query_params.get("api_key")):
            await ws.close(code=4401)
            return
        await hub.connect(channel, ws)
        try:
            while True:
                await ws.receive_text()   # keep-alive pings from the client
        except WebSocketDisconnect:
            pass
        finally:
            hub.disconnect(channel, ws)

    @app.websocket("/ws/alerts")
    async def ws_alerts(ws: WebSocket):
        await _ws("alerts", ws)

    @app.websocket("/ws/traffic")
    async def ws_traffic(ws: WebSocket):
        await _ws("traffic", ws)

    return app


app = create_app()
