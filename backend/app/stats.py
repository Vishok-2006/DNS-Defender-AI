"""Dashboard aggregates (dialect-aware: SQLite for dev, PostgreSQL in production)."""
from __future__ import annotations

from datetime import datetime, timedelta
from typing import Dict, List

from sqlalchemy import distinct, func, select

from .models import BlockedDomain, DNSEvent, MLPrediction, SecurityAlert, utcnow
from .service import iso


def _hour(col, dialect: str):
    if dialect == "postgresql":
        return func.date_trunc("hour", col)
    return func.strftime("%Y-%m-%d %H:00:00", col)


def _to_dt(v) -> datetime:
    return v if isinstance(v, datetime) else datetime.strptime(v, "%Y-%m-%d %H:%M:%S")


def overview(s, hours: int = 24) -> Dict:
    since = utcnow() - timedelta(hours=hours)
    total = s.scalar(select(func.count()).select_from(DNSEvent).where(DNSEvent.timestamp >= since)) or 0
    clients = s.scalar(select(func.count(distinct(DNSEvent.src_ip))).where(DNSEvent.timestamp >= since)) or 0
    by_cls = dict(s.execute(select(MLPrediction.classification, func.count())
                            .where(MLPrediction.timestamp >= since).group_by(MLPrediction.classification)).all())
    open_alerts = s.scalar(select(func.count()).select_from(SecurityAlert)
                           .where(SecurityAlert.status.in_(("new", "investigating")))) or 0
    cats = dict(s.execute(select(SecurityAlert.category, func.count())
                          .where(SecurityAlert.created_at >= since).group_by(SecurityAlert.category)).all())
    return {
        "window_hours": hours,
        "total_queries": total,
        "unique_clients": clients,
        "malicious_queries": by_cls.get("malicious", 0),
        "suspicious_queries": by_cls.get("suspicious", 0),
        "open_alerts": open_alerts,
        "blocked_domains": s.scalar(select(func.count()).select_from(BlockedDomain)) or 0,
        "alert_categories": cats,
    }


def timeseries(s, hours: int = 24) -> List[Dict]:
    now = utcnow().replace(minute=0, second=0, microsecond=0)
    start = now - timedelta(hours=hours - 1)
    dialect = s.bind.dialect.name
    hq = _hour(DNSEvent.timestamp, dialect)
    q = dict((_to_dt(k), v) for k, v in s.execute(
        select(hq, func.count()).where(DNSEvent.timestamp >= start).group_by(hq)).all())
    hp = _hour(MLPrediction.timestamp, dialect)
    a = dict((_to_dt(k), v) for k, v in s.execute(
        select(hp, func.count()).where(MLPrediction.timestamp >= start,
                                       MLPrediction.classification != "benign").group_by(hp)).all())
    return [{"hour": iso(t), "queries": q.get(t, 0), "alerts": a.get(t, 0)}
            for t in (start + timedelta(hours=i) for i in range(hours))]


def top_domains(s, hours: int = 24, limit: int = 8) -> List[Dict]:
    since = utcnow() - timedelta(hours=hours)
    rows = s.execute(select(DNSEvent.domain, func.count().label("n")).where(DNSEvent.timestamp >= since)
                     .group_by(DNSEvent.domain).order_by(func.count().desc()).limit(limit)).all()
    return [{"domain": d, "count": n} for d, n in rows]
