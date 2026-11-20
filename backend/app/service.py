"""Core pipeline: query -> features -> detection -> persistence -> alert -> response policy."""
from __future__ import annotations

import logging
import threading
import time
from datetime import timedelta
from typing import Any, Dict, Iterable, List, Optional, Set

from sqlalchemy import delete, select, update

from .blocking import BlocklistFile, valid_domain
from .classifier import Detector, is_trusted
from .features import BehaviourTracker, ClientNXTracker, normalize
from .hub import EventHub
from .models import (AllowlistedDomain, BlockedDomain, DNSEvent, FeatureVector,
                     MLPrediction, SecurityAlert, new_id, utcnow)

log = logging.getLogger("defender.service")
ALERT_DEDUPE_MINUTES = 10


def iso(dt) -> Optional[str]:
    return dt.isoformat(timespec="seconds") + "Z" if dt else None


def _matches(domain: str, names: Set[str]) -> bool:
    """True if domain or any parent domain is in names."""
    parts = domain.split(".")
    return any(".".join(parts[i:]) in names for i in range(len(parts)))


class DomainPolicyError(ValueError):
    pass


class DefenderService:
    def __init__(self, detector: Detector, session_factory, blocklist: BlocklistFile, hub: EventHub,
                 alert_only: bool = True, auto_block: bool = False, auto_block_min_risk: float = 0.95):
        self.detector = detector
        self.session_factory = session_factory
        self.blocklist = blocklist
        self.hub = hub
        self.alert_only = alert_only
        self.auto_block = auto_block
        self.auto_block_min_risk = auto_block_min_risk
        self._lock = threading.Lock()   # guards trackers and the in-memory caches
        self.behaviour = BehaviourTracker()
        self.client_nx = ClientNXTracker()
        self.allow: Set[str] = set()
        self.blocked: Set[str] = set()

    # ------------------------------------------------------------------ state
    def load_state(self) -> None:
        with self.session_factory() as s:
            self.blocked = set(s.scalars(select(BlockedDomain.domain)))
            self.allow = set(s.scalars(select(AllowlistedDomain.domain)))
        self.blocklist.write(self.blocked)  # DB is the source of truth for the resolver file

    # --------------------------------------------------------------- pipeline
    def process_query(self, domain: str, client_ip: str = "0.0.0.0", query_type: str = "A",
                      response_code: str = "NOERROR", source: str = "api") -> Dict[str, Any]:
        return self.process_batch([dict(domain=domain, client_ip=client_ip, query_type=query_type,
                                        response_code=response_code, source=source)])[0]

    def process_batch(self, items: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
        results, published, auto_blocks = [], [], []
        with self.session_factory() as s:
            for it in items:
                res = self._process(s, it, auto_blocks)
                results.append(res)
                published.append(res)
            s.commit()
        for res in published:
            self.hub.publish("traffic", {"event": "dns_query", "data": res["query"]})
            if res.get("alert"):
                self.hub.publish("alerts", {"event": "alert", "data": res["alert"]})
        for domain, reason in auto_blocks:      # after commit: avoids nested writers on SQLite
            try:
                self.block_domain(domain, reason, source="auto")
            except DomainPolicyError:
                pass
        return results

    def _process(self, s, it: Dict[str, Any], auto_blocks: list) -> Dict[str, Any]:
        domain = normalize(it["domain"])
        client = it.get("client_ip") or "0.0.0.0"
        qtype = (it.get("query_type") or "A").upper()
        rcode = (it.get("response_code") or "NOERROR").upper()
        is_nx = rcode == "NXDOMAIN"
        with self._lock:
            behaviour = self.behaviour.observe(domain, client, qtype, is_nx)
            behaviour.update(self.client_nx.observe(client, domain, is_nx))
            allowlisted = _matches(domain, self.allow)
            blocked = _matches(domain, self.blocked)

        a = self.detector.assess(domain, behaviour, is_nx)
        if allowlisted:  # explicit administrator decision wins
            a.update(classification="benign", is_malicious=False, category="Benign", severity="low",
                     reasons=["Domain is on the administrator allowlist."])

        now = utcnow()
        feats = {**a["lexical_features"], **behaviour}
        ev = DNSEvent(timestamp=now, src_ip=client, domain=domain, query_type=qtype,
                      response_code=rcode, source=it.get("source", "api"), blocked=blocked)
        s.add(ev)
        s.flush()
        s.add(FeatureVector(event_id=ev.id, entropy=a["lexical_features"]["sld_entropy"],
                            digit_ratio=a["lexical_features"]["sld_digit_ratio"],
                            domain_len=int(a["lexical_features"]["domain_length"]), features=feats))
        pred = MLPrediction(event_id=ev.id, risk_score=a["risk_score"], is_malicious=a["is_malicious"],
                            classification=a["classification"], category=a["category"],
                            model_prob=a["model_prob"], rule_score=a["rule_score"],
                            model_ver=a["model_version"], timestamp=now)
        s.add(pred)
        s.flush()

        alert_dict = None
        if a["classification"] != "benign":
            alert = self._upsert_alert(s, pred, domain, client, a, blocked, now)
            alert_dict = self.alert_to_dict(alert)
            if (not self.alert_only and self.auto_block and a["classification"] == "malicious"
                    and a["risk_score"] >= self.auto_block_min_risk and not blocked
                    and not a["trusted_infrastructure"]):
                auto_blocks.append((domain, f"Automatic block: {a['category']} (risk {a['risk_score']:.0%})"))

        query = {"id": ev.id, "timestamp": iso(now), "domain": domain, "client_ip": client,
                 "query_type": qtype, "response_code": rcode, "source": ev.source,
                 "classification": a["classification"], "risk_score": a["risk_score"],
                 "category": a["category"], "severity": a["severity"], "blocked": blocked,
                 "reasons": a["reasons"]}
        return {"query": query, "alert": alert_dict,
                "prediction": {k: a[k] for k in ("classification", "risk_score", "model_prob", "rule_score",
                                                 "category", "severity", "reasons", "model_version",
                                                 "trusted_infrastructure")},
                "features": feats}

    def _upsert_alert(self, s, pred, domain, client, a, blocked, now) -> SecurityAlert:
        cutoff = now - timedelta(minutes=ALERT_DEDUPE_MINUTES)
        existing = s.scalars(select(SecurityAlert).where(
            SecurityAlert.domain == domain, SecurityAlert.client_ip == client,
            SecurityAlert.last_seen >= cutoff, SecurityAlert.status.in_(("new", "investigating"))
        ).limit(1)).first()
        if existing:
            existing.occurrences += 1
            existing.last_seen = now
            existing.prediction_id = pred.id
            if a["risk_score"] > existing.risk_score:
                existing.risk_score, existing.severity = a["risk_score"], a["severity"]
                existing.classification, existing.category = a["classification"], a["category"]
                existing.reasons = a["reasons"]
            return existing
        alert = SecurityAlert(prediction_id=pred.id, domain=domain, client_ip=client, category=a["category"],
                              classification=a["classification"], severity=a["severity"],
                              risk_score=a["risk_score"], reasons=a["reasons"], blocked=blocked,
                              created_at=now, last_seen=now)
        s.add(alert)
        s.flush()
        return alert

    @staticmethod
    def alert_to_dict(al: SecurityAlert) -> Dict[str, Any]:
        return {"id": al.id, "domain": al.domain, "client_ip": al.client_ip, "category": al.category,
                "classification": al.classification, "severity": al.severity, "status": al.status,
                "risk_score": al.risk_score, "reasons": al.reasons or [], "analyst_notes": al.analyst_notes or "",
                "analysis": al.analysis, "occurrences": al.occurrences, "blocked": al.blocked,
                "created_at": iso(al.created_at), "last_seen": iso(al.last_seen)}

    # ------------------------------------------------------------ block / allow
    def _check(self, domain: str) -> str:
        d = normalize(domain)
        if not valid_domain(d):
            raise DomainPolicyError("Invalid domain name")
        return d

    def block_domain(self, domain: str, reason: str = "", source: str = "manual") -> Dict[str, Any]:
        d = self._check(domain)
        if is_trusted(d) or _matches(d, self.allow):
            raise DomainPolicyError(f"{d} is trusted infrastructure or on the allowlist and cannot be blocked")
        with self.session_factory() as s:
            if s.get(BlockedDomain, d) is None:
                s.add(BlockedDomain(domain=d, reason=reason[:500], source=source))
            s.execute(update(SecurityAlert).where(SecurityAlert.domain == d).values(blocked=True))
            s.commit()
        with self._lock:
            self.blocked.add(d)
            snapshot = set(self.blocked)
        enforced = self.blocklist.write(snapshot)
        return {"domain": d, "enforced": enforced}

    def unblock_domain(self, domain: str) -> bool:
        d = self._check(domain)
        with self.session_factory() as s:
            row = s.get(BlockedDomain, d)
            if row is None:
                return False
            s.delete(row)
            s.execute(update(SecurityAlert).where(SecurityAlert.domain == d).values(blocked=False))
            s.commit()
        with self._lock:
            self.blocked.discard(d)
            snapshot = set(self.blocked)
        self.blocklist.write(snapshot)
        return True

    def allow_domain(self, domain: str, reason: str = "") -> Dict[str, Any]:
        d = self._check(domain)
        with self.session_factory() as s:
            if s.get(AllowlistedDomain, d) is None:
                s.add(AllowlistedDomain(domain=d, reason=reason[:500]))
            if s.get(BlockedDomain, d) is not None:
                s.delete(s.get(BlockedDomain, d))
            s.execute(update(SecurityAlert).where(SecurityAlert.domain == d)
                      .values(status="false_positive", blocked=False))
            s.commit()
        with self._lock:
            self.allow.add(d)
            was_blocked = d in self.blocked
            self.blocked.discard(d)
            snapshot = set(self.blocked)
        if was_blocked:
            self.blocklist.write(snapshot)
        return {"domain": d}

    def remove_allow(self, domain: str) -> bool:
        d = self._check(domain)
        with self.session_factory() as s:
            row = s.get(AllowlistedDomain, d)
            if row is None:
                return False
            s.delete(row)
            s.commit()
        with self._lock:
            self.allow.discard(d)
        return True

    # ---------------------------------------------------------------- retention
    def prune(self, days: int) -> int:
        cutoff = utcnow() - timedelta(days=days)
        with self.session_factory() as s:
            old = select(DNSEvent.id).where(DNSEvent.timestamp < cutoff)
            old_pred = select(MLPrediction.id).where(MLPrediction.event_id.in_(old))
            s.execute(update(SecurityAlert).where(SecurityAlert.prediction_id.in_(old_pred))
                      .values(prediction_id=None))
            s.execute(delete(FeatureVector).where(FeatureVector.event_id.in_(old)))
            s.execute(delete(MLPrediction).where(MLPrediction.event_id.in_(old)))
            n = s.execute(delete(DNSEvent).where(DNSEvent.timestamp < cutoff)).rowcount
            s.commit()
        if n:
            log.info("Retention: pruned %d DNS events older than %d days", n, days)
        return n or 0
