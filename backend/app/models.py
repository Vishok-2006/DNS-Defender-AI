"""
ORM schema. Table names follow the project report (section 4.4):
dns_events, feature_vectors, ml_predictions, security_alerts, user_accounts,
plus blocked_domains / allowlisted_domains for the response policy.
"""
import uuid
from datetime import datetime, timezone

from sqlalchemy import (JSON, Boolean, Column, DateTime, Float, ForeignKey, Index,
                        Integer, String, Text)

from .db import Base


def utcnow() -> datetime:
    """Naive UTC timestamp (all timestamps in the DB are UTC)."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def new_id() -> str:
    return uuid.uuid4().hex


class DNSEvent(Base):
    __tablename__ = "dns_events"
    id = Column(String(32), primary_key=True, default=new_id)
    timestamp = Column(DateTime, default=utcnow, index=True, nullable=False)
    src_ip = Column(String(64), index=True, nullable=False)
    domain = Column(String(255), index=True, nullable=False)
    query_type = Column(String(16), nullable=False, default="A")
    response_code = Column(String(16), nullable=False, default="NOERROR")
    source = Column(String(16), nullable=False, default="api")  # dnsmasq|scapy|zeek|api|simulation
    blocked = Column(Boolean, default=False, nullable=False)


class FeatureVector(Base):
    __tablename__ = "feature_vectors"
    id = Column(String(32), primary_key=True, default=new_id)
    event_id = Column(String(32), ForeignKey("dns_events.id", ondelete="CASCADE"), index=True, nullable=False)
    entropy = Column(Float)
    digit_ratio = Column(Float)
    domain_len = Column(Integer)
    features = Column(JSON, nullable=False)  # full lexical + behavioural vector


class MLPrediction(Base):
    __tablename__ = "ml_predictions"
    id = Column(String(32), primary_key=True, default=new_id)
    event_id = Column(String(32), ForeignKey("dns_events.id", ondelete="CASCADE"), index=True, nullable=False)
    risk_score = Column(Float, nullable=False)
    is_malicious = Column(Boolean, nullable=False)
    classification = Column(String(16), nullable=False)  # benign | suspicious | malicious
    category = Column(String(64))
    model_prob = Column(Float)       # Random Forest probability (lexical)
    rule_score = Column(Float)       # behavioural / tunnelling / phishing rule contribution
    model_ver = Column(String(32), nullable=False)
    timestamp = Column(DateTime, default=utcnow, index=True, nullable=False)


class SecurityAlert(Base):
    __tablename__ = "security_alerts"
    id = Column(String(32), primary_key=True, default=new_id)
    prediction_id = Column(String(32), ForeignKey("ml_predictions.id", ondelete="SET NULL"), nullable=True)
    domain = Column(String(255), index=True, nullable=False)
    client_ip = Column(String(64), index=True, nullable=False)
    category = Column(String(64), nullable=False)
    classification = Column(String(16), nullable=False)
    severity = Column(String(16), index=True, nullable=False)   # low | medium | high | critical
    status = Column(String(20), index=True, nullable=False, default="new")
    risk_score = Column(Float, nullable=False)
    reasons = Column(JSON, nullable=False, default=list)
    analyst_notes = Column(Text, default="")
    analysis = Column(JSON, nullable=True)   # LLM / rule-based explanation
    occurrences = Column(Integer, nullable=False, default=1)
    blocked = Column(Boolean, nullable=False, default=False)
    created_at = Column(DateTime, default=utcnow, index=True, nullable=False)
    last_seen = Column(DateTime, default=utcnow, nullable=False)
    __table_args__ = (Index("ix_alert_dedupe", "domain", "client_ip", "last_seen"),)


class BlockedDomain(Base):
    __tablename__ = "blocked_domains"
    domain = Column(String(255), primary_key=True)
    reason = Column(Text, nullable=False, default="")
    source = Column(String(16), nullable=False, default="manual")  # manual | auto
    blocked_at = Column(DateTime, default=utcnow, nullable=False)


class AllowlistedDomain(Base):
    __tablename__ = "allowlisted_domains"
    domain = Column(String(255), primary_key=True)
    reason = Column(Text, nullable=False, default="")
    added_at = Column(DateTime, default=utcnow, nullable=False)


class UserAccount(Base):
    """Reserved for analyst accounts / RBAC (report 4.4). The current release
    protects the API with a shared API key instead (see security.py)."""
    __tablename__ = "user_accounts"
    id = Column(String(32), primary_key=True, default=new_id)
    username = Column(String(64), unique=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    role = Column(String(32), nullable=False, default="analyst")
    created_at = Column(DateTime, default=utcnow, nullable=False)
