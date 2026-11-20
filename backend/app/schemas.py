"""Request models with strict validation."""
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator

from .blocking import valid_domain
from .features import normalize

QUERY_TYPES = {"A", "AAAA", "CNAME", "TXT", "MX", "NS", "PTR", "SRV", "SOA", "HTTPS"}
RESPONSE_CODES = {"NOERROR", "NXDOMAIN", "SERVFAIL", "REFUSED"}


class DomainIn(BaseModel):
    domain: str
    reason: str = Field(default="", max_length=500)

    @field_validator("domain")
    @classmethod
    def _domain(cls, v: str) -> str:
        v = normalize(v)
        if not valid_domain(v):
            raise ValueError("not a valid domain name")
        return v


class QueryIn(DomainIn):
    client_ip: str = Field(default="192.168.1.100", max_length=64)
    query_type: str = "A"
    response_code: str = "NOERROR"

    @field_validator("query_type")
    @classmethod
    def _qt(cls, v: str) -> str:
        v = v.upper()
        if v not in QUERY_TYPES:
            raise ValueError(f"query_type must be one of {sorted(QUERY_TYPES)}")
        return v

    @field_validator("response_code")
    @classmethod
    def _rc(cls, v: str) -> str:
        v = v.upper()
        if v not in RESPONSE_CODES:
            raise ValueError(f"response_code must be one of {sorted(RESPONSE_CODES)}")
        return v


class AlertPatch(BaseModel):
    status: Optional[str] = None
    analyst_notes: Optional[str] = Field(default=None, max_length=4000)

    @field_validator("status")
    @classmethod
    def _status(cls, v):
        if v is not None and v not in {"new", "investigating", "confirmed", "resolved", "false_positive"}:
            raise ValueError("invalid status")
        return v


class SettingsPatch(BaseModel):
    model_config = ConfigDict(extra="forbid")
    alert_only_mode: Optional[bool] = None
    auto_block_confirmed: Optional[bool] = None


class SimulateIn(BaseModel):
    scenario: str = Field(pattern="^(benign|dga_burst|tunnelling|phishing)$")
