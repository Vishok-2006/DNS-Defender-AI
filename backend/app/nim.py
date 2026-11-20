"""Optional threat explanations from NVIDIA NIM (OpenAI-compatible), with an offline fallback."""
from __future__ import annotations

import json
import logging
from typing import Any, Dict, List

import httpx
from pydantic import BaseModel, Field, ValidationError

log = logging.getLogger("defender.nim")


class Explanation(BaseModel):
    summary: str
    indicators: List[str] = Field(default_factory=list)
    possible_threat: str
    severity: str
    recommendations: List[str] = Field(default_factory=list)


SYSTEM_PROMPT = (
    "You are a SOC analyst. You are given DNS detection output. Reply with ONLY a JSON object: "
    '{"summary": str, "indicators": [str], "possible_threat": str, '
    '"severity": "low|medium|high|critical", "recommendations": [str]}. '
    "Do not invent facts that are not supported by the provided evidence."
)


class NimClient:
    def __init__(self, api_key, model, base_url, timeout: float = 12.0):
        self.api_key, self.model, self.base_url, self.timeout = api_key, model, base_url.rstrip("/"), timeout

    @property
    def configured(self) -> bool:
        return bool(self.api_key) and not self.api_key.startswith("nvapi-your")

    async def explain(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        if self.configured:
            try:
                out = await self._remote(alert)
                if out:
                    return out
            except Exception as exc:   # network, HTTP, bad JSON -> degrade gracefully
                log.warning("NVIDIA NIM unavailable (%s) - using offline explanation", exc)
        return self.local(alert)

    async def _remote(self, alert: Dict[str, Any]) -> Dict[str, Any] | None:
        payload = {"domain": alert["domain"], "classification": alert["classification"],
                   "risk_score": alert["risk_score"], "category": alert["category"],
                   "evidence": alert.get("reasons", [])}
        body = {"model": self.model, "temperature": 0.2, "max_tokens": 500,
                "response_format": {"type": "json_object"},
                "messages": [{"role": "system", "content": SYSTEM_PROMPT},
                             {"role": "user", "content": json.dumps(payload)}]}
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            r = await client.post(f"{self.base_url}/chat/completions", json=body,
                                  headers={"Authorization": f"Bearer {self.api_key}"})
        r.raise_for_status()
        try:
            exp = Explanation(**json.loads(r.json()["choices"][0]["message"]["content"]))
        except (ValidationError, KeyError, json.JSONDecodeError) as exc:
            raise ValueError(f"invalid LLM response: {exc}")
        return {**exp.model_dump(), "provider": "nvidia_nim", "model": self.model}

    @staticmethod
    def local(alert: Dict[str, Any]) -> Dict[str, Any]:
        d, cat = alert["domain"], alert["category"]
        return {
            "summary": f"{d} was classified {alert['classification']} ({cat}) with risk {alert['risk_score']:.0%}.",
            "indicators": list(alert.get("reasons") or ["Statistical deviation from benign DNS behaviour."]),
            "possible_threat": cat,
            "severity": alert["severity"],
            "recommendations": [
                f"Verify {d} against threat-intelligence sources (e.g. VirusTotal, AlienVault OTX).",
                f"Inspect the client {alert['client_ip']} for the process issuing these lookups.",
                f"If confirmed, block {d} and review other queries from the same client.",
            ],
            "provider": "local_rules", "model": "offline-rules",
        }
