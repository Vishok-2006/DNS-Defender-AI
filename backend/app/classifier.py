"""
Detection engine.

risk = noisy-OR( RF probability , rule scores )  ->  benign / suspicious / malicious

* The Random Forest (trained by ml-training/train.py on a public DGA dataset)
  scores how algorithmically-generated the registrable label looks.
* Explicit, documented rules add evidence for things the dataset cannot teach:
  DNS tunnelling, regular beaconing, per-client NXDOMAIN bursts, query floods,
  and phishing-style names. They are heuristics, not measured classifiers.
"""
from __future__ import annotations

import logging
import math
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import joblib
import numpy as np

from .features import MODEL_FEATURES, lexical_features, normalize, shannon_entropy

log = logging.getLogger("defender.classifier")

# Machine-generated names are normal under these roots (CDNs, OS/vendor
# infrastructure). The *lexical model* is capped for them to avoid the classic
# CDN false-positive; behavioural and tunnelling rules still apply.
TRUSTED_ROOTS = (
    "google.com", "googleapis.com", "gstatic.com", "googleusercontent.com", "youtube.com",
    "ytimg.com", "googlevideo.com", "microsoft.com", "windows.com", "windowsupdate.com",
    "msftconnecttest.com", "office.com", "office365.com", "live.com", "azure.com",
    "apple.com", "icloud.com", "mzstatic.com", "amazon.com", "amazonaws.com",
    "cloudfront.net", "akamai.net", "akamaiedge.net", "akamaihd.net", "fastly.net",
    "cloudflare.com", "cloudflare-dns.com", "github.com", "githubusercontent.com",
    "ubuntu.com", "debian.org", "raspberrypi.com", "raspberrypi.org", "facebook.com",
    "fbcdn.net", "whatsapp.net", "mozilla.org", "mozilla.net", "digicert.com",
)

PHISH_WORDS = ("login", "signin", "verify", "secure", "account", "update", "suspend",
               "confirm", "wallet", "banking", "password", "paypal", "support", "alert")
_ENCODED_LABEL = re.compile(r"^(?:[a-f0-9]{20,}|[a-z2-7]{24,})$")

SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def is_trusted(domain: str) -> bool:
    d = normalize(domain)
    return any(d == r or d.endswith("." + r) for r in TRUSTED_ROOTS)


def noisy_or(scores: List[float]) -> float:
    prod = 1.0
    for s in scores:
        prod *= 1.0 - min(max(s, 0.0), 0.999)
    return 1.0 - prod


class Detector:
    def __init__(self, model_path: str, suspicious: Optional[float] = None, malicious: Optional[float] = None):
        self.model = None
        self.lm = None
        self.model_version = "heuristic-fallback"
        self.thr_suspicious = suspicious if suspicious is not None else 0.45
        self.thr_malicious = malicious if malicious is not None else 0.80
        self._load(model_path, suspicious, malicious)

    # ------------------------------------------------------------------ loading
    def _load(self, path: str, sus: Optional[float], mal: Optional[float]) -> None:
        p = Path(path)
        if not p.exists():
            log.error("Model file %s not found - running in HEURISTIC FALLBACK mode", p)
            return
        try:
            bundle = joblib.load(p)
            if list(bundle["features"]) != MODEL_FEATURES:
                raise ValueError("feature list in model does not match features.py")
            self.model, self.lm = bundle["model"], bundle["lm"]
            self.model.n_jobs = 1  # single-row inference is faster without thread fan-out
            thr = bundle.get("thresholds", {})
            self.thr_suspicious = sus if sus is not None else float(thr.get("suspicious", 0.45))
            self.thr_malicious = mal if mal is not None else float(thr.get("malicious", 0.80))
            self.model_version = f"rf-{bundle.get('sklearn_version', '?')}"
            log.info("Loaded model %s (thresholds sus=%.3f mal=%.3f)", p, self.thr_suspicious, self.thr_malicious)
        except Exception as exc:  # corrupt file, sklearn version mismatch, ...
            log.error("Could not load model %s (%s) - HEURISTIC FALLBACK mode", p, exc)
            self.model = self.lm = None

    @property
    def model_loaded(self) -> bool:
        return self.model is not None

    # ---------------------------------------------------------------- scoring
    def _model_prob(self, lex: Dict[str, float]) -> float:
        if self.model is not None:
            row = np.array([[lex[k] for k in MODEL_FEATURES]], dtype=np.float32)
            return float(self.model.predict_proba(row)[0][1])
        # Fallback (model unavailable): crude evidence from entropy / consonant runs.
        z = (0.9 * (lex["sld_entropy"] - 3.3) + 0.35 * (lex["sld_max_consonant_run"] - 4)
             + 2.0 * (lex["sld_digit_ratio"] - 0.2) + 0.04 * (lex["sld_length"] - 14))
        return 1.0 / (1.0 + math.exp(-z))

    def _rules(self, d: str, lex: Dict[str, float], beh: Dict[str, float], is_nx: bool
               ) -> Tuple[float, Dict[str, float], List[str]]:
        """Return (combined rule score, per-rule scores, human-readable reasons)."""
        parts: Dict[str, float] = {}
        why: List[str] = []
        labels = d.split(".")
        longest = max((len(l) for l in labels), default=0)

        # --- DNS tunnelling: oversized or encoded-looking labels, TXT-heavy traffic
        tunnel = 0.0
        if longest >= 50:
            tunnel, msg = 0.92, f"Label of {longest} chars (limit 63) - typical of DNS tunnelling payloads."
        elif longest >= 40:
            tunnel, msg = 0.82, f"Very long label ({longest} chars) - possible data exfiltration over DNS."
        else:
            msg = ""
            for lab in labels[:-2] if len(labels) > 2 else []:
                if _ENCODED_LABEL.match(lab) and shannon_entropy(lab) >= 3.0:
                    tunnel, msg = 0.78, f"Encoded-looking subdomain '{lab[:24]}...' (hex/base32 payload pattern)."
                    break
        if beh.get("txt_query_ratio", 0) >= 0.35 and beh.get("domain_frequency", 0) >= 3:
            if tunnel < 0.70:
                tunnel, msg = 0.70, f"{beh['txt_query_ratio']:.0%} of queries are TXT - possible C2/tunnel channel."
        if tunnel:
            parts["tunnelling"] = tunnel
            why.append(msg)

        # --- Regular, machine-like polling. Legitimate software also polls, so this
        # alone stays below the suspicious threshold and only matters with other evidence.
        if beh.get("beaconing", 0) >= 1:
            parts["beaconing"] = 0.40
            why.append("Queries arrive at very regular intervals (automated beaconing pattern).")

        # --- Per-client NXDOMAIN burst (DGA hunting for a live C2 name)
        nx_client = beh.get("client_nxdomain_60s", 0)
        if is_nx and nx_client >= 25:
            parts["nx_burst"] = 0.80
            why.append(f"Client produced {int(nx_client)} distinct NXDOMAIN lookups in 60 s (DGA-style burst).")
        elif is_nx and nx_client >= 10:
            parts["nx_burst"] = 0.60
            why.append(f"Client produced {int(nx_client)} distinct NXDOMAIN lookups in 60 s.")
        if beh.get("domain_frequency", 0) >= 3 and beh.get("nxdomain_ratio", 0) >= 0.6:
            parts["nx_ratio"] = 0.50
            why.append(f"{beh['nxdomain_ratio']:.0%} of lookups for this domain fail (NXDOMAIN).")

        # --- Query flood against one name
        if beh.get("query_frequency", 0) >= 60:
            parts["flood"] = 0.50
            why.append(f"{int(beh['query_frequency'])} queries/minute to a single domain.")

        # --- Phishing-style name: several lure words glued together with hyphens
        sld_label = labels[-2] if len(labels) >= 2 else labels[0]
        hits = [w for w in PHISH_WORDS if w in sld_label]
        if len(hits) >= 2 and sld_label.count("-") >= 2:
            parts["phishing"] = 0.60
            why.append(f"Phishing-style name combining lure words ({', '.join(hits[:3])}).")

        return noisy_or(list(parts.values())), parts, why

    def assess(self, domain: str, behaviour: Optional[Dict[str, float]] = None,
               is_nxdomain: bool = False) -> Dict[str, Any]:
        d = normalize(domain)
        beh = behaviour or {}
        lex = lexical_features(d, self.lm)
        reasons: List[str] = []

        p_model = self._model_prob(lex) if self.lm is not None or self.model is None else 0.0
        trusted = is_trusted(d)
        if trusted:
            p_model = min(p_model, 0.05)
        elif p_model >= self.thr_suspicious:
            reasons.append(
                f"Name looks algorithmically generated (model probability {p_model:.0%}; "
                f"entropy {lex['sld_entropy']:.2f}, longest consonant run {int(lex['sld_max_consonant_run'])})."
            )

        rule_score, parts, rule_reasons = self._rules(d, lex, beh, is_nxdomain)
        reasons.extend(rule_reasons)
        risk = round(min(0.999, noisy_or([p_model, rule_score])), 4)

        if risk >= self.thr_malicious:
            cls = "malicious"
        elif risk >= self.thr_suspicious:
            cls = "suspicious"
        else:
            cls = "benign"

        if cls == "benign":
            category, severity = "Benign", "low"
        else:
            if parts.get("tunnelling", 0) >= 0.7:
                category = "DNS Tunnelling / Exfiltration"
            elif p_model >= self.thr_suspicious:
                category = "DGA (algorithmically generated domain)"
            elif parts.get("nx_burst") or parts.get("nx_ratio"):
                category = "NXDOMAIN Burst (DGA activity)"
            elif parts.get("phishing"):
                category = "Phishing-style Domain"
            elif parts.get("beaconing"):
                category = "Malicious Beaconing"
            else:
                category = "Anomalous DNS Behaviour"
            if risk >= 0.95:
                severity = "critical"
            elif cls == "malicious":
                severity = "high"
            elif risk >= (self.thr_suspicious + self.thr_malicious) / 2:
                severity = "medium"
            else:
                severity = "low"

        return {
            "classification": cls,
            "is_malicious": cls == "malicious",
            "risk_score": risk,
            "model_prob": round(p_model, 4),
            "rule_score": round(rule_score, 4),
            "category": category,
            "severity": severity,
            "reasons": reasons,
            "trusted_infrastructure": trusted,
            "model_version": self.model_version,
            "lexical_features": lex,
        }
