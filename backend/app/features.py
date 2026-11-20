"""
DNS Defender AI - feature extraction.

Two kinds of features, deliberately kept separate:

1. LEXICAL features (stateless, computed from the domain string only).
   These are what the Random Forest is trained on, using a public labelled
   dataset. The SAME function is used by ml-training/train.py and by the live
   service, so there is no training/serving skew.

2. BEHAVIOURAL features (stateful: query rate, NXDOMAIN ratio, TXT ratio,
   beaconing regularity, number of distinct clients). No public labelled
   dataset of these exists, so they are NOT fed to the Random Forest; they are
   combined with the model output by explicit, documented rules (see
   classifier.py).
"""
from __future__ import annotations

import math
import re
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Deque, Dict, List, Set

import numpy as np
import tldextract

# Offline extractor: uses the public-suffix snapshot bundled with the package and
# never touches the network or the filesystem cache (safe inside a container).
# Private suffixes (ddns.net, blogspot.com, ...) are honoured so that the
# random label of "x8f3k2.ddns.net" is treated as the registrable label.
_TLD = tldextract.TLDExtract(
    suffix_list_urls=(), cache_dir=None, include_psl_private_domains=True
)

_VOWELS = set("aeiou")
_CONSONANT_RUN = re.compile(r"[b-df-hj-np-tv-z]+")
_DIGIT_RUN = re.compile(r"\d+")

# Order matters: it is the column order of the trained model.
LEXICAL_FEATURES: List[str] = [
    "sld_length",
    "sld_entropy",
    "sld_digit_ratio",
    "sld_hyphen_ratio",
    "sld_vowel_ratio",
    "sld_unique_ratio",
    "sld_max_consonant_run",
    "sld_max_digit_run",
    "sld_digit_letter_switches",
    "subdomain_count",
    "max_label_length",
    "domain_length",
]

BEHAVIOURAL_FEATURES: List[str] = [
    "query_frequency",
    "domain_frequency",
    "unique_client_count",
    "nxdomain_ratio",
    "txt_query_ratio",
    "beaconing",
]


# Two extra lexical features come from a character-trigram language model of
# *benign* registrable labels ("how natural does this name look?").
LM_FEATURES: List[str] = ["sld_lm_mean", "sld_lm_min"]
MODEL_FEATURES: List[str] = LEXICAL_FEATURES + LM_FEATURES


class CharTrigramLM:
    """Character trigram language model with additive smoothing.

    Fitted on benign registrable labels only. DGA names are statistically
    unlikely under it (unusual letter sequences), which is the single most
    informative lexical signal for algorithmically generated domains.
    """

    ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789-"
    _IDX = {c: i + 2 for i, c in enumerate(ALPHABET)}  # 0 = '^' (start), 1 = '$' (end)
    SIZE = len(ALPHABET) + 2

    def __init__(self, logprob: np.ndarray | None = None) -> None:
        self.logprob = logprob  # shape (SIZE, SIZE, SIZE): log P(c3 | c1, c2)

    @classmethod
    def encode(cls, label: str) -> np.ndarray:
        return np.array([0, 0] + [cls._IDX[c] for c in label if c in cls._IDX] + [1], dtype=np.int16)

    @classmethod
    def fit(cls, labels, smoothing: float = 0.1) -> "CharTrigramLM":
        counts = np.full((cls.SIZE,) * 3, smoothing, dtype=np.float64)
        for label in labels:
            s = cls.encode(label)
            np.add.at(counts, (s[:-2], s[1:-1], s[2:]), 1)
        return cls(np.log(counts / counts.sum(axis=2, keepdims=True)).astype(np.float32))

    def score(self, label: str) -> tuple[float, float]:
        """(mean, min) log-probability of the label's trigrams."""
        s = self.encode(label)
        lp = self.logprob[s[:-2], s[1:-1], s[2:]]
        return float(lp.mean()), float(lp.min())


def normalize(domain: str) -> str:
    return domain.strip().lower().rstrip(".")


def split_domain(domain: str):
    """Return (subdomain, registrable_label, suffix) for a normalised domain."""
    r = _TLD(domain)
    return r.subdomain, r.domain, r.suffix


def shannon_entropy(text: str) -> float:
    """H(X) = -sum p(x) log2 p(x) over the characters of ``text``."""
    if not text:
        return 0.0
    n = len(text)
    counts: Dict[str, int] = defaultdict(int)
    for ch in text:
        counts[ch] += 1
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def lexical_features(domain: str, lm: "CharTrigramLM | None" = None) -> Dict[str, float]:
    """Stateless lexical feature vector for a domain name.

    If a fitted ``lm`` is given, the language-model features are added too
    (this is the full ``MODEL_FEATURES`` vector).
    """
    d = normalize(domain)
    subdomain, sld, _suffix = split_domain(d)
    # Fall back to the first label for single-label names ("localhost").
    label = sld or (d.split(".")[0] if d else "")
    n = len(label)
    labels = [l for l in d.split(".") if l]

    letters = [c for c in label if c.isalpha()]
    digits = sum(c.isdigit() for c in label)
    hyphens = label.count("-")
    vowels = sum(c in _VOWELS for c in label)
    alnum = re.sub(r"[^a-z0-9]", "", label)

    consonant_runs = _CONSONANT_RUN.findall(alnum)
    digit_runs = _DIGIT_RUN.findall(alnum)
    switches = sum(
        1
        for a, b in zip(alnum, alnum[1:])
        if (a.isdigit() and b.isalpha()) or (a.isalpha() and b.isdigit())
    )
    denom = max(1, n)
    feats = {
        "sld_length": float(n),
        "sld_entropy": shannon_entropy(alnum),
        "sld_digit_ratio": digits / denom,
        "sld_hyphen_ratio": hyphens / denom,
        "sld_vowel_ratio": vowels / max(1, len(letters)) if letters else 0.0,
        "sld_unique_ratio": len(set(alnum)) / max(1, len(alnum)),
        "sld_max_consonant_run": float(max((len(r) for r in consonant_runs), default=0)),
        "sld_max_digit_run": float(max((len(r) for r in digit_runs), default=0)),
        "sld_digit_letter_switches": switches / denom,
        "subdomain_count": float(len([s for s in subdomain.split(".") if s])),
        "max_label_length": float(max((len(l) for l in labels), default=0)),
        "domain_length": float(len(d)),
    }
    if lm is not None:
        mean, low = lm.score(re.sub(r"[^a-z0-9-]", "", label))
        feats["sld_lm_mean"] = mean
        feats["sld_lm_min"] = low
    return feats


@dataclass
class _DomainState:
    timestamps: Deque[float] = field(default_factory=lambda: deque(maxlen=200))
    clients: Set[str] = field(default_factory=set)
    total: int = 0
    nxdomain: int = 0
    txt: int = 0


class BehaviourTracker:
    """Rolling per-domain behavioural statistics (10 minute window for rates)."""

    WINDOW_SECONDS = 600.0
    MAX_DOMAINS = 20000  # bound memory on a Raspberry Pi

    def __init__(self) -> None:
        self._state: Dict[str, _DomainState] = {}

    def observe(
        self,
        domain: str,
        client_ip: str = "0.0.0.0",
        query_type: str = "A",
        is_nxdomain: bool = False,
        now: float | None = None,
    ) -> Dict[str, float]:
        now = time.time() if now is None else now
        d = normalize(domain)
        if d not in self._state and len(self._state) >= self.MAX_DOMAINS:
            self._evict(now)
        st = self._state.setdefault(d, _DomainState())
        st.total += 1
        st.timestamps.append(now)
        st.clients.add(client_ip)
        if is_nxdomain:
            st.nxdomain += 1
        if query_type.upper() == "TXT":
            st.txt += 1

        recent = [t for t in st.timestamps if now - t <= self.WINDOW_SECONDS]
        last_minute = sum(1 for t in recent if now - t <= 60.0)
        return {
            "query_frequency": float(last_minute),
            "domain_frequency": float(st.total),
            "unique_client_count": float(len(st.clients)),
            "nxdomain_ratio": st.nxdomain / st.total,
            "txt_query_ratio": st.txt / st.total,
            "beaconing": float(self._is_beaconing(recent)),
        }

    @staticmethod
    def _is_beaconing(ts: List[float]) -> bool:
        """Very regular inter-arrival times (>=5 queries) suggest automated polling."""
        if len(ts) < 5:
            return False
        gaps = [b - a for a, b in zip(ts, ts[1:])]
        mean = sum(gaps) / len(gaps)
        if mean < 0.05:  # a burst, not a periodic beacon
            return False
        var = sum((g - mean) ** 2 for g in gaps) / len(gaps)
        return math.sqrt(var) / mean < 0.15  # coefficient of variation

    def _evict(self, now: float) -> None:
        """Drop the least recently seen quarter of tracked domains."""
        by_age = sorted(self._state.items(), key=lambda kv: kv[1].timestamps[-1])
        for key, _ in by_age[: self.MAX_DOMAINS // 4]:
            del self._state[key]


# ---------------------------------------------------------------------------
# Per-client NXDOMAIN burst tracking (the classic runtime signature of a DGA
# searching for a live C2 domain: many *different* names failing in a row).
# ---------------------------------------------------------------------------
class ClientNXTracker:
    def __init__(self, window: float = 60.0, max_clients: int = 5000) -> None:
        self.window = window
        self.max_clients = max_clients
        self._events: Dict[str, Deque[tuple]] = {}

    def observe(self, client_ip: str, domain: str, is_nxdomain: bool, now: float | None = None) -> Dict[str, float]:
        now = time.time() if now is None else now
        if client_ip not in self._events and len(self._events) >= self.max_clients:
            self._events.pop(next(iter(self._events)))
        q = self._events.setdefault(client_ip, deque(maxlen=500))
        q.append((now, domain, is_nxdomain))
        recent = [(t, d, nx) for t, d, nx in q if now - t <= self.window]
        nx_domains = {d for _, d, nx in recent if nx}
        return {"client_nxdomain_60s": float(len(nx_domains))}
