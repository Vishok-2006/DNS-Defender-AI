#!/usr/bin/env python3
"""
DNS Defender AI - model training and evaluation.

Trains the Random Forest malicious-domain classifier on a PUBLIC labelled
dataset and reports honest metrics.

Dataset
-------
chrmor/DGA_domains_dataset (https://github.com/chrmor/DGA_domains_dataset)
  * 337,500 DGA domains from 25 malware families (Netlab 360 OpenData)
  * ~337,400 benign domains (Alexa top sites)
  Cucchiarelli, Morbidoni, Spalazzi, Baldi (2021). "Algorithmically generated
  malicious domain names detection based on n-grams features."
  Expert Systems with Applications 170, 114551.
  https://doi.org/10.1016/j.eswa.2020.114551
Free for research use; cite the paper. The CSV is downloaded on demand and is
intentionally NOT committed to this repository.

Evaluation protocols (all reported)
-----------------------------------
A. Random split  : 70% train / 15% validation / 15% test (stratified).
                   Thresholds are chosen on validation, metrics reported on test.
B. Unseen families: six malware families are removed from training entirely and
                   used only for testing. This is the honest answer to "does it
                   catch domains from malware it has never seen?".
C. 5-fold CV     : stability of the random-split result.

The character-trigram language-model features are fitted on benign training
rows only and are CROSS-FITTED (each benign training row is scored by a model
that never saw it) so the Random Forest does not learn from leaked scores.

Usage
-----
    python ml-training/train.py            # full run (~10-20 min on one core)
    python ml-training/train.py --quick    # 120k-row subsample, ~2 min
"""
from __future__ import annotations

import argparse
import gc
import hashlib
import json
import os
import re
import sys
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import StratifiedKFold, train_test_split

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent / "backend"))
from app.features import (  # noqa: E402
    LEXICAL_FEATURES,
    MODEL_FEATURES,
    CharTrigramLM,
    lexical_features,
    split_domain,
)

DATASET_URL = (
    "https://raw.githubusercontent.com/chrmor/DGA_domains_dataset/master/dga_domains_full.csv"
)
DATA_PATH = ROOT / "data" / "dga_domains_full.csv"
OUT_MODEL = ROOT.parent / "backend" / "models" / "dga_rf.joblib"
OUT_CARD = ROOT.parent / "backend" / "models" / "model_card.json"

# Families held out for protocol B: a mix of random-looking and dictionary-word DGAs.
HELD_OUT_FAMILIES = ["gozi", "suppobox", "ramnit", "pykspa", "necurs", "conficker"]
SEED = 42


def rf_factory(n_estimators: int) -> RandomForestClassifier:
    return RandomForestClassifier(
        n_estimators=n_estimators,
        max_depth=16,
        min_samples_leaf=20,   # regularised: keeps the model small enough for a Raspberry Pi
        class_weight="balanced",  # robust to class imbalance
        n_jobs=-1,
        random_state=SEED,
    )


def load_dataset(quick: bool) -> pd.DataFrame:
    if not DATA_PATH.exists():
        DATA_PATH.parent.mkdir(parents=True, exist_ok=True)
        print(f"[data] downloading {DATASET_URL}")
        urllib.request.urlretrieve(DATASET_URL, DATA_PATH)
    df = pd.read_csv(DATA_PATH, header=None, names=["label", "family", "domain"])
    df["domain"] = df["domain"].astype(str).str.strip().str.lower()
    df = df.drop_duplicates("domain").reset_index(drop=True)
    if quick:
        df = df.sample(n=120_000, random_state=SEED).reset_index(drop=True)
    print(f"[data] {len(df):,} unique domains | "
          f"{(df.label == 'dga').sum():,} DGA / {(df.label == 'legit').sum():,} benign | "
          f"{df[df.label == 'dga'].family.nunique()} DGA families")
    return df


class Features:
    """Computes base lexical features once; LM features per train/test split."""

    def __init__(self, df: pd.DataFrame):
        t = time.time()
        self.y = (df["label"] == "dga").astype(int).values
        self.family = df["family"].values
        self.labels = []
        base = []
        for d in df["domain"].values:
            _, sld, _ = split_domain(d)
            label = re.sub(r"[^a-z0-9-]", "", sld or d.split(".")[0])
            self.labels.append(label)
            f = lexical_features(d)
            base.append([f[k] for k in LEXICAL_FEATURES])
        self.base = np.array(base, dtype=np.float32)
        self.seq = [CharTrigramLM.encode(l) for l in self.labels]
        print(f"[features] base lexical features in {time.time() - t:.0f}s")

    def _fit_lm(self, idx) -> CharTrigramLM:
        return CharTrigramLM.fit(self.labels[i] for i in idx)

    def _score(self, lm: CharTrigramLM, idx) -> np.ndarray:
        out = np.zeros((len(idx), 2), dtype=np.float32)
        for k, i in enumerate(idx):
            s = self.seq[i]
            lp = lm.logprob[s[:-2], s[1:-1], s[2:]]
            out[k] = (lp.mean(), lp.min())
        return out

    def build(self, train_idx, eval_idx):
        """Return (full feature matrix, final LM fitted on all benign train rows)."""
        train_idx = np.asarray(train_idx)
        benign = train_idx[self.y[train_idx] == 0].copy()
        np.random.RandomState(SEED).shuffle(benign)
        half = len(benign) // 2
        a, b = benign[:half], benign[half:]
        lm_a, lm_b, lm_all = self._fit_lm(a), self._fit_lm(b), self._fit_lm(benign)
        extra = np.zeros((len(self.y), 2), dtype=np.float32)
        extra[a] = self._score(lm_b, a)        # cross-fitted: never scored by own LM
        extra[b] = self._score(lm_a, b)
        mal = train_idx[self.y[train_idx] == 1]
        extra[mal] = self._score(lm_all, mal)
        extra[eval_idx] = self._score(lm_all, eval_idx)
        return np.hstack([self.base, extra]), lm_all


def metrics(y, p, thr) -> dict:
    pred = (p >= thr).astype(int)
    tn, fp, fn, tp = confusion_matrix(y, pred).ravel()
    return {
        "threshold": round(float(thr), 4),
        "accuracy": round(accuracy_score(y, pred), 4),
        "precision": round(precision_score(y, pred), 4),
        "recall_tpr": round(recall_score(y, pred), 4),
        "f1": round(f1_score(y, pred), 4),
        "false_positive_rate": round(fp / max(1, fp + tn), 4),
        "roc_auc": round(roc_auc_score(y, p), 4),
        "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
        "n": int(len(y)),
    }


def threshold_for_fpr(y, p, target_fpr) -> float:
    """Smallest threshold whose false-positive rate on benign samples is <= target."""
    benign = np.sort(p[y == 0])
    k = int(np.ceil((1 - target_fpr) * len(benign))) - 1
    return float(benign[min(max(k, 0), len(benign) - 1)]) + 1e-6


def run_cv(F: "Features", all_idx, y, trees: int) -> dict:
    aucs, f1s = [], []
    for k, (a, b) in enumerate(StratifiedKFold(5, shuffle=True, random_state=SEED).split(all_idx, y)):
        Xk, _ = F.build(a, b)
        mk = rf_factory(trees).fit(Xk[a], y[a])
        pk = mk.predict_proba(Xk[b])[:, 1]
        aucs.append(roc_auc_score(y[b], pk))
        f1s.append(f1_score(y[b], (pk >= 0.5).astype(int)))
        print(f"[cv] fold {k + 1}/5 auc={aucs[-1]:.4f} f1={f1s[-1]:.4f}", flush=True)
        del mk, Xk, pk          # free the forest before the next fold (memory-bound hosts)
        gc.collect()
    return {"roc_auc_mean": round(float(np.mean(aucs)), 4), "roc_auc_std": round(float(np.std(aucs)), 4),
            "f1_mean": round(float(np.mean(f1s)), 4), "f1_std": round(float(np.std(f1s)), 4), "folds": 5}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--quick", action="store_true", help="train on a 120k subsample")
    ap.add_argument("--trees", type=int, default=100)
    ap.add_argument("--skip-cv", action="store_true")
    ap.add_argument("--cv-only", action="store_true",
                    help="only run 5-fold CV and merge it into an existing model_card.json")
    args = ap.parse_args()
    t0 = time.time()

    df = load_dataset(args.quick)
    F = Features(df)
    y, fam = F.y, F.family
    all_idx = np.arange(len(y))
    card: dict = {}
    if args.cv_only:
        card = json.loads(OUT_CARD.read_text())
        card["C_5fold_cv"] = run_cv(F, all_idx, y, args.trees)
        OUT_CARD.write_text(json.dumps(card, indent=2, default=str))
        print("[done] CV merged into", OUT_CARD)
        return

    # ---------------- Protocol A: random split + threshold selection -------------
    tr, rest = train_test_split(all_idx, test_size=0.30, random_state=SEED, stratify=y)
    val, te = train_test_split(rest, test_size=0.50, random_state=SEED, stratify=y[rest])
    X, _ = F.build(tr, np.concatenate([val, te]))
    m = rf_factory(args.trees).fit(X[tr], y[tr])
    p_val, p_te = m.predict_proba(X[val])[:, 1], m.predict_proba(X[te])[:, 1]
    thr_malicious = threshold_for_fpr(y[val], p_val, 0.01)   # <=1% FPR on validation
    thr_suspicious = threshold_for_fpr(y[val], p_val, 0.05)  # <=5% FPR on validation
    card["A_random_split_test"] = {
        "at_0.5": metrics(y[te], p_te, 0.5),
        "at_malicious_threshold": metrics(y[te], p_te, thr_malicious),
        "at_suspicious_threshold": metrics(y[te], p_te, thr_suspicious),
    }
    importances = sorted(zip(MODEL_FEATURES, m.feature_importances_), key=lambda kv: -kv[1])
    card["feature_importance"] = {k: round(float(v), 4) for k, v in importances}
    del m, X
    gc.collect()
    print("\n=== A. random 70/15/15 split (test set) ===")
    for k, v in card["A_random_split_test"].items():
        print(f"{k:26s} {json.dumps(v)}")

    # ---------------- Protocol B: unseen malware families -----------------------
    held = np.isin(fam, HELD_OUT_FAMILIES)
    benign_idx = np.where(y == 0)[0]
    benign_te = np.random.RandomState(SEED).choice(benign_idx, len(benign_idx) // 5, replace=False)
    te_b = np.concatenate([np.where(held)[0], benign_te])
    tr_b = np.setdiff1d(all_idx, te_b)
    Xb, _ = F.build(tr_b, te_b)
    mb = rf_factory(args.trees).fit(Xb[tr_b], y[tr_b])
    pb = mb.predict_proba(Xb[te_b])[:, 1]
    per_family = {}
    for f in HELD_OUT_FAMILIES:
        mask = fam[te_b] == f
        per_family[f] = round(float((pb[mask] >= thr_malicious).mean()), 4)
    card["B_unseen_families"] = {
        "held_out_families": HELD_OUT_FAMILIES,
        "at_malicious_threshold": metrics(y[te_b], pb, thr_malicious),
        "at_suspicious_threshold": metrics(y[te_b], pb, thr_suspicious),
        "recall_per_unseen_family_at_malicious_threshold": per_family,
    }
    print("\n=== B. families never seen in training ===")
    print(json.dumps(card["B_unseen_families"], indent=2))
    del mb, Xb
    gc.collect()

    # ---------------- Final model on ALL data ------------------------------------
    print("\n[final] fitting production model on all data ...")
    Xf, lm_final = F.build(all_idx, np.array([], dtype=int))
    final = rf_factory(args.trees).fit(Xf, y)
    bundle = {
        "model": final,
        "lm": lm_final,
        "features": MODEL_FEATURES,
        "thresholds": {"suspicious": round(thr_suspicious, 4), "malicious": round(thr_malicious, 4)},
        "sklearn_version": sklearn.__version__,
    }
    OUT_MODEL.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(bundle, OUT_MODEL, compress=3)

    card.update({
        "model": "RandomForestClassifier",
        "params": final.get_params(),
        "trained_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "sklearn_version": sklearn.__version__,
        "quick_mode": bool(args.quick),
        "thresholds": bundle["thresholds"],
        "features": MODEL_FEATURES,
        "dataset": {
            "name": "chrmor/DGA_domains_dataset",
            "url": "https://github.com/chrmor/DGA_domains_dataset",
            "citation": "Cucchiarelli et al. (2021), Expert Systems with Applications 170, 114551",
            "rows_used": int(len(df)),
            "sha256": hashlib.sha256(DATA_PATH.read_bytes()).hexdigest(),
        },
        "model_file_mb": round(os.path.getsize(OUT_MODEL) / 1e6, 2),
        "limitations": [
            "Lexical model: dictionary-word DGA families (e.g. gozi, suppobox) are barely detectable from the name alone.",
            "Benign class is Alexa top sites; CDN/hash-like infrastructure names can look random and need the allowlist.",
            "DNS tunnelling, beaconing and NXDOMAIN-burst detection are rule-based heuristics, not evaluated by this dataset.",
        ],
    })
    OUT_CARD.write_text(json.dumps(card, indent=2, default=str))
    print("[saved] model + preliminary card written")
    del final, Xf
    gc.collect()

    # ---------------- Protocol C: 5-fold cross-validation -----------------------
    if not args.skip_cv:
        card["C_5fold_cv"] = run_cv(F, all_idx, y, args.trees)
    OUT_CARD.write_text(json.dumps(card, indent=2, default=str))
    print(f"[done] model -> {OUT_MODEL} ({card['model_file_mb']} MB), card -> {OUT_CARD}, "
          f"total {time.time() - t0:.0f}s")


if __name__ == "__main__":
    main()
