#!/usr/bin/env python3
"""
Compare candidate classifiers on the same data/features (report objective 4).

Same 70/15/15 split and cross-fitted language-model features as train.py;
a 150k-row stratified subsample keeps it quick. Output: docs/model_comparison.json
"""
import json
import sys
import time
from pathlib import Path

import numpy as np
from sklearn.ensemble import HistGradientBoostingClassifier, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.tree import DecisionTreeClassifier

sys.path.insert(0, str(Path(__file__).resolve().parent))
import train as T  # noqa: E402

N = 150_000
df = T.load_dataset(quick=False).sample(n=N, random_state=T.SEED).reset_index(drop=True)
F = T.Features(df)
y = F.y
tr, rest = train_test_split(np.arange(N), test_size=0.30, random_state=T.SEED, stratify=y)
val, te = train_test_split(rest, test_size=0.50, random_state=T.SEED, stratify=y[rest])
X, _ = F.build(tr, np.concatenate([val, te]))

candidates = {
    "Logistic Regression": make_pipeline(StandardScaler(), LogisticRegression(max_iter=1000, class_weight="balanced")),
    "Decision Tree": DecisionTreeClassifier(max_depth=12, min_samples_leaf=20, class_weight="balanced", random_state=T.SEED),
    "Random Forest (chosen)": T.rf_factory(100),
    "Gradient Boosting (HistGB)": HistGradientBoostingClassifier(max_iter=200, random_state=T.SEED),
}
results = {}
for name, model in candidates.items():
    t = time.time()
    model.fit(X[tr], y[tr])
    fit_s = time.time() - t
    p = model.predict_proba(X[te])[:, 1]
    pred = (p >= 0.5).astype(int)
    if hasattr(model, "n_jobs"):
        model.n_jobs = 1
    row = X[te][:1]
    t = time.perf_counter()
    for _ in range(200):
        model.predict_proba(row)
    results[name] = {
        "accuracy": round(accuracy_score(y[te], pred), 4), "precision": round(precision_score(y[te], pred), 4),
        "recall": round(recall_score(y[te], pred), 4), "f1": round(f1_score(y[te], pred), 4),
        "roc_auc": round(roc_auc_score(y[te], p), 4), "fit_seconds": round(fit_s, 1),
        "single_row_latency_ms": round((time.perf_counter() - t) / 200 * 1000, 2),
    }
    print(name, results[name], flush=True)
out = Path(__file__).resolve().parent.parent / "docs" / "model_comparison.json"
out.parent.mkdir(exist_ok=True)
out.write_text(json.dumps({"rows_used": N, "test_rows": int(len(te)), "threshold": 0.5, "results": results}, indent=2))
print("saved", out)
