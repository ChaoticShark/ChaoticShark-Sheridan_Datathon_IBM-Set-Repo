"""
Robustness checks, logged to results/robustness.json:
  * a second, untouched forward split (train 2024 H1 -> test 2024 Q3), since the model
    choice was made on the 2025 season;
  * vendor-feature simplification (the two vendor features overlap);
  * a per-vendor cap in the ranking (to avoid 20 slots riding on one advisory).
A change is only adopted if it does not hurt on BOTH splits.
Run:  python pipeline/robustness.py
"""
import json
import os
import sys
import numpy as np
import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import core
import model
from backtest import baselines, hits_at, SCOREBOARD_N

OUT = os.path.join(core.ROOT, "results")

SPLITS = {
    "main: train 2024 -> test 2025 Jan-Sep": dict(
        train={"2023-12-31": [f"2024-{m:02d}" for m in range(1, 13)]}, train_label="2024-12-31",
        test=[f"2025-{m:02d}" for m in range(1, 10)], test_label="2025-12-31", test_know="2024-12-31"),
    "second: train 2024 Jan-Jun -> test 2024 Jul-Sep": dict(
        train={"2023-12-31": [f"2024-{m:02d}" for m in range(1, 7)]}, train_label="2024-06-30",
        test=[f"2024-{m:02d}" for m in range(7, 10)], test_label="2024-12-31", test_know="2023-12-31"),
    # quarterly walk-forward (idea from the team repo; here labels are cut at each quarter's start)
    "quarterly: 2025-Q2 (train <= 2025-03, labels <= 2025-03-31)": dict(
        train={"2023-12-31": [f"2024-{m:02d}" for m in range(1, 13)], "2024-12-31": ["2025-01", "2025-02", "2025-03"]},
        train_label="2025-03-31",
        test=["2025-04", "2025-05", "2025-06"], test_label="2025-12-31", test_know="2024-12-31"),
    "quarterly: 2025-Q3 (train <= 2025-06, labels <= 2025-06-30)": dict(
        train={"2023-12-31": [f"2024-{m:02d}" for m in range(1, 13)], "2024-12-31": [f"2025-{m:02d}" for m in range(1, 7)]},
        train_label="2025-06-30",
        test=["2025-07", "2025-08", "2025-09"], test_label="2025-12-31", test_know="2024-12-31"),
}

VARIANTS = {
    "current model (with vendor cap)": dict(features=model.FEATURES, cap="auto"),
    "current, no vendor cap": dict(features=model.FEATURES, cap=None),
    "without nearest-KEV similarity": dict(features=[f for f in model.FEATURES if f != "kev_sim_max"], cap="auto"),
    "+ similarity top5 too": dict(features=model.FEATURES + ["kev_sim_top5"], cap="auto"),
    "+ vendor_matched back": dict(features=model.FEATURES + ["vendor_matched"], cap="auto"),
}


def capped(scores, vendors, cap):
    """Greedy re-rank: a vendor's (cap+1)th and later CVEs move below all uncapped ones."""
    order = np.argsort(-scores, kind="stable")
    seen, first, later = {}, [], []
    for i in order:
        v = vendors[i]
        if v is None or (isinstance(v, float) and np.isnan(v)):
            first.append(i); continue
        seen[v] = seen.get(v, 0) + 1
        (first if seen[v] <= cap else later).append(i)
    new = np.empty(len(scores))
    for r, i in enumerate(first + later):
        new[i] = -r
    return new


def main():
    vulns, kev, sig = core.load_vulns(), core.load_kev(), core.load_signals()
    hist = core.KevHistory(kev)
    raw = pd.read_csv(os.path.join(core.DATA, "vulnerabilities.csv"), usecols=["cve_id", "cvss3_score"])
    raw_cvss = raw.set_index("cve_id").cvss3_score
    report = {}
    for sname, sp in SPLITS.items():
        Xtr, ytr, wtr = model.training_set(sp["train"], sp["train_label"], vulns, kev, sig, hist)
        pool = core.build_pool(sp["test"], sp["test_label"], vulns, kev, sig)
        ts, _ = model.text_scores(vulns, kev, pool.cve_id, sp["test_know"])
        Xte, mte = core.build_features(pool, vulns, kev, hist, ts, assigner_cutoff=sp["test_know"],
                                       kevsim=model.kev_similarity(kev, vulns, sp["test_know"]))
        Xte = model.add_age(Xte, mte)
        y = mte.label.values
        k = round(500 * len(pool) / SCOREBOARD_N)
        rows = {}
        for n, s in baselines(mte, Xte, raw_cvss).items():
            rows["BASELINE " + n] = s
        for vname, v in VARIANTS.items():
            pipe = model.fit(Xtr, ytr, wtr, v["features"])
            s = model.score(pipe, Xte)
            if v["cap"] == "auto":
                s = model.capped_rank(s, mte.brand.values, model.cap_for(k), k)
            rows[vname] = s
        res = {n: {f"hits@{k} (scaled)": hits_at(y, s, k), "hits@500": hits_at(y, s, 500)} for n, s in rows.items()}
        report[sname] = {"train_positive_rows": int(ytr.sum()), "test_pool": len(pool),
                         "test_positives": int(y.sum()), "k_scaled": k, "results": res}
        print(f"\n== {sname}  (train pos rows {int(ytr.sum())}, test pool {len(pool)}, positives {y.sum()}, k={k})")
        print(pd.DataFrame(res).T.to_string())
    json.dump(report, open(os.path.join(OUT, "robustness.json"), "w"), indent=2)


if __name__ == "__main__":
    main()
