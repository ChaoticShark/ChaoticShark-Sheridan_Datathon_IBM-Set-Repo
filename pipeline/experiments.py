"""EARLY EXPLORATION, superseded by model.py / backtest.py. Kept so results/experiments.json can be reproduced.
Note: it uses the earlier feature set, so its numbers differ slightly from the locked model.
"""
"""
Model-variant comparison on the walk-forward backtest. Every variant is logged
(results/experiments.json), including the ones that did not help, so the choice
of final model is transparent rather than cherry-picked.
"""
import json
import os
import pickle
import sys
import numpy as np
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import core
from text_model import TextPrior
from ranker import Ranker
from backtest import baselines, hits_at, SCOREBOARD_N

OUT = os.path.join(core.ROOT, "results")


def get_data():
    path = os.path.join(core.CACHE, "bt_features.pkl")
    if os.path.exists(path):
        return pickle.load(open(path, "rb"))
    vulns, kev, sig = core.load_vulns(), core.load_kev(), core.load_signals()
    hist = core.KevHistory(kev)
    tr = core.build_pool([f"2024-{m:02d}" for m in range(1, 13)], "2024-12-31", vulns, kev, sig, include_fast=True)
    te = core.build_pool([f"2025-{m:02d}" for m in range(1, 10)], "2025-12-31", vulns, kev, sig)
    V = vulns.set_index("cve_id")
    tp1 = TextPrior().fit(vulns, kev, "2023-12-31")
    tp2 = TextPrior().fit(vulns, kev, "2024-12-31")
    ts1 = dict(zip(tr.cve_id, tp1.score(V.loc[tr.cve_id].description, V.loc[tr.cve_id].assigner_key)))
    ts2 = dict(zip(te.cve_id, tp2.score(V.loc[te.cve_id].description, V.loc[te.cve_id].assigner_key)))
    Xtr, mtr = core.build_features(tr, vulns, kev, hist, ts1, assigner_cutoff="2023-12-31")
    Xte, mte = core.build_features(te, vulns, kev, hist, ts2, assigner_cutoff="2024-12-31")
    mtr["fast"] = tr.fast.values
    raw = pd.read_csv(os.path.join(core.DATA, "vulnerabilities.csv"), usecols=["cve_id", "cvss3_score"])
    d = dict(Xtr=Xtr, mtr=mtr, Xte=Xte, mte=mte, raw_cvss=raw.set_index("cve_id").cvss3_score)
    pickle.dump(d, open(path, "wb"))
    return d


def rank01(s):
    return pd.Series(s).rank(pct=True).values


def main():
    d = get_data()
    Xtr, mtr, Xte, mte = d["Xtr"], d["mtr"], d["Xte"], d["mte"]
    y = mte.label.values
    k = round(500 * len(Xte) / SCOREBOARD_N)
    m_base = (mtr.snapshot_month <= "2024-09") & (mtr.fast == 0)
    m_12 = mtr.fast == 0
    m_all = np.ones(len(mtr), bool)

    variants = {}
    for name, s in baselines(mte, Xte, d["raw_cvss"]).items():
        variants["BASELINE " + name] = s
    variants["Text prior only"] = Xte.text_score.values
    for C in (0.01, 0.05, 0.2):
        variants[f"LR C={C} train 2024-01..09"] = Ranker(C).fit(Xtr[m_base], mtr.label[m_base]).score(Xte)
        variants[f"LR C={C} train 2024-01..12"] = Ranker(C).fit(Xtr[m_12], mtr.label[m_12]).score(Xte)
        variants[f"LR C={C} train 2024 + fast positives"] = Ranker(C).fit(Xtr[m_all], mtr.label[m_all]).score(Xte)
    gb = HistGradientBoostingClassifier(max_depth=3, learning_rate=0.05, max_iter=300, l2_regularization=1.0,
                                        class_weight="balanced", random_state=0)
    gb.fit(Xtr[m_all].fillna(-1), mtr.label[m_all])
    variants["GBM train 2024 + fast"] = gb.predict_proba(Xte.fillna(-1))[:, 1]
    # simple, readable blend: exploit code / EPSS / text prior / vendor history
    variants["Blend: rank(text)+rank(epss)+code+vendor"] = (
        rank01(Xte.text_score) + rank01(Xte.epss_log) + Xte.any_exploit_code.values + Xte.kev_vendor_log.values / 3)

    res = {n: {"hits@500": hits_at(y, s, 500), f"hits@{k}": hits_at(y, s, k), "hits@1000": hits_at(y, s, 1000)}
           for n, s in variants.items()}
    df = pd.DataFrame(res).T
    print(f"test pool {len(Xte)}  positives {y.sum()}  scaled k={k}")
    print(df.to_string())
    json.dump(res, open(os.path.join(OUT, "experiments.json"), "w"), indent=2)


if __name__ == "__main__":
    main()
