"""
Walk-forward backtest that mirrors the scoreboard setup on past data.

  TRAIN : rolling pool for months 2024-01..2024-12, KEV labels known by 2024-12-31,
          text prior / assigner stats fit on data known by 2023-12-31
  TEST  : CVEs published 2025-01..2025-09, not in KEV at end of publish month,
          label = added to KEV by 2025-12-31 (same shape as the real benchmark:
          Jan-Sep pools, judged ~2 months after September).
          Text prior / assigner stats known by 2024-12-31.

Nothing from the test period is used to build any training feature or label.
Run:  python pipeline/backtest.py
"""
import json
import os
import sys
import numpy as np
import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import core
import model

OUT = os.path.join(core.ROOT, "results")
os.makedirs(OUT, exist_ok=True)
SCOREBOARD_N = 72_670
TRAIN_MONTHS = [f"2024-{m:02d}" for m in range(1, 13)]
TEST_MONTHS = [f"2025-{m:02d}" for m in range(1, 10)]


def baselines(meta, X, raw_cvss):
    epss = np.where(X["epss_missing"].values == 1, 0.0, 10 ** X["epss_log"].values)
    cv = meta.cve_id.map(raw_cvss).fillna(0).values
    return {
        "Highest CVSS 3 first": cv + 1e-3 * epss,
        "EPSS first": epss,
        "Public exploit code first, then EPSS": X["any_exploit_code"].values * 10 + epss,
    }


def hits_at(y, s, k):
    idx = np.argsort(-np.asarray(s), kind="stable")[:k]
    return int(np.asarray(y)[idx].sum())


def bootstrap_ci(y, s_ours, s_base, k, n=1000, seed=0):
    """How often does ours beat the best baseline when the test pool is resampled?"""
    rng = np.random.default_rng(seed)
    N = len(y)
    wins, diffs = 0, []
    for _ in range(n):
        idx = rng.integers(0, N, N)
        kk = max(1, round(k))
        d = hits_at(y[idx], s_ours[idx], kk) - hits_at(y[idx], s_base[idx], kk)
        diffs.append(d)
        wins += d > 0
    return {"p_ours_better": wins / n, "diff_p05": float(np.percentile(diffs, 5)),
            "diff_median": float(np.median(diffs)), "diff_p95": float(np.percentile(diffs, 95))}


def _ranks(sc):
    order = np.argsort(-np.asarray(sc), kind="stable")
    r = np.empty(len(order), dtype=int)
    r[order] = np.arange(1, len(order) + 1)
    return r


def write_timemachine(mte, X, y, scores, k, kev):
    """'Time Machine': replay 2025. For every test CVE that later joined KEV, where did each
    method rank it at the end of its publish month, and how long before CISA's listing was that?
    Ranks are within the whole Jan-Sep 2025 test pool, same as the backtest table."""
    ranks = {n: _ranks(sc) for n, sc in scores.items()}
    # rank inside the CVE's own publish month (for the "patch N a month" slider). Ours uses the
    # uncapped score here: the vendor cap is defined for one top-k cut of the whole pool.
    months = mte.snapshot_month.values
    mranks = {n: np.zeros(len(months), dtype=int) for n in scores}
    month_pool = {}
    for m in np.unique(months):
        idx = np.where(months == m)[0]
        month_pool[str(m)] = int(len(idx))
        for n, sc in scores.items():
            src = scores["Ours (no vendor cap)"] if n == "Ours" else sc
            mranks[n][idx] = _ranks(np.asarray(src)[idx])
    added = kev.set_index("cve_id").date_added
    epss = np.where(X["epss_missing"].values == 1, np.nan, 10 ** X["epss_log"].values)
    rows = []
    for i in np.where(y == 1)[0]:
        m = mte.iloc[i]
        seen = core.month_end(m.snapshot_month)
        kd = pd.Timestamp(added.get(m.cve_id))
        rows.append({
            "id": m.cve_id, "month": m.snapshot_month, "published": str(m.published)[:10],
            "kev_added": str(kd.date()), "lead_days": int((kd - seen).days),
            "vendor": m.vendor_guess if isinstance(m.vendor_guess, str) and m.vendor_guess else m.brand,
            "product": m.product_guess if isinstance(m.product_guess, str) else "",
            "epss": None if np.isnan(epss[i]) else float(epss[i]),
            "code": int(X["any_exploit_code"].values[i]),
            "desc": str(m.description)[:300],
            "ranks": {n: int(r[i]) for n, r in ranks.items()},
            "mranks": {n: int(r[i]) for n, r in mranks.items()},
        })
    rows.sort(key=lambda r: r["ranks"]["Ours"])
    out = {"pool": int(len(mte)), "k": int(k), "positives": int(y.sum()), "month_pool": month_pool,
           "note": "Rank at the end of the CVE's publish month, using only data known then. "
                   "lead_days = days from that month end to CISA adding it to KEV.",
           "cves": rows}
    with open(os.path.join(OUT, "timemachine_2025.json"), "w") as f:
        json.dump(out, f, indent=2)


def main():
    vulns, kev, sig = core.load_vulns(), core.load_kev(), core.load_signals()
    hist = core.KevHistory(kev)
    raw = pd.read_csv(os.path.join(core.DATA, "vulnerabilities.csv"), usecols=["cve_id", "cvss3_score"])
    raw_cvss = raw.set_index("cve_id").cvss3_score

    Xtr, ytr, wtr = model.training_set({"2023-12-31": TRAIN_MONTHS}, "2024-12-31", vulns, kev, sig, hist)
    pipe = model.fit(Xtr, ytr, wtr)

    test_pool = core.build_pool(TEST_MONTHS, "2025-12-31", vulns, kev, sig)
    ts, _ = model.text_scores(vulns, kev, test_pool.cve_id, "2024-12-31")
    Xte, mte = core.build_features(test_pool, vulns, kev, hist, ts, assigner_cutoff="2024-12-31", kevsim=model.kev_similarity(kev, vulns, "2024-12-31"))
    Xte = model.add_age(Xte, mte)
    y = mte.label.values
    k = round(500 * len(test_pool) / SCOREBOARD_N)
    s_raw = model.score(pipe, Xte)
    s = model.capped_rank(s_raw, mte.brand.values, model.cap_for(k), k)

    scores = baselines(mte, Xte, raw_cvss)
    scores["Ours (no vendor cap)"] = s_raw
    scores["Ours"] = s
    results = {n: {"hits@500": hits_at(y, sc, 500), f"hits@{k} (benchmark-scaled)": hits_at(y, sc, k),
                   "hits@1000": hits_at(y, sc, 1000)} for n, sc in scores.items()}
    best_base = scores["Public exploit code first, then EPSS"]
    ci = {f"vs exploit-code baseline @{k}": bootstrap_ci(y, s, best_base, k),
          "vs exploit-code baseline @500": bootstrap_ci(y, s, best_base, 500)}

    per_month = []
    for m in TEST_MONTHS:
        mask = (mte.snapshot_month == m).values
        km = max(1, round(500 * mask.sum() / SCOREBOARD_N))
        row = {"month": m, "pool": int(mask.sum()), "positives": int(y[mask].sum()), "k": km}
        for n, sc in scores.items():
            row[n] = hits_at(y[mask], sc[mask], km)
        per_month.append(row)

    report = {
        "train_months": TRAIN_MONTHS, "train_label_cutoff": "2024-12-31", "train_knowledge_cutoff": "2023-12-31",
        "train_rows": int(len(Xtr)), "train_positive_rows": int(ytr.sum()),
        "test_months": TEST_MONTHS, "test_label_cutoff": "2025-12-31", "test_knowledge_cutoff": "2024-12-31",
        "test_pool": int(len(test_pool)), "test_positives": int(y.sum()), "k_scaled": k,
        "results": results, "bootstrap": ci, "per_month": per_month,
        "features": model.FEATURES, "weights": model.weights(pipe), "vendor_cap": model.cap_for(k),
    }
    with open(os.path.join(OUT, "backtest.json"), "w") as f:
        json.dump(report, f, indent=2, default=float)

    write_timemachine(mte, Xte, y, scores, k, kev)

    top = mte.assign(score=s, rank=pd.Series(-s).rank(method="first").values).sort_values("rank")
    top.head(1000).drop(columns=["description"]).to_csv(os.path.join(OUT, "backtest_2025_top1000.csv"), index=False)

    print(f"test pool {len(test_pool)}  positives {y.sum()}  benchmark-scaled k={k}")
    print(pd.DataFrame(results).T.to_string())
    print(json.dumps(ci, indent=2))
    print(pd.DataFrame(per_month).to_string(index=False))
    return report


if __name__ == "__main__":
    main()
