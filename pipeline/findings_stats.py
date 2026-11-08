"""
Discovery statistics for the findings write-up, computed on scoreboard-shaped pools
(CVEs published 2024-01..2024-09 and 2025-01..2025-09, not in KEV at the end of their
publish month; label = added to KEV later, by the end of that year).
Writes results/findings_stats.json.
"""
import json
import os
import sys
import numpy as np
import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import core

OUT = os.path.join(core.ROOT, "results")


def lift_table(df, col, min_n=200, top=12):
    base = df.label.mean()
    g = df.groupby(col).label.agg(["sum", "count"])
    g = g[g["count"] >= min_n]
    g["rate"] = g["sum"] / g["count"]
    g["lift"] = g.rate / base
    return g.sort_values("lift", ascending=False).head(top)


def main():
    vulns, kev, sig = core.load_vulns(), core.load_kev(), core.load_signals()
    hist = core.KevHistory(kev)
    pools = [core.build_pool([f"2024-{m:02d}" for m in range(1, 10)], "2024-12-31", vulns, kev, sig),
             core.build_pool([f"2025-{m:02d}" for m in range(1, 10)], "2025-12-31", vulns, kev, sig)]
    p = pd.concat(pools, ignore_index=True)
    X, m = core.build_features(p, vulns, kev, hist, None, assigner_cutoff=None)
    df = m.join(X)
    df["epss"] = p.epss.values
    pos = df[df.label == 1]
    base = df.label.mean()
    S = {"pool": len(df), "positives": int(df.label.sum()), "base_rate": base}

    # 1. Exploited CVEs the standard signals miss
    S["pos_share_no_exploit_code"] = float((pos.any_exploit_code == 0).mean())
    S["pos_share_epss_below_1pct"] = float((pos.epss.fillna(0) < 0.01).mean())
    S["pos_share_no_code_and_low_epss"] = float(((pos.any_exploit_code == 0) & (pos.epss.fillna(0) < 0.01)).mean())

    # 2. Keyword lifts
    kw = {}
    for c in [c for c in X.columns if c.startswith("kw_")] + ["any_exploit_code", "vendor_matched"]:
        on = df[df[c] == 1]
        if len(on) >= 50:
            kw[c] = {"n": int(len(on)), "positives": int(on.label.sum()), "rate": float(on.label.mean()),
                     "lift": float(on.label.mean() / base)}
    S["feature_lifts"] = dict(sorted(kw.items(), key=lambda t: -t[1]["lift"]))

    # 3. Assigner (CNA) lifts
    a = lift_table(df, "assigner_key", min_n=150)
    S["assigner_lifts"] = {k: {"n": int(r["count"]), "positives": int(r["sum"]), "lift": float(r.lift)} for k, r in a.iterrows()}

    # 4. Repeat-target vendors
    S["pos_share_vendor_already_in_kev"] = float((pos.kev_vendor_log > 0).mean())
    S["all_share_vendor_already_in_kev"] = float((df.kev_vendor_log > 0).mean())
    S["top_positive_vendors"] = pos.vendor_guess.value_counts().head(12).to_dict()

    # 5. Leak evidence
    v = pd.read_csv(os.path.join(core.DATA, "vulnerabilities.csv"),
                    usecols=["cve_id", "nvd_status", "cvss3_source"], dtype=str).set_index("cve_id").loc[df.cve_id]
    an = v.nvd_status.isin(["Analyzed", "Modified"]).values
    nv = (v.cvss3_source == "nvd@nist.gov").values
    y = df.label.values == 1
    S["leak_analyzed_share"] = {"exploited": float(an[y].mean()), "others": float(an[~y].mean())}
    S["leak_nvd_cvss_share"] = {"exploited": float(nv[y].mean()), "others": float(nv[~y].mean())}

    # 6. CVSS is a weak signal: share of CRITICAL among exploited vs all
    raw = pd.read_csv(os.path.join(core.DATA, "vulnerabilities.csv"), usecols=["cve_id", "cvss3_score"]).set_index("cve_id")
    cv = raw.loc[df.cve_id].cvss3_score.values
    S["critical_cvss_count"] = int((cv >= 9).sum())
    S["critical_cvss_hit_rate"] = float(df.label.values[cv >= 9].mean())

    json.dump(S, open(os.path.join(OUT, "findings_stats.json"), "w"), indent=2, default=float)
    print(json.dumps({k: v for k, v in S.items() if k not in ("feature_lifts", "assigner_lifts")}, indent=2, default=float))
    print(pd.DataFrame(S["feature_lifts"]).T.round(4).to_string())
    print(pd.DataFrame(S["assigner_lifts"]).T.round(2).to_string())


if __name__ == "__main__":
    main()
