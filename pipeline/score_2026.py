"""
Score the 72,670 scoreboard CVEs with the locked model and write:
  top500.csv                      - submission file, one column: cve_id
  results/top500_detailed.csv     - the same 500 with scores and plain-English reasons
  results/scoreboard_ranked.csv   - all 72,670 CVEs ranked (for the dashboard)

Training uses everything known by 2025-12-31 (the end of the KEV file we were given).
Each scoreboard CVE only uses its own snapshot-month EPSS / exploit flags.
Run:  python pipeline/score_2026.py
"""
import json
import os
import shutil
import sys
import numpy as np
import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import core
import model

OUT = os.path.join(core.ROOT, "results")
os.makedirs(OUT, exist_ok=True)

TRAIN = {
    "2023-12-31": [f"2024-{m:02d}" for m in range(1, 13)],
    "2024-12-31": [f"2025-{m:02d}" for m in range(1, 11)],
}
KNOWLEDGE_CUTOFF = "2025-12-31"
BINARY = set(core.SIGNAL_FLAGS) | {"any_exploit_code", "epss_missing"} | {f for f in model.FEATURES if f.startswith("kw_")}


def reasons(contrib_row, X_row, n=3):
    """Top positive drivers of a CVE's score, as plain English."""
    out = []
    for f, v in contrib_row.sort_values(ascending=False).items():
        if v <= 0 or len(out) >= n:
            break
        if f in ("epss_missing", "age", "kw_needs_auth", "kw_user_click", "cvss4"):
            continue
        # a yes/no feature is only a reason when it is actually present
        # (otherwise "not a WordPress plugin" would show up as "WordPress plugin")
        if f in BINARY and X_row[f] != 1:
            continue
        if f in ("kev_vendor_log", "kev_product_log", "text_score", "epss_log") and X_row[f] <= 0 and f != "text_score":
            continue
        out.append(model.FEATURE_LABELS[f])
    return "; ".join(out)


TAGS = [("kw_rce", "RCE"), ("kw_cmd_inj", "Command injection"), ("kw_auth_bypass", "Auth bypass"),
        ("kw_deserial", "Deserialization"), ("kw_path_trav", "Path traversal"), ("kw_upload", "File upload"),
        ("kw_sqli", "SQL injection"), ("kw_memory", "Memory corruption"), ("kw_privesc", "Privilege escalation"),
        ("kw_xss", "XSS"), ("kw_dos", "DoS"), ("kw_edge", "Edge device"), ("kw_browser", "Browser"),
        ("kw_wp_plugin", "WordPress plugin")]


def tags(X_row):
    return "; ".join(lbl for f, lbl in TAGS if X_row.get(f, 0) == 1)


def evidence(m, X_row, kev_dates):
    """Concrete, checkable facts behind a ranking (all known at the snapshot)."""
    parts = []
    v = m.get("vendor_guess")
    nv = int(round(np.expm1(X_row["kev_vendor_log"]))) if "kev_vendor_log" in X_row else 0
    if isinstance(v, str) and v and nv > 0:
        parts.append(f"{v}: {nv} earlier KEV entr{'y' if nv == 1 else 'ies'}")
    code = [n for n, f in (("Exploit-DB", "exploitdb"), ("Metasploit", "metasploit"),
                           ("Nuclei", "nuclei"), ("GitHub PoC", "poc_github")) if m.get(f) == 1]
    if code:
        parts.append("public exploit code: " + ", ".join(code))
    e = m.get("epss")
    if e is not None and not pd.isna(e):
        parts.append(f"EPSS {float(e):.4f}")
    nk, ns = m.get("nearest_kev"), m.get("nearest_kev_sim")
    if isinstance(nk, str) and nk and ns is not None and ns >= 0.30:
        when = kev_dates.get(nk)
        parts.append(f"looks like {nk} (similarity {ns:.2f}, exploited {when:%b %Y})" if when is not None
                     else f"looks like {nk} (similarity {ns:.2f})")
    return "; ".join(parts)


EPSS_STEPS = [0.001, 0.002, 0.005, 0.01, 0.02, 0.05, 0.1, 0.2, 0.5, 1.0]


def add_comparisons(full, X, pipe, sb):
    """Display-only columns (they do not change the ranking or top500.csv):
    rank_cvss / rank_code : where the two standard rankings would put each CVE among all 72,670
                            (CVSS 3 is used here only for this comparison, never by the model).
    trig_code             : watchlist CVE (501-3,000) would enter the top 500 if public exploit code appeared
    trig_epss             : smallest EPSS that would move it into the top 500 (blank = no EPSS is enough)
    capped                : already scores like a top-500 CVE but its vendor hit the 20-per-500 cap"""
    raw = pd.read_csv(os.path.join(core.DATA, "vulnerabilities.csv"), usecols=["cve_id", "cvss3_score"])
    cv = full.cve_id.map(raw.set_index("cve_id").cvss3_score).fillna(0).values
    ep = full.epss.fillna(0).values
    code = full[core.SIGNAL_FLAGS].max(axis=1).values
    for name, sc in (("rank_cvss", cv + 1e-3 * ep), ("rank_code", code * 10 + ep)):
        order = np.argsort(-sc, kind="stable")
        r = np.empty(len(sc), dtype=int)
        r[order] = np.arange(1, len(sc) + 1)
        full[name] = r

    bar = full.loc[full["rank"] <= 500, "score"].min()       # raw score needed to make the top 500
    watch = full.index[(full["rank"] > 500) & (full["rank"] <= 3000)]
    Xw = X.loc[watch]
    full["capped"] = 0
    full.loc[watch, "capped"] = (full.loc[watch, "score"] >= bar).astype(int)
    Xc = Xw.copy()
    Xc["poc_github"] = 1
    Xc["any_exploit_code"] = 1
    full["trig_code"] = 0
    full.loc[watch, "trig_code"] = (model.score(pipe, Xc) >= bar).astype(int)
    need = pd.Series(np.nan, index=watch)
    for e in reversed(EPSS_STEPS):                          # keep the smallest step that clears the bar
        Xe = Xw.copy()
        Xe["epss_missing"] = 0
        Xe["epss_log"] = np.log10(max(e, 1e-5))
        ok = (model.score(pipe, Xe) >= bar) & (full.loc[watch, "epss"].fillna(0).values < e)
        need[ok] = e
    full["trig_epss"] = np.nan
    full.loc[watch, "trig_epss"] = need.values
    return ["rank_cvss", "rank_code", "capped", "trig_code", "trig_epss"]


def main():
    vulns, kev, sig = core.load_vulns(), core.load_kev(), core.load_signals()
    hist = core.KevHistory(kev)

    Xtr, ytr, wtr = model.training_set(TRAIN, KNOWLEDGE_CUTOFF, vulns, kev, sig, hist)
    pipe = model.fit(Xtr, ytr, wtr)
    print("trained on", len(Xtr), "rows,", int(ytr.sum()), "positive rows")

    sb = core.load_scoreboard()
    pool = sb.drop(columns=["published"]).merge(vulns[["cve_id", "published"]], on="cve_id", how="left")
    ts, _ = model.text_scores(vulns, kev, pool.cve_id, KNOWLEDGE_CUTOFF)
    X, meta = core.build_features(pool, vulns, kev, hist, ts, assigner_cutoff=KNOWLEDGE_CUTOFF, kevsim=model.kev_similarity(kev, vulns, KNOWLEDGE_CUTOFF))
    X = model.add_age(X, meta)
    s = model.score(pipe, X)
    contrib = model.contributions(pipe, X)

    meta = meta.assign(score=s)
    # vendor cap: at most model.CAP_PER_500 CVEs per vendor in the top 500 (extras move to rank 501+)
    order_score = model.capped_rank(s, meta.brand.values, model.cap_for(500), 500)
    meta["rank"] = pd.Series(order_score, index=meta.index).rank(ascending=False, method="first").astype(int)
    meta["epss"] = pool.epss.values
    for c in core.SIGNAL_FLAGS:
        meta[c] = pool[c].values
    meta = meta.sort_values("rank")
    # show users the original description (the model saw it with exploitation claims removed)
    meta["description"] = meta.cve_id.map(vulns.set_index("cve_id").description_raw)

    # submission file: one column, cve_id
    sub = os.path.join(core.ROOT, "top500.csv")
    legacy = os.path.join(OUT, "legacy_top500_v1_leaky.csv")
    if os.path.exists(sub) and not os.path.exists(legacy):
        shutil.copy(sub, legacy)        # keep the old version for reference
    meta.head(500)[["cve_id"]].to_csv(sub, index=False)

    kev_dates = kev.set_index("cve_id").date_added.to_dict()
    top = meta.head(500).copy()
    top["why"] = [reasons(contrib.loc[i], X.loc[i]) for i in top.index]
    top["evidence"] = [evidence(top.loc[i], X.loc[i], kev_dates) for i in top.index]
    top["vendor_guess"] = top.vendor_guess.fillna("")
    top["product_guess"] = top.product_guess.fillna("")
    top["description"] = top.description.str.slice(0, 400)
    cols = ["rank", "cve_id", "score", "published", "snapshot_month", "epss"] + core.SIGNAL_FLAGS + \
           ["assigner_key", "vendor_guess", "brand", "product_guess", "nearest_kev", "nearest_kev_sim", "why", "evidence", "description"]
    top[cols].to_csv(os.path.join(OUT, "top500_detailed.csv"), index=False)

    full = meta.copy()
    full["why"] = ""
    full["evidence"] = ""
    head = full.head(3000).index
    full.loc[head, "why"] = [reasons(contrib.loc[i], X.loc[i]) for i in head]
    full.loc[head, "evidence"] = [evidence(full.loc[i], X.loc[i], kev_dates) for i in head]
    full["vendor_kev_n"] = np.round(np.expm1(X.loc[full.index, "kev_vendor_log"])).astype(int)
    full["tags"] = ""
    full.loc[head, "tags"] = [tags(X.loc[i]) for i in head]
    full["description"] = full.description.str.slice(0, 300)
    extra = add_comparisons(full, X, pipe, sb)
    full[cols + ["vendor_kev_n", "tags"] + extra].to_csv(os.path.join(OUT, "scoreboard_ranked.csv"), index=False)

    json.dump({"weights": model.weights(pipe), "train_rows": int(len(Xtr)), "train_pos": int(ytr.sum()),
               "knowledge_cutoff": KNOWLEDGE_CUTOFF},
              open(os.path.join(OUT, "final_model.json"), "w"), indent=2, default=float)
    print(top[["rank", "cve_id", "why", "evidence"]].head(15).to_string(index=False))


if __name__ == "__main__":
    main()
