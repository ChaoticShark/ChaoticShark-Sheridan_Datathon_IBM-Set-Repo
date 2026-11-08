"""
Automated checks that the pipeline is honest. Prints PASS / FAIL / WARN per check.
Run:  python pipeline/verify.py          (fast, ~2 min)
      python pipeline/verify.py --full   (also re-runs scoring to check reproducibility)
"""
import json
import os
import re
import sys
import subprocess
import numpy as np
import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import core
import model
from backtest import hits_at, TRAIN_MONTHS, TEST_MONTHS

ROOT = core.ROOT
RES = os.path.join(ROOT, "results")
results = []


def check(name, ok, detail="", warn=False):
    tag = "PASS" if ok else ("WARN" if warn else "FAIL")
    results.append((tag, name, detail))
    print(f"[{tag}] {name}" + (f"  -- {detail}" if detail else ""))


# ---------------------------------------------------------------- Fix 1: leakage
def check_features():
    banned = ["nvd_status", "n_affected_cpes", "n_references", "cwe", "cvss3", "cv_", "affected", "reference", "last_modified"]
    bad = [f for f in model.FEATURES if any(b in f for b in banned)]
    check("Model features contain no unsafe columns", not bad, f"features={len(model.FEATURES)} bad={bad}")
    print("       features used:", ", ".join(model.FEATURES))


def check_code_reads():
    files = ["core.py", "model.py", "text_model.py", "score_2026.py", "backtest.py"]
    pat = re.compile(r"affected_products\.csv|references\.csv|\"nvd_status\"\]|n_affected_cpes\"\]|\[\"n_references")
    hits = []
    for f in files:
        src = open(os.path.join(ROOT, "pipeline", f), encoding="utf-8").read()
        # ignore the documentation list of unsafe columns
        src = re.sub(r"UNSAFE_VULN_COLS = \[.*?\]", "", src)
        for m in pat.finditer(src):
            hits.append(f"{f}: {m.group(0)}")
    check("Scoring code never reads affected_products / references / nvd_status", not hits, "; ".join(hits))
    src = open(os.path.join(ROOT, "pipeline", "core.py"), encoding="utf-8").read()
    m = re.search(r"SAFE_VULN_COLS = \[(.*?)\]", src, re.S)
    loaded = re.findall(r'"(\w+)"', m.group(1))
    leaked = [c for c in loaded if c in core.UNSAFE_VULN_COLS]
    check("vulnerabilities.csv is loaded with safe columns only", not leaked, f"loaded={loaded}")


def leak_test(Xte, mte):
    """Prove the excluded columns DO leak: a model on only those columns, fit on the
    2024 season, finds far more 2025 positives than chance."""
    v = pd.read_csv(os.path.join(core.DATA, "vulnerabilities.csv"),
                    usecols=["cve_id", "nvd_status", "n_affected_cpes", "n_references", "cvss3_source"], dtype=str
                    ).set_index("cve_id")
    x = v.loc[mte.cve_id]
    L = pd.DataFrame({
        "analyzed": x.nvd_status.isin(["Analyzed", "Modified"]).astype(int).values,
        "cpes": np.log1p(pd.to_numeric(x.n_affected_cpes, errors="coerce").fillna(0)).values,
        "refs": np.log1p(pd.to_numeric(x.n_references, errors="coerce").fillna(0)).values,
        "nvd_cvss": (x.cvss3_source == "nvd@nist.gov").astype(int).values,
    })
    s = L.analyzed * 10 + L.refs + L.cpes * 0.1
    y = mte.label.values
    k = round(500 * len(y) / 72670)
    leaky_hits = hits_at(y, s.values, k)
    pos_analyzed = L.analyzed[y == 1].mean()
    neg_analyzed = L.analyzed[y == 0].mean()
    check("Leak test: excluded columns really do leak (justifies dropping them)",
          pos_analyzed > neg_analyzed + 0.2,
          f"'Analyzed by NIST' share: exploited={pos_analyzed:.0%} vs others={neg_analyzed:.0%}; "
          f"a ranking built only from leaky columns gets {leaky_hits} hits@{k}")
    return leaky_hits


def point_in_time(kev):
    hist = core.KevHistory(kev)
    rng = np.random.default_rng(1)
    vend = rng.choice(list(hist.vdates.keys()), 40)
    bad = 0
    for vname in vend:
        when = pd.Timestamp("2024-01-01") + pd.Timedelta(days=int(rng.integers(0, 700)))
        n, _ = hist._count_before(hist.vdates[vname], when)
        truth = int(((hist.k.v == vname) & (hist.k.date_added <= when)).sum())
        bad += n != truth
    check("KEV history only counts entries dated on/before the snapshot", bad == 0, f"{bad}/40 mismatches")


# ---------------------------------------------------------------- Fix 2: backtest
def check_backtest():
    path = os.path.join(RES, "backtest.json")
    if not os.path.exists(path):
        check("Backtest results exist", False, "run python pipeline/backtest.py")
        return None
    r = json.load(open(path))
    check("Train months all before test months", max(r["train_months"]) < min(r["test_months"]),
          f"train {r['train_months'][0]}..{r['train_months'][-1]}  test {r['test_months'][0]}..{r['test_months'][-1]}")
    check("Train labels/knowledge cut off before test period",
          r["train_label_cutoff"] < r["test_months"][0] + "-01" and r["test_knowledge_cutoff"] < r["test_months"][0] + "-01",
          f"train labels <= {r['train_label_cutoff']}, test-time knowledge <= {r['test_knowledge_cutoff']}")
    res = r["results"]
    k = [c for c in res["Ours"] if "scaled" in c][0]
    base = {n: v[k] for n, v in res.items() if not n.startswith("Ours")}
    check("Baselines are in a sane low range (no leak in the harness)", max(base.values()) <= 25, f"{base}")
    best = max(base.values())
    check("Ours beats the best baseline at the benchmark-scaled cutoff", res["Ours"][k] > best,
          f"ours={res['Ours'][k]} best baseline={best} ({k})")
    check("Ours >= best baseline at a flat top 500", res["Ours"]["hits@500"] >= max(v["hits@500"] for n, v in res.items() if not n.startswith("Ours")),
          f"ours={res['Ours']['hits@500']}")
    worse = [m["month"] for m in r["per_month"] if m["Ours"] < max(m[n] for n in base)]
    check("Never worse than the best baseline in any single month", not worse, f"worse in: {worse}", warn=True)
    check("Result is not suspiciously high (would suggest a leak)",
          res["Ours"][k] < 0.6 * r["test_positives"], f"{res['Ours'][k]} of {r['test_positives']} positives")
    b = r["bootstrap"]
    key = [x for x in b if "@" in x][0]
    check("Bootstrap: ours beats exploit-code baseline in most resamples", b[key]["p_ours_better"] >= 0.8,
          f"{b[key]['p_ours_better']:.0%} of 1000 resamples", warn=True)
    return r


def spot_check(kev):
    path = os.path.join(RES, "backtest_2025_top1000.csv")
    if not os.path.exists(path):
        return
    t = pd.read_csv(path)
    hits = t[(t.label == 1) & (t["rank"] <= 500)].head(5)
    kd = kev.set_index("cve_id").date_added
    bad = []
    for _, r in hits.iterrows():
        if not kd[r.cve_id] > core.month_end(r.snapshot_month):
            bad.append(r.cve_id)
    check("Spot check: backtest hits were added to KEV AFTER their snapshot month", not bad,
          ", ".join(f"{c} (snapshot {m}, KEV {kd[c].date()})" for c, m in zip(hits.cve_id, hits.snapshot_month)))


# ---------------------------------------------------------------- Fix 3: Granite
BANNED = re.compile(r"actively exploited|exploited in the wild|in the wild|confirmed (?:attack|exploit)|is being exploited|known exploited", re.I)


def check_granite():
    path = os.path.join(RES, "granite_explanations.csv")
    if not os.path.exists(path):
        check("Granite explanations generated", False, "not yet: run python pipeline/granite_layer.py (needs Ollama)", warn=True)
        return
    g = pd.read_csv(path)
    bad = g[g.explanation.fillna("").str.contains(BANNED)]
    check("Granite never claims a CVE is already exploited", len(bad) == 0, f"{len(bad)} of {len(g)} violate")
    check("Every explanation passed the grounding validator", (g.validated == 1).all(),
          f"{(g.validated == 1).sum()}/{len(g)} validated; rest use template fallback", warn=True)
    if "vendor_acc_2025" in g.columns:
        pass
    acc = os.path.join(RES, "granite_extraction_accuracy.json")
    if os.path.exists(acc):
        a = json.load(open(acc))
        check("Granite vendor extraction accuracy on 2025 CVEs (checked vs NIST product list)",
              a["vendor_accuracy"] >= 0.7, f"{a['vendor_accuracy']:.0%} on {a['n']} CVEs", warn=True)


# ---------------------------------------------------------------- Submission
def check_submission():
    t = pd.read_csv(os.path.join(ROOT, "top500.csv"), dtype=str)
    sb = pd.read_csv(os.path.join(core.DATA, "scoreboard_2026.csv"), usecols=["cve_id"], dtype=str)
    check("top500.csv has exactly one column named cve_id", list(t.columns) == ["cve_id"], f"columns={list(t.columns)}")
    check("top500.csv has 500 rows", len(t) == 500, f"rows={len(t)}")
    check("top500.csv has no duplicates", t.cve_id.is_unique)
    missing = (~t.cve_id.isin(sb.cve_id)).sum()
    check("Every top500 ID is in scoreboard_2026.csv", missing == 0, f"missing={missing}")


def check_legacy():
    stale = []
    for f in ["generate_dashboard.py", "Granite_CVE_Analyzer/granite_agent.py", "pipeline/build_dashboard.py"]:
        p = os.path.join(ROOT, f)
        if os.path.exists(p) and "affected_products.csv" in open(p, encoding="utf-8").read():
            stale.append(f)
    check("No active script reads affected_products.csv (v1 code moved to legacy/)", not stale,
          f"still present in: {stale} (legacy, not used for top500)", warn=True)


# ---------------------------------------------------------------- Docs + dashboard
def check_docs():
    r = json.load(open(os.path.join(RES, "backtest.json")))["results"]
    k = [c for c in r["Ours"] if "scaled" in c][0]
    ours_k, ours_500 = r["Ours"][k], r["Ours"]["hits@500"]
    best_k = max(v[k] for n, v in r.items() if not n.startswith("Ours"))
    for doc in ("README.md", "DATATHON_ANALYSIS_FINDINGS.md"):
        txt = open(os.path.join(ROOT, doc), encoding="utf-8").read()
        ok = f"**{ours_k}**" in txt and f"**{ours_500}**" in txt and f"| {best_k} |" in txt
        check(f"{doc} quotes the current backtest numbers", ok, f"expects ours {ours_k}/{ours_500}, best baseline {best_k}")
    dash = os.path.join(ROOT, "dashboard.html")
    ranked = os.path.join(RES, "scoreboard_ranked.csv")
    check("dashboard.html is newer than the latest scoring run",
          os.path.exists(dash) and os.path.getmtime(dash) >= os.path.getmtime(ranked),
          "rebuild with python pipeline/build_dashboard.py")


def check_description_claims():
    """Descriptions are today's versions. If a scoreboard description claims exploitation and
    cites a date AFTER the CVE's snapshot month, the text was edited later and would leak."""
    months = {m: i for i, m in enumerate(["january", "february", "march", "april", "may", "june", "july",
                                          "august", "september", "october", "november", "december"], 1)}
    v = core.load_vulns().set_index("cve_id")
    sb = pd.read_csv(os.path.join(core.DATA, "scoreboard_2026.csv"), usecols=["cve_id", "snapshot_month"], dtype=str)
    bad, n = [], 0
    for c, snap in zip(sb.cve_id, sb.snapshot_month):
        t = v.description_raw.get(c, "")
        m = core._EXPL.search(t)
        if not m:
            continue
        n += 1
        sent = t[max(0, t.rfind(".", 0, m.start()) + 1): t.find(".", m.end()) if t.find(".", m.end()) > 0 else len(t)]
        dates = [f"{y}-{int(mo):02d}" for y, mo in re.findall(r"(?<![\w-])(20\d\d)-(0[1-9]|1[0-2])(?!\d)", sent)]
        dates += [f"{y}-{months[mn.lower()]:02d}" for mn, y in
                  re.findall(r"(January|February|March|April|May|June|July|August|September|October|November|December)\s+(20\d\d)", sent, re.I)]
        # open-ended "through 2026" written in 2026 means up to now, so count it as that year's start
        dates += [f"{y}-01" for y in re.findall(r"through (20\d\d)\b", sent)]
        late = [d for d in dates if d > snap]
        if late:
            bad.append(f"{c} (snapshot {snap}, cites {late})")
    check("No scoreboard description cites exploitation dated after its snapshot", not bad,
          f"{n} descriptions mention exploitation; post-snapshot: {bad[:5]}")


def check_granite_coverage():
    path = os.path.join(RES, "granite_cache.jsonl")
    if not os.path.exists(path):
        return
    cache = {}
    for line in open(path, encoding="utf-8"):
        d = json.loads(line); cache[d["cve_id"]] = d
    t = pd.read_csv(os.path.join(ROOT, "top500.csv")).cve_id
    have = t.isin(cache).sum()
    check("Granite covers the current top 500", have == 500, f"{have}/500 explained", warn=True)
    bad = [c for c, d in cache.items() if BANNED.search(str(d.get("explanation", "")))]
    check("No cached Granite text claims a CVE is already exploited", not bad, f"{len(bad)} violations")


def check_dashboard_features():
    """Time Machine, standard-ranking comparison, watchlist triggers, vendor cap."""
    tp = os.path.join(RES, "timemachine_2025.json")
    if not os.path.exists(tp):
        check("Time Machine replay exists", False, "run python pipeline/backtest.py")
        return
    tm, bt = json.load(open(tp)), json.load(open(os.path.join(RES, "backtest.json")))
    k = bt["k_scaled"]
    kc = [c for c in bt["results"]["Ours"] if "scaled" in c][0]
    caught = sum(c["ranks"]["Ours"] <= k for c in tm["cves"])
    check("Time Machine matches the backtest (same CVEs caught)",
          caught == bt["results"]["Ours"][kc] and len(tm["cves"]) == bt["test_positives"],
          f"replay {caught}/{len(tm['cves'])}, backtest {bt['results']['Ours'][kc]}/{bt['test_positives']}")
    check("Patch-budget slider data is complete (within-month ranks; month pools add up)",
          all("mranks" in c for c in tm["cves"]) and sum(tm.get("month_pool", {}).values()) == tm["pool"],
          f"month pools sum {sum(tm.get('month_pool', {}).values())} vs pool {tm['pool']}")
    check("Time Machine lead times are all after the snapshot month", all(c["lead_days"] > 0 for c in tm["cves"]),
          f"min lead {min(c['lead_days'] for c in tm['cves'])} days")
    r = pd.read_csv(os.path.join(RES, "scoreboard_ranked.csv"), low_memory=False)
    need = {"rank_cvss", "rank_code", "capped", "trig_code", "trig_epss"}
    check("Ranked file has the comparison and trigger columns", need <= set(r.columns), f"missing={need - set(r.columns)}")
    if need <= set(r.columns):
        top = r[r["rank"] <= 500]
        check("Watchlist triggers only appear outside the top 500",
              top.trig_code.sum() == 0 and top.trig_epss.isna().all() and top.capped.sum() == 0)
        per = top.brand.fillna("").value_counts()
        per = per[per.index != ""]
        check("Vendor cap holds in the 2026 top 500 (max 20 per vendor)", per.max() <= 20, f"max {per.idxmax()}={per.max()}")
        words = top.description.fillna("").str.upper()
        biggest = max(words.str.contains(v.upper(), regex=False).sum() for v in per.index[:10])
        check("No vendor slips past the cap under a second name (top-10 vendors by name in description)",
              biggest <= 22, f"max mentions {biggest}", warn=True)


def reproducibility():
    before = pd.read_csv(os.path.join(ROOT, "top500.csv")).cve_id.tolist()
    subprocess.run([sys.executable, os.path.join(ROOT, "pipeline", "score_2026.py")], check=True,
                   stdout=subprocess.DEVNULL)
    after = pd.read_csv(os.path.join(ROOT, "top500.csv")).cve_id.tolist()
    check("Re-running scoring gives the identical top 500", before == after,
          f"{len(set(before) & set(after))}/500 overlap")


def main():
    kev = core.load_kev()
    print("== Fix 1: no leaky columns ==")
    check_features(); check_code_reads(); point_in_time(kev); check_description_claims()
    print("== Fix 2: honest backtest ==")
    r = check_backtest(); spot_check(kev)
    if r is not None:
        vulns, sig = core.load_vulns(), core.load_signals()
        pool = core.build_pool(TEST_MONTHS, "2025-12-31", vulns, kev, sig)
        leak_test(None, pool.assign(label=pool.label))
    print("== Fix 3/4: Granite ==")
    check_granite(); check_granite_coverage()
    print("== Docs + dashboard ==")
    check_docs(); check_dashboard_features()
    print("== Submission ==")
    check_submission(); check_legacy()
    if "--full" in sys.argv:
        reproducibility()
    n = {t: sum(1 for r in results if r[0] == t) for t in ("PASS", "WARN", "FAIL")}
    print(f"\nSUMMARY: {n['PASS']} pass, {n['WARN']} warn, {n['FAIL']} fail")
    sys.exit(1 if n["FAIL"] else 0)


if __name__ == "__main__":
    main()
