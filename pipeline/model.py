"""
The locked model. One code path is used for both the backtest and the 2026 scoring,
so the backtest numbers describe exactly what produced top500.csv.

Model: logistic regression on a short list of leak-safe features, trained on a
"rolling" pool (every CVE up to 24 months old in each training month, labelled by
whether it joined KEV within the next 4 months). Chosen on the 2025 backtest from the
variants logged in results/experiments.json; it was the best at the benchmark-scaled cutoff.
"""
import os
import pickle
import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler
from sklearn.impute import SimpleImputer
from sklearn.pipeline import make_pipeline

import core
from text_model import TextPrior

FEATURES = [
    "epss_log", "epss_missing", "any_exploit_code", "poc_github", "nuclei", "metasploit", "exploitdb",
    "text_score", "assigner_rate_log", "kev_vendor_log", "kev_product_log", "cvss4",
    "kw_auth_bypass", "kw_edge", "kw_rce", "kw_cmd_inj", "kw_dos", "kw_xss", "kw_wp_plugin",
    "kw_remote", "kw_local", "kw_needs_auth", "kw_user_click", "age",
    # adopted from results/robustness.json: never worse on any of 4 splits, +1 on one
    "kev_sim_max",
]

# Plain-English names used in explanations and the dashboard
FEATURE_LABELS = {
    "epss_log": "EPSS attack-probability score",
    "epss_missing": "no EPSS score yet",
    "any_exploit_code": "public exploit code exists",
    "poc_github": "proof-of-concept on GitHub",
    "nuclei": "Nuclei scanner template exists",
    "metasploit": "Metasploit module exists",
    "exploitdb": "Exploit-DB entry exists",
    "text_score": "description resembles past exploited CVEs",
    "assigner_rate_log": "reporting organisation's past exploited rate",
    "kev_vendor_log": "vendor's past KEV history",
    "kev_product_log": "product's past KEV history",
    "vendor_matched": "vendor previously targeted (in KEV)",
    "cvss4": "vendor CVSS 4 severity",
    "kw_auth_bypass": "authentication bypass / unauthenticated",
    "kw_edge": "edge or network device (VPN, firewall, gateway)",
    "kw_rce": "remote code execution",
    "kw_cmd_inj": "command injection",
    "kw_dos": "denial of service only",
    "kw_xss": "cross-site scripting",
    "kw_wp_plugin": "WordPress plugin",
    "kw_remote": "reachable remotely",
    "kw_local": "needs local access",
    "kw_needs_auth": "attacker needs an account / privileges",
    "kw_user_click": "needs a user to click or open something",
    "age": "time since publication",
    "kev_sim_max": "description closely matches a past exploited CVE",
    "kev_sim_top5": "description resembles several past exploited CVEs",
}

C = 0.05
# superset used when building training data, so experiments can pick subsets
ALL_FEATURES = FEATURES + ["vendor_matched", "kev_sim_top5"]
# Diversification: at most CAP_PER_500 CVEs from one vendor per 500 ranks
# (adopted from results/robustness.json: +1/+2 hits on the main split, no change on the second)
CAP_PER_500 = 20
TRAIN_NEG_FRAC = 0.15
MAX_AGE = 24
HORIZON = 4


def text_scores(vulns, kev, cve_ids, cutoff):
    tag = "_masked" if os.environ.get("MASK_CLAIMS") else ""
    path = os.path.join(core.CACHE, f"textprior_{pd.Timestamp(cutoff).date()}{tag}.pkl")
    if os.path.exists(path):
        tp = pickle.load(open(path, "rb"))
    else:
        tp = TextPrior().fit(vulns, kev, cutoff)
        pickle.dump(tp, open(path, "wb"))
    V = vulns.set_index("cve_id").loc[pd.Index(cve_ids).unique()]
    return dict(zip(V.index, tp.score(V.description, V.assigner_key))), tp


_KS = {}


def kev_similarity(kev, vulns, cutoff):
    if cutoff not in _KS:
        _KS[cutoff] = core.KevSimilarity(kev, vulns, cutoff)
    return _KS[cutoff]


def training_set(months_by_cutoff, label_cutoff, vulns, kev, sig, hist):
    """months_by_cutoff: {text/assigner knowledge cutoff: [months]} so each training row
    only sees text-prior and assigner statistics known before that row's year."""
    Xs, ys, ws = [], [], []
    for know_cut, months in months_by_cutoff.items():
        p = core.build_rolling_pool(months, label_cutoff, vulns, kev, sig, max_age_months=MAX_AGE,
                                    horizon_months=HORIZON, neg_frac=TRAIN_NEG_FRAC)
        ts, _ = text_scores(vulns, kev, p.cve_id, know_cut)
        X, m = core.build_features(p, vulns, kev, hist, ts, assigner_cutoff=know_cut,
                                   kevsim=kev_similarity(kev, vulns, know_cut))
        X["age"] = p.age_months.values
        Xs.append(X[[c for c in ALL_FEATURES if c in X.columns]]); ys.append(m.label.values); ws.append(p.weight.values)
    return pd.concat(Xs, ignore_index=True), np.concatenate(ys), np.concatenate(ws)


def fit(X, y, w, features=None):
    features = list(features or FEATURES)
    pipe = make_pipeline(SimpleImputer(strategy="median"), StandardScaler(),
                         LogisticRegression(C=C, class_weight="balanced", max_iter=5000))
    pipe.fit(X[features], y, logisticregression__sample_weight=w)
    pipe.features_ = features
    return pipe


def score(pipe, X):
    return pipe.decision_function(X[pipe.features_])


def contributions(pipe, X):
    Z = pipe[:-1].transform(X[pipe.features_])
    return pd.DataFrame(Z * pipe[-1].coef_[0], columns=pipe.features_, index=X.index)


def weights(pipe):
    return dict(sorted(zip(pipe.features_, pipe[-1].coef_[0].round(3)), key=lambda t: -abs(t[1])))


def add_age(X, meta):
    ends = meta.snapshot_month.map(core.month_end)
    X["age"] = ((ends - pd.to_datetime(meta.published)).dt.days / 30.4).clip(lower=0).values
    return X


def cap_for(k):
    return max(1, round(CAP_PER_500 * k / 500))


def capped_rank(scores, vendors, cap, k=500):
    """Diversify the top k: at most `cap` CVEs per vendor inside the top k. A vendor's
    extra CVEs move to just below rank k (not to the bottom), keeping their order.
    Returns a new score (higher = better)."""
    order = np.argsort(-np.asarray(scores), kind="stable")
    seen, top, deferred, rest = {}, [], [], []
    for i in order:
        if len(top) >= k:
            rest.append(i)
            continue
        v = vendors[i]
        if v is None or (isinstance(v, float) and np.isnan(v)):
            top.append(i)
            continue
        seen[v] = seen.get(v, 0) + 1
        (top if seen[v] <= cap else deferred).append(i)
    new = np.empty(len(order))
    for r, i in enumerate(top + deferred + rest):
        new[i] = -r
    return new
