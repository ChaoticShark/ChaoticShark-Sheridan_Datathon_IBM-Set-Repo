"""
Leak-safe data loading, backtest pool construction and feature building.

Every feature here must be knowable at the end of a CVE's snapshot month.
See COLUMNS_USED.md for the full list of columns used and excluded.
"""
import os
import re
import pickle
import numpy as np
import pandas as pd

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.path.join(ROOT, "data")
CACHE = os.path.join(DATA, "cache")
os.makedirs(CACHE, exist_ok=True)

# Columns from vulnerabilities.csv that we allow the model to see.
SAFE_VULN_COLS = [
    "cve_id", "published", "assigner", "description",
    "cvss3_score", "cvss3_vector", "cvss3_source",
    "attack_vector", "attack_complexity", "privileges_required",
    "user_interaction", "scope",
    "confidentiality_impact", "integrity_impact", "availability_impact",
    "cvss4_score",
]
# Columns we deliberately never load for modelling (they leak the answer).
UNSAFE_VULN_COLS = ["nvd_status", "n_affected_cpes", "n_references", "last_modified", "cwe_ids"]

NVD_SOURCE = "nvd@nist.gov"
SIGNAL_FLAGS = ["exploitdb", "metasploit", "nuclei", "poc_github"]


# Claims about real-world exploitation (not generic wording like "could be exploited by")
_EXPL = re.compile(r"\b(?:in the wild|actively exploit\w*|known to be exploit\w*|(?<!could )(?<!would )(?<!might )(?:has|have|had|was|were)"
                   r" (?:been )?exploited|may have been exploited|known exploitation|evidence of exploitation|"
                   r"active exploitation|targeted exploitation|exploitation (?:attempts|activity))\b", re.I)
_SENT = re.compile(r"(?<=[.!?])\s+(?=[A-Z(\"'])")   # sentence breaks, not version dots like 4.4.20


def mask_exploitation(text):
    """Remove claims about real-world exploitation (e.g. 'as exploited in the wild in August 2026',
    'no known exploitation'); descriptions can be edited after an attack. If the claim is a
    trailing clause, only that clause is cut; otherwise the whole sentence is dropped."""
    if not text:
        return ""
    out = []
    for sn in _SENT.split(text):
        m = _EXPL.search(sn)
        if not m:
            out.append(sn)
            continue
        cut = max(sn.rfind(",", 0, m.start()), sn.rfind(";", 0, m.start()))
        if cut > 20:
            out.append(sn[:cut] + ".")
    return " ".join(out)


def _cached(name, fn):
    path = os.path.join(CACHE, name + ".pkl")
    if os.path.exists(path):
        with open(path, "rb") as f:
            return pickle.load(f)
    obj = fn()
    with open(path, "wb") as f:
        pickle.dump(obj, f, protocol=pickle.HIGHEST_PROTOCOL)
    return obj


def load_vulns():
    def _load():
        v = pd.read_csv(os.path.join(DATA, "vulnerabilities.csv"), usecols=SAFE_VULN_COLS, dtype=str)
        v["published"] = pd.to_datetime(v["published"])
        v["description_raw"] = v["description"].fillna("")
        # The model sees the description as published. Claims like "as exploited in the wild in
        # August 2026" were checked: in the 2026 scoreboard every such claim is dated at or before
        # the CVE's publication month, i.e. written when the CVE was assigned, not added later.
        # verify.py re-checks this on every run. Masking them (MASK_CLAIMS=1) is kept as an option;
        # it lowered the 2025 backtest from 18 to 16 by hiding legitimate at-publication signals.
        v["description"] = (v["description_raw"].map(mask_exploitation) if os.environ.get("MASK_CLAIMS")
                            else v["description_raw"])
        for c in ["cvss3_score", "cvss4_score"]:
            v[c] = pd.to_numeric(v[c], errors="coerce")
        # CVSS 3 is only trusted when the reporting organisation (CNA) supplied it.
        # NIST's own score appears only after NIST analyses the CVE, and NIST analyses
        # exploited CVEs first, so an NVD-sourced score is a leak.
        nvd = v["cvss3_source"] == NVD_SOURCE
        cvss_cols = ["cvss3_score", "cvss3_vector", "attack_vector", "attack_complexity",
                     "privileges_required", "user_interaction", "scope",
                     "confidentiality_impact", "integrity_impact", "availability_impact"]
        for c in cvss_cols:
            v.loc[nvd, c] = np.nan
        v["cvss_from_cna"] = (~nvd & v["cvss3_score"].notna()).astype(int)
        v["assigner_key"] = v["assigner"].fillna("unknown").str.lower().str.replace(r"^.*@", "", regex=True)
        return v
    return _cached("vulns" + ("_masked" if os.environ.get("MASK_CLAIMS") else ""), _load)


def load_kev():
    k = pd.read_csv(os.path.join(DATA, "known_exploited.csv"), dtype=str)
    k["date_added"] = pd.to_datetime(k["date_added"])
    return k


def load_signals():
    def _load():
        parts = []
        for y in (2024, 2025):
            s = pd.read_csv(os.path.join(DATA, f"exploit_signals_{y}.csv"),
                            dtype={"month": str, "cve_id": str})
            parts.append(s)
        s = pd.concat(parts, ignore_index=True)
        for c in SIGNAL_FLAGS + ["in_kev"]:
            s[c] = s[c].fillna(0).astype(np.int8)
        return s
    return _cached("signals", _load)


def load_scoreboard():
    s = pd.read_csv(os.path.join(DATA, "scoreboard_2026.csv"), dtype={"cve_id": str, "snapshot_month": str})
    s["published"] = pd.to_datetime(s["published"])
    for c in SIGNAL_FLAGS:
        s[c] = s[c].fillna(0).astype(np.int8)
    return s


def month_end(m):
    return pd.Period(m, "M").end_time.normalize()


# ---------------------------------------------------------------------------
# Backtest pools: rebuild the scoreboard setup on 2024/2025 data
# ---------------------------------------------------------------------------
def build_pool(months, label_cutoff, vulns, kev, signals, include_fast=False):
    """CVEs published in each month, not in KEV by end of that month.
    label = added to KEV after the snapshot and on/before label_cutoff.
    include_fast=True (training only) also keeps CVEs that were already exploited by
    the end of their publish month as extra positives ("fast" zero-day style cases)."""
    label_cutoff = pd.Timestamp(label_cutoff)
    kev_date = kev.set_index("cve_id")["date_added"]
    rows = []
    for m in months:
        end = month_end(m)
        start = pd.Period(m, "M").start_time
        p = vulns.loc[(vulns.published >= start) & (vulns.published <= end), ["cve_id", "published"]].copy()
        da = p.cve_id.map(kev_date)
        sig = signals[signals.month == m].drop(columns=["month"])
        p = p.merge(sig, on="cve_id", how="left")
        fast = (da.values <= end) | (p["in_kev"].fillna(0).values == 1)
        p["fast"] = fast.astype(int)
        if not include_fast:
            p = p[~fast]
        da = p.cve_id.map(kev_date)
        p["label"] = (((da > end) & (da <= label_cutoff)) | (p.fast == 1)).astype(int)
        p["snapshot_month"] = m
        p = p.drop(columns=["in_kev"])
        rows.append(p)
    pool = pd.concat(rows, ignore_index=True)
    for c in SIGNAL_FLAGS:
        pool[c] = pool[c].fillna(0).astype(np.int8)
    return pool


# ---------------------------------------------------------------------------
# Vendor / product history (point in time, from KEV only)
# ---------------------------------------------------------------------------
_word = re.compile(r"[a-z0-9][a-z0-9\-\.]+")


def _norm(s):
    return re.sub(r"\s+", " ", str(s).lower()).strip()


class KevHistory:
    """Answers: how often was this vendor/product in KEV before date X?
    Vendor/product are found by matching KEV names inside the CVE description
    (text available at publication), not via NIST's affected-product list."""

    GENERIC = {"multiple", "unknown", "n/a", "the", "linux", "open source", "server",
               "windows", "web", "client", "framework", "multiple products", "multiple vendors"}

    def __init__(self, kev):
        k = kev.copy()
        k["v"] = k["vendor"].map(_norm)
        k["p"] = k["product"].map(_norm)
        self.k = k
        self.vendors = sorted({v for v in k.v if len(v) >= 3 and v not in self.GENERIC}, key=len, reverse=True)
        self.products = sorted({p for p in k.p if len(p) >= 4 and p not in self.GENERIC}, key=len, reverse=True)
        # (?<![./_-]) stops file names like "index.php" matching the vendor "php"
        self._vre = re.compile(r"(?<![./_-])\b(" + "|".join(map(re.escape, self.vendors)) + r")\b(?!\.\w)")
        self._pre = re.compile(r"(?<![./_-])\b(" + "|".join(map(re.escape, self.products)) + r")\b(?!\.\w)")
        self.vdates = {v: np.sort(g.date_added.values) for v, g in k.groupby("v")}
        self.pdates = {p: np.sort(g.date_added.values) for p, g in k.groupby("p")}
        self.rdates = {v: np.sort(g.date_added.values) for v, g in k[k.known_ransomware_use == "Known"].groupby("v")}

    VENDOR_WINDOW = 100   # chars: the affected vendor is named early; later mentions are incidental
                          # (e.g. "...via sudo", "PHP code injection", "Dockwatch")

    def match(self, text):
        t = _norm(text)
        vm = self._vre.search(t)
        if vm and vm.start() > self.VENDOR_WINDOW:
            vm = None
        pm = self._pre.search(t)
        if pm and pm.start() > self.VENDOR_WINDOW:
            pm = None
        return (vm.group(1) if vm else None), (pm.group(1) if pm else None)

    @staticmethod
    def _count_before(dates, when):
        if dates is None:
            return 0, np.nan
        n = int(np.searchsorted(dates, np.datetime64(when), side="right"))
        if n == 0:
            return 0, np.nan
        days = (np.datetime64(when) - dates[n - 1]) / np.timedelta64(1, "D")
        return n, float(days)

    def features(self, descriptions, assigners, whens):
        out = np.zeros((len(descriptions), 6), dtype=float)
        vend, prod = [], []
        for i, (d, a, w) in enumerate(zip(descriptions, assigners, whens)):
            v, p = self.match(d)
            if v is None and isinstance(a, str):
                # fall back to the assigner's domain, e.g. fortinet.com -> fortinet
                dom = a.split(".")[0]
                if dom in self.vdates:
                    v = dom
            vend.append(v)
            prod.append(p)
            nv, dv = self._count_before(self.vdates.get(v), w)
            npd, _ = self._count_before(self.pdates.get(p), w)
            nr, _ = self._count_before(self.rdates.get(v), w)
            # recent activity: KEV adds for this vendor in the 365 days before w
            dates = self.vdates.get(v)
            recent = 0
            if dates is not None:
                lo = np.searchsorted(dates, np.datetime64(w) - np.timedelta64(365, "D"))
                hi = np.searchsorted(dates, np.datetime64(w), side="right")
                recent = hi - lo
            out[i] = [np.log1p(nv), np.log1p(npd), np.log1p(nr), np.log1p(recent),
                      0.0 if np.isnan(dv) else np.exp(-dv / 365.0), float(v is not None)]
        cols = ["kev_vendor_log", "kev_product_log", "kev_vendor_ransom_log",
                "kev_vendor_recent_log", "kev_vendor_recency", "vendor_matched"]
        return pd.DataFrame(out, columns=cols), vend, prod


# ---------------------------------------------------------------------------
# Description keyword flags (cheap, interpretable)
# ---------------------------------------------------------------------------
KEYWORDS = {
    "kw_rce": r"remote code execution|execute arbitrary code|arbitrary code execution|code injection",
    "kw_cmd_inj": r"command injection|os command|execute arbitrary (?:os |system )?commands",
    "kw_auth_bypass": r"authentication bypass|bypass authentication|without authentication|unauthenticated|missing authentication",
    "kw_privesc": r"privilege escalation|elevation of privilege|escalate privileges|gain (?:root|system|administrator)",
    "kw_path_trav": r"path traversal|directory traversal",
    "kw_deserial": r"deserializ",
    "kw_upload": r"arbitrary file upload|upload arbitrary|unrestricted upload",
    "kw_sqli": r"sql injection",
    "kw_memory": r"use[- ]after[- ]free|out[- ]of[- ]bounds write|heap[- ]based buffer overflow|type confusion|memory corruption",
    "kw_xss": r"cross[- ]site scripting|\bxss\b",
    "kw_dos": r"denial of service",
    "kw_edge": r"\bvpn\b|firewall|gateway|router|\bssl[- ]vpn|load balancer|appliance|edge|remote access|secure access|connect secure|fortigate|fortios|pan-os|netscaler",
    "kw_wp_plugin": r"wordpress|plugin for wordpress",
    "kw_in_wild": r"exploited in the wild|may have been exploited|actively exploited|exploitation in the wild",
    "kw_browser": r"chrome|chromium|webkit|safari|firefox|v8\b",
    # access requirements, read from the text instead of the (leaky) CVSS 3 vector
    "kw_remote": r"remote attacker|remotely|remote,? unauthenticated|over the network|via the network|crafted (?:http|request|packet)",
    "kw_local": r"local attacker|local user|locally|physical access|local access",
    "kw_needs_auth": r"authenticated (?:user|attacker|admin)|administrator privileges|admin privileges|requires authentication|with (?:admin|high) privileges|contributor|subscriber",
    "kw_user_click": r"user interaction|convince a user|trick a user|open a (?:crafted|malicious)|visit a (?:crafted|malicious)",
}
_kw = {k: re.compile(v) for k, v in KEYWORDS.items()}


def keyword_features(descriptions):
    d = pd.Series(descriptions).fillna("").str.lower()
    return pd.DataFrame({k: d.str.contains(r).astype(np.int8).values for k, r in _kw.items()})


# ---------------------------------------------------------------------------
# Assigner (CNA) historical base rate, point in time
# ---------------------------------------------------------------------------
def assigner_rates(vulns, kev, cutoff, min_year=2015):
    """KEV rate per assigner among CVEs published in [min_year, cutoff), KEV adds <= cutoff."""
    cutoff = pd.Timestamp(cutoff)
    h = vulns[(vulns.published >= f"{min_year}-01-01") & (vulns.published < cutoff)][["cve_id", "assigner_key"]]
    kd = kev[kev.date_added <= cutoff].cve_id
    h = h.assign(y=h.cve_id.isin(kd).astype(int))
    g = h.groupby("assigner_key").y.agg(["sum", "count"])
    prior = h.y.mean()
    # smoothed rate (empirical Bayes, strength 200)
    rate = (g["sum"] + prior * 200) / (g["count"] + 200)
    return rate.to_dict(), prior


CVSS_MAP = {
    "attack_vector": {"NETWORK": 1.0, "ADJACENT_NETWORK": 0.6, "LOCAL": 0.3, "PHYSICAL": 0.1},
    "attack_complexity": {"LOW": 1.0, "HIGH": 0.0},
    "privileges_required": {"NONE": 1.0, "LOW": 0.5, "HIGH": 0.0},
    "user_interaction": {"NONE": 1.0, "REQUIRED": 0.0},
    "scope": {"CHANGED": 1.0, "UNCHANGED": 0.0},
}


def build_features(pool, vulns, kev, hist, text_score=None, assigner_cutoff=None, kevsim=None):
    """Feature matrix for a pool of (cve_id, snapshot_month, signals...)."""
    df = pool.merge(vulns.drop(columns=["published"]), on="cve_id", how="left")
    whens = [month_end(m) for m in df.snapshot_month]
    X = pd.DataFrame(index=df.index)
    # exploit signals at snapshot
    epss = df["epss"].astype(float)
    X["epss_missing"] = epss.isna().astype(int)
    X["epss_log"] = np.log10(epss.fillna(1e-5).clip(1e-5, 1))
    # EPSS changed model in March 2025: use within-month percentile so versions are comparable
    X["epss_pct"] = df.assign(e=epss.fillna(0)).groupby("snapshot_month").e.rank(pct=True).values
    X["epss_v3"] = df.snapshot_month.lt("2025-03").astype(int)
    for c in SIGNAL_FLAGS:
        X[c] = df[c].fillna(0).astype(int)
    X["any_exploit_code"] = X[SIGNAL_FLAGS].max(axis=1)
    # CVSS 3 is NOT used: whether a CVE has a CNA score or an NVD score depends on whether
    # NIST analysed it, which leaks the label (54% of test positives vs 37% of negatives
    # had an NVD-sourced score). CVSS 4 comes only from the reporting organisation, so it's kept.
    X["cvss4"] = df["cvss4_score"].fillna(-1)
    # assigner base rate
    if assigner_cutoff is not None:
        rates, prior = assigner_rates(vulns, kev, assigner_cutoff)
        X["assigner_rate_log"] = np.log10(df.assigner_key.map(rates).fillna(prior))
    # vendor/product KEV history
    hf, vend, prod = hist.features(df.description.values, df.assigner_key.values, whens)
    X = pd.concat([X, hf.set_index(X.index)], axis=1)
    # description keywords
    X = pd.concat([X, keyword_features(df.description.values).set_index(X.index)], axis=1)
    X["desc_len_log"] = np.log1p(df.description.str.len().fillna(0))
    if text_score is not None:
        X["text_score"] = df.cve_id.map(text_score).fillna(np.nan).values
    nearest = None
    if kevsim is not None:
        smax, s5, nearest = kevsim.features(df.cve_id.values, df.description.fillna("").values, whens)
        X["kev_sim_max"] = smax
        X["kev_sim_top5"] = s5
    meta = df[["cve_id", "snapshot_month", "published", "description", "assigner_key"]].copy()
    if nearest is not None:
        meta["nearest_kev"] = nearest
        meta["nearest_kev_sim"] = X["kev_sim_max"].values
    meta["vendor_guess"] = vend
    meta["brand"] = [v if v else brand_key(d) for v, d in zip(vend, df.description.fillna(""))]
    meta["product_guess"] = prod
    if "label" in df:
        meta["label"] = df["label"].values
    return X, meta


def build_rolling_pool(months, label_cutoff, vulns, kev, signals, max_age_months=12,
                       horizon_months=4, neg_frac=0.15, seed=0):
    """Training-only pool with many more positive events: for each month M, every CVE
    published in the previous `max_age_months` months that is not in KEV at end of M.
    label = added to KEV within `horizon_months` after M (and <= label_cutoff).
    Negatives are subsampled (weight = 1/neg_frac) to keep it fast."""
    rng = np.random.default_rng(seed)
    label_cutoff = pd.Timestamp(label_cutoff)
    kev_date = kev.set_index("cve_id")["date_added"]
    pub = vulns.set_index("cve_id")["published"]
    rows = []
    for m in months:
        end = month_end(m)
        lo = (pd.Period(m, "M") - (max_age_months - 1)).start_time
        hz = min(month_end(str(pd.Period(m, "M") + horizon_months)), label_cutoff)
        sig = signals[signals.month == m].drop(columns=["month"])
        p = vulns.loc[(vulns.published >= lo) & (vulns.published <= end), ["cve_id", "published"]]
        p = p.merge(sig, on="cve_id", how="left")
        da = p.cve_id.map(kev_date)
        keep = ~((da <= end) | (p["in_kev"].fillna(0) == 1))
        p = p[keep.values].copy()
        da = p.cve_id.map(kev_date)
        p["label"] = ((da > end) & (da <= hz)).astype(int).values
        p["age_months"] = ((end - p.published).dt.days / 30.4).clip(lower=0).values
        r = rng.random(len(p))
        p = p[(p.label == 1) | (r < neg_frac)].copy()
        p["weight"] = np.where(p.label == 1, 1.0, 1.0 / neg_frac)
        p["snapshot_month"] = m
        rows.append(p.drop(columns=["in_kev"]))
    pool = pd.concat(rows, ignore_index=True)
    for c in SIGNAL_FLAGS:
        pool[c] = pool[c].fillna(0).astype(np.int8)
    return pool


# ---------------------------------------------------------------------------
# Nearest past exploited CVE (idea ported from the team repo, made strictly point in time)
# ---------------------------------------------------------------------------
class KevSimilarity:
    """Cosine similarity (TF-IDF) between a CVE's description and KEV entries that were
    already on the list at the CVE's snapshot. Vocabulary is fit only on KEV entries
    known by `vocab_cutoff`, so no future KEV text shapes the features."""

    def __init__(self, kev, vulns, vocab_cutoff):
        from sklearn.feature_extraction.text import TfidfVectorizer
        desc = vulns.set_index("cve_id").description
        k = kev[kev.cve_id.isin(desc.index)].sort_values("date_added").reset_index(drop=True)
        self.ids = k.cve_id.values
        self.dates = k.date_added.values
        text = desc.loc[self.ids].fillna("").values
        known = self.dates <= np.datetime64(pd.Timestamp(vocab_cutoff))
        self.vec = TfidfVectorizer(ngram_range=(1, 2), min_df=2, sublinear_tf=True, stop_words="english")
        self.vec.fit(text[known])
        self.K = self.vec.transform(text)

    def features(self, cve_ids, descriptions, whens, chunk=20000):
        n = len(cve_ids)
        smax = np.zeros(n, np.float32)
        stop5 = np.zeros(n, np.float32)
        near = np.array([""] * n, dtype=object)
        whens = pd.to_datetime(pd.Series(list(whens))).values
        ids = np.asarray(cve_ids)
        for w in np.unique(whens):
            sel = np.where(whens == w)[0]
            nk = np.searchsorted(self.dates, w, side="right")
            if nk == 0:
                continue
            Kw = self.K[:nk].T.tocsc()
            for s in range(0, len(sel), chunk):
                part = sel[s:s + chunk]
                S = (self.vec.transform(np.asarray(descriptions)[part]) @ Kw).toarray()
                S[np.equal.outer(ids[part], self.ids[:nk])] = 0      # never match itself
                j = S.argmax(axis=1)
                smax[part] = S[np.arange(len(part)), j]
                k5 = min(5, S.shape[1])
                stop5[part] = np.sort(S, axis=1)[:, -k5:].mean(axis=1)
                near[part] = self.ids[:nk][j]
        return smax, stop5, near


# ---------------------------------------------------------------------------
# Brand fallback: first product-like capitalised word in the description.
# Used only to group CVEs for the per-vendor cap and for display (never as a KEV feature).
# ---------------------------------------------------------------------------
_BRAND_STOP = set("""a an the in on of for to and or with by via from this that these those there it its
multiple improper insufficient missing incorrect inadequate unrestricted uncontrolled unauthenticated
authenticated authorization authentication arbitrary remote local cross site sql os command code
injection buffer overflow heap stack use after free out bounds read write null pointer dereference
integer path directory traversal server side request forgery deserialization untrusted data
vulnerability vulnerabilities issue issues flaw flaws bug affected affects allows allow when if due
an attacker attackers user users admin administrator versions version prior before through up
critical high medium low information disclosure denial service dos rce xss csrf ssrf xxe lfi rfi
open access management web api http https json xml url file upload download plugin theme module
component function parameter endpoint interface page panel portal application app software firmware
device devices system systems product products platform service services cve note""".split())
_BRAND_RE = re.compile(r"\b([A-Z][A-Za-z0-9]+(?:[-_][A-Za-z0-9]+)*|[A-Z]{2,}[A-Z0-9-]*)\b")


_IDENT_AFTER = re.compile(r"\(?\)?\s+(?:function|method|parameter|endpoint|handler|interface|API)\b")


def brand_key(text):
    for m in _BRAND_RE.finditer(text[:160] if text else ""):
        w = m.group(1)
        # skip code identifiers ("the setWanCfg function of TOTOLINK ...") so they don't split one vendor
        if _IDENT_AFTER.match(text, m.end()):
            continue
        if w.lower() not in _BRAND_STOP and len(w) >= 3:
            return w.lower()
    return None
