"""
Description-text prior: "does this read like a vulnerability attackers use?"
Trained on long history (CVEs published 2015 .. cutoff) with KEV as the label,
using only KEV adds known by the cutoff date. Description is available for every CVE,
including the ~51k 2026 CVEs NIST never analysed.
"""
import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from scipy.sparse import hstack


def _assigner_text(a):
    return "assigner_" + a.fillna("unknown").str.replace(r"[^a-z0-9]", "_", regex=True)


class TextPrior:
    def __init__(self, C=4.0):
        self.word = TfidfVectorizer(ngram_range=(1, 2), min_df=5, max_features=200_000,
                                    sublinear_tf=True, stop_words="english")
        self.clf = LogisticRegression(C=C, max_iter=2000, class_weight="balanced", solver="liblinear")

    def _X(self, desc, assigner, fit=False):
        t = desc.fillna("") + " " + _assigner_text(assigner)
        return self.word.fit_transform(t) if fit else self.word.transform(t)

    def fit(self, vulns, kev, cutoff, start="2015-01-01"):
        cutoff = pd.Timestamp(cutoff)
        h = vulns[(vulns.published >= start) & (vulns.published <= cutoff)]
        y = h.cve_id.isin(kev[kev.date_added <= cutoff].cve_id).astype(int).values
        self.n_train, self.n_pos = len(h), int(y.sum())
        X = self._X(h.description, h.assigner_key, fit=True)
        self.clf.fit(X, y)
        return self

    def score(self, desc, assigner):
        return self.clf.decision_function(self._X(desc, assigner))

    def top_terms(self, n=25):
        names = np.array(self.word.get_feature_names_out())
        coef = self.clf.coef_[0]
        idx = np.argsort(coef)[::-1][:n]
        return list(zip(names[idx], coef[idx].round(2)))
