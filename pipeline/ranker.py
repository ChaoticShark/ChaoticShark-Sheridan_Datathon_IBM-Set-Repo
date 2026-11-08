"""EARLY EXPLORATION, superseded by model.py / backtest.py. Kept so results/experiments.json can be reproduced.
Note: it uses the earlier feature set, so its numbers differ slightly from the locked model.
"""
"""
Final ranker: a regularised logistic regression on a small set of leak-safe features.
Few positives exist per season (dozens), so a simple, readable model generalises
better than a deep one, and its weights explain every ranking.
"""
import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler
from sklearn.impute import SimpleImputer
from sklearn.pipeline import make_pipeline


class Ranker:
    def __init__(self, C=0.05):
        self.pipe = make_pipeline(SimpleImputer(strategy="median"), StandardScaler(),
                                  LogisticRegression(C=C, class_weight="balanced", max_iter=5000))

    def fit(self, X, y):
        self.cols = list(X.columns)
        self.pipe.fit(X[self.cols], y)
        return self

    def score(self, X):
        return self.pipe.decision_function(X[self.cols])

    def contributions(self, X):
        """Per-feature contribution to each CVE's score (standardised value * weight)."""
        Z = self.pipe[:-1].transform(X[self.cols])
        w = self.pipe[-1].coef_[0]
        return pd.DataFrame(Z * w, columns=self.cols, index=X.index)

    def importance(self, X=None, y=None):
        w = self.pipe[-1].coef_[0]
        return dict(sorted(zip(self.cols, w.round(3)), key=lambda t: -abs(t[1])))
