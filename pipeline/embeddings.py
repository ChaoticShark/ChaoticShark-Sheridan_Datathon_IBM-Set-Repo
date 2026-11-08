"""
IBM Granite embeddings (granite-embedding:30m via Ollama) for CVE descriptions.

Used for a point-in-time "nearest past exploited CVE" feature: for each CVE, the cosine
similarity to the most similar KEV entry that was added BEFORE its snapshot date, and
which one it is (shown to users as "looks like CVE-XXXX, exploited in <date>").

Run:  python pipeline/embeddings.py      (embeds every needed CVE once; resumable cache)
"""
import json
import os
import sys
import time
import urllib.request
import numpy as np
import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import core

OLLAMA = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
MODEL = "granite-embedding:30m"
DIR = os.path.join(core.CACHE, "granite_emb")
os.makedirs(DIR, exist_ok=True)


def _embed(texts):
    body = {"model": MODEL, "input": [t[:1500] for t in texts], "truncate": True}
    req = urllib.request.Request(OLLAMA + "/api/embed", data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json"})
    out = json.loads(urllib.request.urlopen(req, timeout=900).read())["embeddings"]
    E = np.asarray(out, dtype=np.float32)
    return E / np.linalg.norm(E, axis=1, keepdims=True).clip(1e-9)


def needed_ids(vulns, kev):
    ids = set(vulns.loc[vulns.published >= "2022-01-01", "cve_id"]) | set(kev.cve_id)
    return sorted(ids & set(vulns.cve_id))


def build(batch=128, chunk=8192):
    vulns, kev = core.load_vulns(), core.load_kev()
    ids = needed_ids(vulns, kev)
    desc = vulns.set_index("cve_id").description
    done = set()
    for f in os.listdir(DIR):
        if f.endswith(".ids.json"):
            done |= set(json.load(open(os.path.join(DIR, f))))
    todo = [c for c in ids if c not in done]
    print(f"{len(ids)} needed, {len(done)} cached, {len(todo)} to embed", flush=True)
    t0 = time.time()
    for ci in range(0, len(todo), chunk):
        part = todo[ci:ci + chunk]
        E = np.vstack([_embed(desc.loc[part[i:i + batch]].tolist()) for i in range(0, len(part), batch)])
        n = len([f for f in os.listdir(DIR) if f.endswith(".npy")])
        np.save(os.path.join(DIR, f"part{n:03d}.npy"), E)
        json.dump(part, open(os.path.join(DIR, f"part{n:03d}.ids.json"), "w"))
        rate = (ci + len(part)) / (time.time() - t0)
        print(f"{ci + len(part)}/{len(todo)}  {rate:.0f}/s", flush=True)


def load():
    ids, mats = [], []
    for f in sorted(os.listdir(DIR)):
        if f.endswith(".npy"):
            mats.append(np.load(os.path.join(DIR, f)))
            ids += json.load(open(os.path.join(DIR, f.replace(".npy", ".ids.json"))))
    return {c: i for i, c in enumerate(ids)}, (np.vstack(mats) if mats else np.zeros((0, 384), np.float32))


class NearestKev:
    """Point-in-time nearest-KEV similarity."""

    def __init__(self, kev):
        self.index, self.E = load()
        k = kev[kev.cve_id.isin(self.index)].sort_values("date_added")
        self.kev_ids = k.cve_id.values
        self.kev_dates = k.date_added.values
        self.K = self.E[[self.index[c] for c in self.kev_ids]]

    def features(self, cve_ids, whens):
        sims = np.full(len(cve_ids), np.nan, dtype=np.float32)
        best = np.array([""] * len(cve_ids), dtype=object)
        whens = pd.to_datetime(pd.Series(whens)).values
        rows = np.array([self.index.get(c, -1) for c in cve_ids])
        for w in np.unique(whens):
            sel = np.where((whens == w) & (rows >= 0))[0]
            nk = np.searchsorted(self.kev_dates, w, side="right")   # KEV entries known by w
            if nk == 0 or len(sel) == 0:
                continue
            S = self.E[rows[sel]] @ self.K[:nk].T
            # never match a CVE to itself
            same = np.equal.outer(np.asarray(cve_ids)[sel], self.kev_ids[:nk])
            S[same] = -1
            j = S.argmax(axis=1)
            sims[sel] = S[np.arange(len(sel)), j]
            best[sel] = self.kev_ids[:nk][j]
        return sims, best


if __name__ == "__main__":
    build()
