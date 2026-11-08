"""
IBM Granite layer (granite4:3b via local Ollama), grounded and validated.

For each top-ranked CVE, Granite gets ONLY that CVE's facts (description, snapshot-month
signals, the model's top reasons) and returns JSON:
    vendor, product, internet_facing (yes/no/unclear), attack_type, explanation
A validator rejects any output that
  * claims the CVE is already exploited ("in the wild", "actively exploited", ...),
  * quotes a number that is not in the facts it was given,
  * does not read as a prediction.
Rejected outputs are retried once with the reason; if still invalid, a template
explanation built from the model's reasons is used (validated=0), so nothing ungrounded ships.

Run:
  python pipeline/granite_layer.py               # explain top 500 -> results/granite_explanations.csv
  python pipeline/granite_layer.py --n 100       # fewer (CPU is slow)
  python pipeline/granite_layer.py --accuracy 150
      # check Granite's vendor extraction on 2025 CVEs against NIST's product list.
      # (Past data, used only to MEASURE extraction accuracy, never as a model feature.)
"""
import argparse
import json
import os
import re
import sys
import time
import urllib.request
import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import core

OLLAMA = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
MODEL = os.environ.get("GRANITE_MODEL", "granite4:3b")
RES = os.path.join(core.ROOT, "results")
CACHE = os.path.join(RES, "granite_cache.jsonl")

ATTACK_TYPES = ["remote code execution", "command injection", "authentication bypass", "privilege escalation",
                "path traversal / file read", "SQL injection", "cross-site scripting", "deserialization",
                "memory corruption", "information disclosure", "denial of service", "other"]

BANNED = re.compile(r"actively exploited|exploited in the wild|in the wild|confirmed (?:attack|exploit)|"
                    r"is being exploited|has been exploited|known exploited|currently exploited", re.I)
PREDICTIVE = re.compile(r"\b(likely|predict|risk|could|may|prioriti[sz]e|expect|probab)", re.I)

PROMPT = """You are a vulnerability triage assistant. Use ONLY the facts below. Do not add facts.
This CVE is NOT confirmed as exploited. Our model PREDICTS it is at elevated risk of future exploitation.
Never say it is exploited, actively exploited, or exploited in the wild.

FACTS
cve_id: {cve_id}
description: {description}
EPSS score at snapshot: {epss}
public exploit code: {code}
model rank: {rank} of 72670
top reasons from the model: {why}

Return JSON with keys:
  "vendor": vendor name from the description, or "unknown"
  "product": product name from the description, or "unknown"
  "internet_facing": "yes" if the affected product is typically reachable from the internet (VPN, firewall, web app, mail server, gateway), "no" if local/desktop only, else "unclear"
  "attack_type": one of {types}
  "explanation": exactly two sentences for an engineer: why this is predicted to be high risk (use the reasons), and what to do first. Only use numbers that appear in FACTS.
"""


def _post(path, body, timeout=600):
    req = urllib.request.Request(OLLAMA + path, data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json"})
    return json.loads(urllib.request.urlopen(req, timeout=timeout).read())


def ollama_ok():
    try:
        out = _post("/api/generate", {"model": MODEL, "prompt": "Reply OK", "stream": False,
                                      "options": {"num_predict": 3}}, timeout=300)
        return "response" in out, ""
    except Exception as e:  # noqa
        body = getattr(e, "read", lambda: b"")()
        return False, f"{e} {body[:300]!r}"


def _numbers(text):
    return set(re.findall(r"\d+(?:\.\d+)?", text))


def validate(out, facts_text):
    if not isinstance(out, dict):
        return "not JSON"
    exp = str(out.get("explanation", ""))
    if len(exp) < 30:
        return "explanation missing or too short"
    if BANNED.search(exp):
        return "claims the CVE is already exploited; it is only a prediction"
    stray = {n for n in _numbers(exp) if n not in _numbers(facts_text) and len(n) > 1}
    stray -= {"2026"}
    if stray:
        return f"uses numbers not in FACTS: {sorted(stray)}"
    if not PREDICTIVE.search(exp):
        return "does not read as a prediction (use words like likely / risk / prioritise)"
    if out.get("attack_type") not in ATTACK_TYPES:
        out["attack_type"] = "other"
    if out.get("internet_facing") not in ("yes", "no", "unclear"):
        out["internet_facing"] = "unclear"
    return None


def template(row):
    return (f"{row.cve_id} is ranked {row['rank']} of 72670 for likely future exploitation because: {row.why}. "
            f"Prioritise patching or mitigating it ahead of higher-CVSS issues that lack these signals.")


def ask(row):
    code = "yes" if any(int(row[c]) for c in core.SIGNAL_FLAGS) else "no"
    facts = dict(cve_id=row.cve_id, description=str(row.description)[:900], epss=row.epss, code=code,
                 rank=row["rank"], why=row.why)
    prompt = PROMPT.format(types=ATTACK_TYPES, **facts)
    facts_text = " ".join(str(v) for v in facts.values())
    err = None
    for attempt in range(2):
        p = prompt if err is None else prompt + f"\nYour previous answer was rejected: {err}. Fix it."
        try:
            r = _post("/api/generate", {"model": MODEL, "prompt": p, "format": "json", "stream": False,
                                        "options": {"temperature": 0, "num_predict": 300}})
            out = json.loads(r["response"])
        except Exception as e:  # noqa
            out, err = None, f"call failed: {e}"
            continue
        err = validate(out, facts_text)
        if err is None:
            out["validated"] = 1
            out["attempts"] = attempt + 1
            return out
    out = out if isinstance(out, dict) else {}
    return {"vendor": out.get("vendor", "unknown"), "product": out.get("product", "unknown"),
            "internet_facing": out.get("internet_facing", "unclear"), "attack_type": out.get("attack_type", "other"),
            "explanation": template(row), "validated": 0, "attempts": 2, "rejected_reason": err}


def load_cache():
    c = {}
    if os.path.exists(CACHE):
        for line in open(CACHE, encoding="utf-8"):
            d = json.loads(line)
            c[d["cve_id"]] = d
    return c


def explain(n):
    top = pd.read_csv(os.path.join(RES, "top500_detailed.csv")).head(n)
    cache = load_cache()
    t0 = time.time()
    with open(CACHE, "a", encoding="utf-8") as f:
        for i, row in top.iterrows():
            if row.cve_id in cache:
                continue
            out = ask(row)
            out["cve_id"] = row.cve_id
            cache[row.cve_id] = out
            f.write(json.dumps(out) + "\n"); f.flush()
            done = i + 1
            print(f"[{done}/{n}] {row.cve_id} validated={out['validated']} "
                  f"({(time.time() - t0) / max(1, done):.1f}s/CVE)", flush=True)
    rows = [dict(cache[c], rank=r) for c, r in zip(top.cve_id, top["rank"]) if c in cache]
    df = pd.DataFrame(rows)
    cols = ["rank", "cve_id", "vendor", "product", "internet_facing", "attack_type", "explanation", "validated"]
    df[cols].to_csv(os.path.join(RES, "granite_explanations.csv"), index=False)
    print(f"wrote {len(df)} explanations; validated={int(df.validated.sum())}")


def accuracy(n):
    """Granite vendor extraction vs NIST's vendor list, on 2025 CVEs (past data only)."""
    v = core.load_vulns()
    s = v[(v.published >= "2025-01-01") & (v.published < "2025-10-01")].sample(n * 3, random_state=0)
    ap = pd.read_csv(os.path.join(core.DATA, "affected_products.csv"), usecols=["cve_id", "vendor", "vulnerable"],
                     dtype=str)
    ap = ap[(ap.vulnerable == "Y") & ap.cve_id.isin(s.cve_id)]
    truth = ap.groupby("cve_id").vendor.apply(lambda x: set(x.str.replace("_", " ")))
    s = s[s.cve_id.isin(truth.index)].head(n)
    ok = 0
    for i, r in enumerate(s.itertuples()):
        p = (f"Return JSON {{\"vendor\": ...}} with the software vendor named in this vulnerability description, "
             f"lower case, or \"unknown\".\n\n{r.description[:800]}")
        try:
            out = json.loads(_post("/api/generate", {"model": MODEL, "prompt": p, "format": "json", "stream": False,
                                                     "options": {"temperature": 0, "num_predict": 30}})["response"])
            g = str(out.get("vendor", "")).lower().strip()
        except Exception:  # noqa
            g = ""
        t = truth[r.cve_id]
        hit = any(g and (g in x or x in g) for x in t)
        ok += hit
        print(f"[{i + 1}/{len(s)}] granite={g!r} nist={sorted(t)[:3]} {'OK' if hit else 'MISS'}", flush=True)
    res = {"n": len(s), "vendor_accuracy": ok / max(1, len(s)), "model": MODEL}
    json.dump(res, open(os.path.join(RES, "granite_extraction_accuracy.json"), "w"), indent=2)
    print(res)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=500)
    ap.add_argument("--accuracy", type=int, default=0)
    a = ap.parse_args()
    ok, err = ollama_ok()
    if not ok:
        sys.exit(f"Ollama / {MODEL} is not working: {err}\n"
                 "Fix: reinstall Ollama from https://ollama.com/download, then `ollama run granite4:3b`.")
    if a.accuracy:
        accuracy(a.accuracy)
    else:
        explain(a.n)
