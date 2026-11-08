"""
Build dashboard.html: a single self-contained file (no internet needed), styled after the
v1 dashboard (dark navy, pill badges, segmented filters, Inspect panel) with the v2 content.
    python pipeline/build_dashboard.py
"""
import json
import os
import sys
import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import core

RES = os.path.join(core.ROOT, "results")
N_ROWS = 3000
POOL = 72670
# robustness.json row that corresponds to the adopted model
ADOPTED = "+ nearest-KEV similarity (max)"


def s(v):
    return v if isinstance(v, str) else ""


def load():
    r = pd.read_csv(os.path.join(RES, "scoreboard_ranked.csv"), low_memory=False).head(N_ROWS)
    g = {}
    gp = os.path.join(RES, "granite_cache.jsonl")
    if os.path.exists(gp):
        for line in open(gp, encoding="utf-8"):
            d = json.loads(line)
            g[d["cve_id"]] = d
    kev = core.load_kev().set_index("cve_id")
    full_desc = core.load_vulns().set_index("cve_id").description_raw
    rows = []
    for x in r.itertuples():
        gd = g.get(x.cve_id, {})
        code = [n for n, f in (("Exploit-DB", x.exploitdb), ("Metasploit", x.metasploit),
                               ("Nuclei", x.nuclei), ("GitHub PoC", x.poc_github)) if f == 1]
        nk = s(x.nearest_kev)
        sim = None if pd.isna(x.nearest_kev_sim) else round(float(x.nearest_kev_sim), 2)
        close = nk and (sim or 0) >= 0.30
        nk_info = {}
        if close and nk in kev.index:
            k = kev.loc[nk]
            nk_info = {"name": s(k["name"]), "date": str(k.date_added.date()),
                       "ransom": s(k.known_ransomware_use) == "Known"}
        vendor = s(x.vendor_guess) or (gd.get("vendor") if gd.get("vendor") not in (None, "", "unknown") else "") or s(x.brand)
        product = s(x.product_guess) or (gd.get("product") if gd.get("product") not in (None, "", "unknown") else "")
        rows.append({
            "r": int(x.rank), "id": x.cve_id, "pub": str(x.published)[:10], "m": x.snapshot_month,
            "e": None if pd.isna(x.epss) else round(float(x.epss), 5), "c": code,
            "v": vendor, "p": product, "vk": 0 if pd.isna(x.vendor_kev_n) else int(x.vendor_kev_n),
            "tg": [t for t in s(x.tags).split("; ") if t], "w": [t for t in s(x.why).split("; ") if t],
            "ev": s(x.evidence), "d": s(full_desc.get(x.cve_id, x.description)),
            "nk": nk if close else "", "ns": sim if close else None, "nki": nk_info,
            "x": gd.get("explanation", "") if gd.get("validated") == 1 else "",
            "i": gd.get("internet_facing", ""), "a": gd.get("attack_type", ""), "as": s(x.assigner_key),
            "rc": int(x.rank_cvss), "rx": int(x.rank_code),
            "cp": int(x.capped), "tc": int(x.trig_code), "te": None if pd.isna(x.trig_epss) else float(x.trig_epss),
        })
    bt = json.load(open(os.path.join(RES, "backtest.json")))
    fs = json.load(open(os.path.join(RES, "findings_stats.json")))
    rp = os.path.join(RES, "robustness.json")
    rb = json.load(open(rp)) if os.path.exists(rp) else {}
    tp = os.path.join(RES, "timemachine_2025.json")
    tm = json.load(open(tp)) if os.path.exists(tp) else {"cves": []}
    return rows, bt, fs, rb, tm


HTML = r"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Before the Breach: Exploitation Prediction Matrix</title>
<style>
:root{--bg:#0b0f19;--card:#111827;--card2:#0f172a;--line:#1f2937;--line2:#374151;--ink:#f9fafb;--muted:#9ca3af;--dim:#6b7280;
--blue:#60a5fa;--green:#4ade80;--purple:#c084fc;--red:#f87171;--orange:#fb923c;--yellow:#facc15;--amber:#fbbf24}
*{box-sizing:border-box}html,body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
.wrap{max-width:1280px;margin:0 auto;padding:24px 16px 64px}
.mono{font-family:ui-monospace,SFMono-Regular,Consolas,monospace}
.pill{display:inline-flex;align-items:center;gap:6px;padding:3px 10px;font-size:12px;font-weight:600;border-radius:6px;border:1px solid}
.p-blue{background:rgba(30,58,138,.6);color:var(--blue);border-color:rgba(29,78,216,.5)}
.p-purple{background:rgba(88,28,135,.6);color:var(--purple);border-color:rgba(126,34,206,.5)}
.p-green{background:rgba(20,83,45,.6);color:var(--green);border-color:rgba(21,128,61,.5)}
header{display:flex;flex-wrap:wrap;gap:16px;justify-content:space-between;align-items:flex-end;border-bottom:1px solid var(--line);padding-bottom:20px}
h1{font-size:30px;margin:8px 0 4px;line-height:1.2}h1 span{color:var(--blue)}
.sub{color:var(--muted);margin:0;max-width:760px}
.btn{font:inherit;font-size:13px;font-weight:600;color:#e5e7eb;background:#1f2937;border:1px solid var(--line2);border-radius:8px;padding:8px 14px;cursor:pointer}
.btn:hover{background:#374151}
.card{background:var(--card);border:1px solid var(--line);border-radius:14px}
.proof{margin-top:24px;padding:18px 20px;background:linear-gradient(90deg,#111827,#111827 55%,rgba(23,37,84,.55));border-color:rgba(30,64,175,.45)}
.ptitle{display:flex;flex-wrap:wrap;gap:8px;align-items:center}.tag-s{padding:2px 7px;font-size:11px;font-weight:800;letter-spacing:.05em;text-transform:uppercase;border-radius:4px;background:rgba(59,130,246,.2);color:var(--blue);border:1px solid rgba(59,130,246,.3)}
.pgrid{display:grid;grid-template-columns:minmax(0,1.3fr) minmax(0,1fr);gap:24px;margin-top:14px}
@media(max-width:900px){.pgrid{grid-template-columns:1fr}}
.bar{display:grid;grid-template-columns:minmax(100px,230px) minmax(0,1fr) 34px;gap:10px;align-items:center;margin:7px 0;font-size:13px}
.track{height:12px;background:#1f2937;border-radius:6px;overflow:hidden}.fill{height:100%;background:#4b5563;border-radius:6px}
@media(max-width:600px){.bar{grid-template-columns:minmax(0,1fr) 34px;row-gap:3px}.bar>span{grid-column:1/-1}}
.bar.ours{font-weight:700}.bar.ours .fill{background:linear-gradient(90deg,#2563eb,#60a5fa)}.bar.ours b{color:var(--blue)}
table.mini{width:100%;border-collapse:collapse;font-size:13px}table.mini th,table.mini td{padding:5px 6px;border-bottom:1px solid var(--line);text-align:left}
table.mini th{color:var(--dim);font-size:11px;text-transform:uppercase;letter-spacing:.04em}table.mini td.win{color:var(--green);font-weight:700}
.note{font-size:12px;color:var(--dim)}
.kpis{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;margin-top:16px}
@media(max-width:900px){.kpis{grid-template-columns:repeat(2,minmax(0,1fr))}}@media(max-width:480px){.kpis{grid-template-columns:1fr}}
.kpi{padding:16px}.kl{font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.06em;color:var(--muted)}
.kv{font-size:30px;font-weight:800;margin-top:4px;line-height:1.1}.ks{font-size:12px;color:var(--muted);margin-top:4px}
.c-white{color:#fff}.c-green{color:var(--green)}.c-purple{color:var(--purple)}.c-red{color:var(--red)}.c-blue{color:var(--blue)}.c-amber{color:var(--amber)}
.controls{margin-top:24px;padding:12px;display:flex;flex-wrap:wrap;gap:10px;align-items:center}
.seg{display:flex;flex-wrap:wrap;gap:4px}
.seg button{font:inherit;font-size:12.5px;font-weight:600;color:var(--muted);background:transparent;border:1px solid transparent;border-radius:9px;padding:8px 12px;cursor:pointer;display:flex;gap:6px;align-items:center}
.seg button:hover{color:#fff;background:#1f2937}.seg button.on{background:#2563eb;color:#fff}
.seg .cnt{font-size:10.5px;font-family:ui-monospace,Consolas,monospace;padding:1px 6px;border-radius:4px;background:rgba(0,0,0,.35)}
.seg button.hid{color:var(--purple);border-color:rgba(147,51,234,.4)}.seg button.hid.on{background:#7e22ce;color:#fff}
input,select{font:inherit;font-size:13px;color:#e5e7eb;background:#1f2937;border:1px solid var(--line2);border-radius:8px;padding:8px 10px;min-width:0;max-width:100%}
input{flex:1 1 220px}input::placeholder{color:var(--dim)}
.status{margin-top:12px;padding:10px 14px;display:flex;justify-content:space-between;gap:10px;flex-wrap:wrap;font-size:13px;color:var(--muted)}
.status b{color:#fff}
.tw{margin-top:12px;overflow-x:auto}
table.main{width:100%;border-collapse:collapse;min-width:1020px}
table.main th{position:sticky;top:0;background:#1f2937;color:var(--muted);font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.05em;text-align:left;padding:12px 10px;white-space:nowrap;user-select:none}
table.main th[data-k]{cursor:pointer}table.main th[data-k]:hover{color:#fff}table.main th .ar{color:var(--blue)}
table.main td{padding:12px 10px;border-top:1px solid var(--line);vertical-align:top}
table.main tr:hover td{background:#0f172a}
.cve{color:var(--blue);font-weight:700;white-space:nowrap}.small{font-size:11.5px;color:var(--dim)}
.badge{display:inline-block;padding:2px 7px;border-radius:5px;font-size:11px;font-weight:700;border:1px solid;white-space:nowrap}
.b-crit{background:rgba(239,68,68,.2);color:#f87171;border-color:rgba(239,68,68,.4)}
.b-high{background:rgba(249,115,22,.2);color:#fb923c;border-color:rgba(249,115,22,.4)}
.b-elev{background:rgba(234,179,8,.2);color:#facc15;border-color:rgba(234,179,8,.4)}
.b-watch{background:rgba(59,130,246,.2);color:#60a5fa;border-color:rgba(59,130,246,.4)}
.b-pur{background:rgba(168,85,247,.2);color:#c084fc;border-color:rgba(168,85,247,.4)}
.b-gry{background:rgba(107,114,128,.18);color:#d1d5db;border-color:rgba(107,114,128,.35)}
.chips{display:flex;flex-wrap:wrap;gap:4px;margin-top:4px}
.epss{font-weight:700}.e-hi{color:var(--red)}.e-mid{color:var(--amber)}.e-lo{color:var(--dim)}
.why{font-size:12.5px;color:#d1d5db;max-width:280px}
.insp{font:inherit;font-size:12px;font-weight:600;color:var(--blue);background:rgba(30,58,138,.35);border:1px solid rgba(29,78,216,.5);border-radius:7px;padding:5px 10px;cursor:pointer}
.insp:hover{background:#1d4ed8;color:#fff}
.pager{display:flex;justify-content:flex-end;align-items:center;gap:8px;margin-top:10px;flex-wrap:wrap}
.finds{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:12px;margin-top:12px}
@media(max-width:900px){.finds{grid-template-columns:1fr}}
.find{padding:16px}.find .kv{font-size:24px}
h2{font-size:18px;margin:36px 0 0}
.modal{position:fixed;inset:0;background:rgba(3,7,18,.78);display:none;align-items:flex-start;justify-content:center;padding:40px 16px;overflow:auto;z-index:10}
.modal.open{display:flex}
.mbox{max-width:820px;width:100%;padding:24px}
.mhead{display:flex;justify-content:space-between;gap:12px;align-items:flex-start}
.x{font:inherit;font-size:22px;line-height:1;color:var(--muted);background:none;border:none;cursor:pointer}
.sec{margin-top:16px;padding:14px;border-radius:10px;background:var(--card2);border:1px solid var(--line);overflow-wrap:anywhere}
.sec h4{margin:0 0 6px;font-size:11px;letter-spacing:.06em;text-transform:uppercase;color:var(--muted)}
.gran{border-color:rgba(29,78,216,.55);background:linear-gradient(180deg,rgba(30,58,138,.25),var(--card2))}
.grid2{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:0 12px}@media(max-width:600px){.grid2{grid-template-columns:1fr}}
.hbtns{display:flex;gap:8px;flex-wrap:wrap}
#plainBtn[aria-pressed="true"]{background:#14532d;border-color:#15803d;color:#bbf7d0}
.tabs{display:flex;gap:4px;flex-wrap:wrap;margin-top:16px;border-bottom:1px solid var(--line)}
.tabs button{font:inherit;font-size:13.5px;font-weight:600;color:var(--muted);background:none;border:none;border-bottom:2px solid transparent;padding:10px 14px;cursor:pointer}
.tabs button:hover{color:#fff}.tabs button.on{color:#fff;border-bottom-color:var(--blue)}
.view{display:none}.view.on{display:block}
.tog{display:flex;gap:6px;align-items:center;font-size:13px;color:var(--muted);cursor:pointer;white-space:nowrap}
.tog input{flex:none;accent-color:#2563eb}
.stackbox,.answer{margin-top:12px;padding:14px}
.srow{display:flex;gap:8px;margin-top:8px;flex-wrap:wrap}
.ex{font:inherit;font-size:12px;color:var(--blue);background:rgba(30,58,138,.3);border:1px solid rgba(29,78,216,.45);border-radius:6px;padding:3px 9px;cursor:pointer}
.answer{font-size:15px;border-color:rgba(21,128,61,.5)}
.light{display:inline-flex;align-items:center;gap:7px;font-weight:700;white-space:nowrap}
.light i{width:12px;height:12px;border-radius:50%;display:inline-block}
.l-red i{background:#ef4444;box-shadow:0 0 8px #ef4444}.l-red{color:#fca5a5}
.l-amb i{background:#f59e0b;box-shadow:0 0 8px #f59e0b}.l-amb{color:#fcd34d}
.l-grn i{background:#22c55e}.l-grn{color:#86efac}
.plainwhy{font-size:13.5px;color:#e5e7eb;max-width:560px}
.trig{margin-top:6px;font-size:12px;color:var(--amber)}
.std{font-size:12px;white-space:nowrap}.std .miss{color:var(--red);font-weight:700}.std .hit{color:var(--green);font-weight:700}
.b-ok{background:rgba(34,197,94,.18);color:#4ade80;border-color:rgba(34,197,94,.4)}
td.in{color:var(--green);font-weight:700}td.out{color:var(--dim)}
table.main.tm,table.main.vend{min-width:860px}
.vlink{font:inherit;font-weight:700;color:var(--blue);background:none;border:none;padding:0;cursor:pointer;text-align:left}
body.plain .expert-only{display:none}
.story{margin-top:8px}
.step{display:grid;grid-template-columns:40px minmax(0,1fr);gap:14px;padding:26px 0;border-bottom:1px solid var(--line)}
.step:last-child{border-bottom:none}
.num{width:32px;height:32px;border-radius:50%;background:#1e3a8a;color:#bfdbfe;font-weight:800;display:flex;align-items:center;justify-content:center}
.step h3{margin:4px 0 6px;font-size:19px}.lead{margin:0 0 12px;color:#d1d5db;max-width:820px}
.lead code{font-size:12.5px;background:#1f2937;padding:1px 5px;border-radius:4px}
.heroes{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:12px}@media(max-width:800px){.heroes{grid-template-columns:1fr}}
.hero{padding:16px}
.chart{padding:16px 18px}.ct{font-weight:700;margin-bottom:8px}
.legend{display:flex;flex-wrap:wrap;gap:14px;font-size:12px;color:var(--muted);margin-bottom:8px;align-items:center}
.sw{display:inline-block;width:10px;height:10px;border-radius:3px;margin-right:5px;vertical-align:-1px}
.s-red,.f-red{background:#f87171}.s-gry,.f-gry{background:#6b7280}.s-blu,.f-blu{background:#60a5fa}
.pair{margin:8px 0 12px}.pt{font-size:13px;font-weight:600;margin-bottom:2px}
.hb{display:grid;grid-template-columns:minmax(90px,230px) minmax(0,1fr) 48px;gap:10px;align-items:center;margin:6px 0;font-size:13px}
.hb .fill{border-radius:0 4px 4px 0}.hb b{font-variant-numeric:tabular-nums}
.bigrow{display:flex;gap:16px;align-items:center;flex-wrap:wrap}.bigrow .kv{font-size:44px}.bigrow .ks{max-width:560px;font-size:14px}
.stack{display:flex;gap:2px;height:30px;margin:14px 0 8px;border-radius:6px;overflow:hidden;font-size:12px;font-weight:700}
.stack>div{display:flex;align-items:center;padding:0 10px;white-space:nowrap;overflow:hidden}
.seg1{background:#7e22ce;color:#fff}.seg2{background:#374151;color:#e5e7eb}
.lift{display:grid;grid-template-columns:minmax(110px,220px) minmax(0,1fr) 48px;gap:10px;align-items:center;margin:5px 0;font-size:13px}
.ltrack{position:relative;height:14px;background:#0f172a;border-radius:4px}
.axis1{position:absolute;top:-3px;bottom:-3px;width:2px;background:#9ca3af}
.lbar{position:absolute;top:2px;height:10px;border-radius:3px}
.zero{position:absolute;left:0;top:-1px;font-size:11px;color:var(--blue);font-weight:700}
.lscale{position:relative;height:18px;margin-left:calc(min(220px,30%) + 10px);margin-right:58px;font-size:11px;color:var(--dim)}
.lscale span{position:absolute;transform:translateX(-50%);white-space:nowrap}
@media(max-width:600px){.lift,.hb{grid-template-columns:minmax(0,1fr) 44px;row-gap:2px}.lift .hl,.hb .hl{grid-column:1/-1}.lscale{margin-left:0;margin-right:54px}}
.grid2w{display:grid;grid-template-columns:minmax(0,1.2fr) minmax(0,1fr);gap:12px}@media(max-width:900px){.grid2w{grid-template-columns:1fr}}
ul.checks{margin:6px 0 12px;padding-left:18px}ul.checks li{margin:5px 0}ul.checks b{color:var(--green)}
.paths{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:12px}@media(max-width:800px){.paths{grid-template-columns:1fr}}
.path{font:inherit;color:inherit;text-align:left;padding:16px;cursor:pointer;display:flex;flex-direction:column;gap:6px}
.path:hover{border-color:#2563eb;background:#0f172a}.path span{font-size:13px;color:var(--muted)}.path em{font-style:normal;color:var(--blue);font-weight:700;font-size:13px}
.budget{padding:18px 20px;margin-top:12px;border-color:rgba(30,64,175,.45)}
.brow{display:flex;flex-wrap:wrap;gap:12px 18px;align-items:center;margin:10px 0 14px}
.brow input[type=range]{flex:1 1 260px;min-width:0;max-width:520px;accent-color:#2563eb;background:none;border:none;padding:0}
.bval{font-size:26px;font-weight:800;color:#fff;font-variant-numeric:tabular-nums}
.bsub{font-size:13px;color:var(--muted)}
.bstats{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:12px;margin-top:12px}@media(max-width:800px){.bstats{grid-template-columns:1fr}}
.bstat{padding:12px 14px;background:var(--card2);border:1px solid var(--line);border-radius:10px}.bstat .kv{font-size:24px}
a{color:var(--blue)}footer{margin-top:40px;font-size:12px;color:var(--dim);border-top:1px solid var(--line);padding-top:16px}
</style></head><body><div class="wrap">

<header><div>
 <div style="display:flex;gap:8px;flex-wrap:wrap"><span class="pill p-blue">IBM Granite 4 · 3B explanations</span><span class="pill p-purple">Scoreboard 2026 · 72,670 CVEs</span><span class="pill p-green">Leak-safe · backtested</span></div>
 <h1>Before the Breach: <span>Exploitation Prediction Matrix</span></h1>
 <p class="sub">Which newly published vulnerabilities attackers are most likely to use next, ranked only from what was known at each CVE's snapshot month, with the reasons and evidence behind each rank.</p>
</div><div class="hbtns"><button class="btn" id="plainBtn" aria-pressed="false">Plain English: off</button><button class="btn" id="csv">Export filtered CSV</button></div></header>

<nav class="tabs" id="tabs" aria-label="Sections"><button data-v="start">Start here</button><button data-v="rank">2026 ranking</button><button data-v="tm">Time Machine · 2025 replay</button><button data-v="vend">Vendors</button><button data-v="find">What the data says</button></nav>

<div class="view" data-v="start">
<section class="story">
 <div class="step"><span class="num">1</span><div><h3>The problem</h3>
  <p class="lead">Tens of thousands of new vulnerabilities a year, and attackers use a tiny fraction. Security teams have to guess which ones to fix first.</p>
  <div class="heroes" id="stProblem"></div></div></div>

 <div class="step"><span class="num">2</span><div><h3>The trap we found: NIST's data gives away the answer</h3>
  <p class="lead">NIST reviews attacked vulnerabilities first. So its own fields, read today, quietly reveal which old CVEs were exploited. A model trained on them looks brilliant in testing, then fails on new CVEs that haven't been reviewed yet. We removed every field like this, and <code>verify.py</code> re-proves the leak on every run.</p>
  <div class="card chart" id="stLeak"></div></div></div>

 <div class="step"><span class="num">3</span><div><h3>Standard tools are blind on day one</h3>
  <p class="lead">Exploit code and EPSS are the usual early warnings. For most attacked CVEs, neither had fired by the end of the month they were published.</p>
  <div class="card chart" id="stBlind"></div></div></div>

 <div class="step"><span class="num">4</span><div><h3>What a bug <i>is</i> says more than its severity score</h3>
  <p class="lead">How much more (or less) likely a 2024–25 CVE was to be exploited, by what its description says and who reported it. 1× = the average CVE.</p>
  <div class="card chart" id="stLift"></div></div></div>

 <div class="step"><span class="num">5</span><div><h3>Proof: it would have worked last year</h3>
  <p class="lead">Trained only on 2024 and tested on every CVE published January–September 2025, using only what was known at the end of each CVE's publish month, then checked against CISA's exploited list.</p>
  <div class="grid2w"><div class="card chart" id="stProof"></div><div class="card chart" id="stSure"></div></div>
 <div class="card budget" id="budget"><div class="ct">What does this mean for <i>your</i> team? Set your patch budget</div>
  <div class="note">Each month of 2025, a team patches the top N new CVEs by each method. How many of the CVEs CISA later confirmed as exploited would each method have caught?</div>
  <div class="brow"><input type="range" id="bud" min="0" max="9" step="1" value="3" aria-label="Patches per month"><div><span class="bval" id="budN"></span> <span class="bsub" id="budP"></span></div></div>
  <div id="budBars"></div><div class="bstats" id="budStats"></div>
  <div class="note" style="margin-top:8px">Jan–Sep 2025 replay, trained on 2024 only. Ranks are within each month's new CVEs, using only what was known at the end of that month.</div></div></div></div>

 <div class="step"><span class="num">6</span><div><h3>The 2026 list: pick your starting point</h3>
  <p class="lead">72,670 new CVEs ranked. The top 500 is our submission.</p>
  <div class="paths">
   <button class="card path" data-go="fix"><b>I run security for an organisation</b><span>The top 500 with evidence, Granite explanations, and what would move each watchlist CVE up.</span><em>Open Fix now →</em></button>
   <button class="card path" data-go="plain"><b>I just want to know if my stuff is affected</b><span>Plain English, traffic lights, and "do I need to worry about…?" search.</span><em>Open Plain English →</em></button>
   <button class="card path" data-go="vend"><b>I choose vendors and suppliers</b><span>Predicted 2026 risk per vendor, for reviews and renewals.</span><em>Open Vendors →</em></button>
  </div></div></div>
</section>
</div>

<div class="view" data-v="rank">
<section class="card proof">
 <div class="ptitle"><span class="tag-s">Proof</span><b>Would this have worked last year?</b><span class="note">Trained on 2024 · tested on 2025 · checked against CISA's exploited list (KEV)</span></div>
 <div class="pgrid"><div id="bars"></div><div><table class="mini" id="checks"></table><div class="note" style="margin-top:6px">Each check retrained only on what was known at its start. Counts are at the benchmark's top 500, scaled to that window's size.</div></div></div>
</section>

<div class="kpis" id="kpis"></div>

<div class="card controls">
 <div class="seg" id="seg"></div>
 <input id="q" placeholder="Search CVE, vendor, product, look-alike, description…" aria-label="Search">
 <select id="sort" aria-label="Sort"><option value="r">Sort by predicted rank</option><option value="e">Sort by EPSS</option><option value="vk">Sort by vendor KEV history</option><option value="ns">Sort by look-alike similarity</option><option value="pub">Sort by newest</option></select>
 <select id="ps" aria-label="Rows per page"><option>10</option><option selected>25</option><option>50</option><option>100</option><option>250</option><option>500</option></select>
 <button class="btn" id="stackBtn">Edit my stack</button>
 <label class="tog expert-only"><input type="checkbox" id="cmp"> Compare with standard rankings</label>
</div>
<div class="card stackbox" id="stackbox" hidden>
 <b>My stack</b> <span class="note">List the vendors, products or apps you use, separated by commas. Saved only in this browser; nothing is sent anywhere.</span>
 <div class="srow"><input id="stackIn" placeholder="e.g. fortinet, ivanti, chrome, winrar, wordpress" aria-label="My stack"><button class="btn" id="stackSave">Save</button></div>
 <div class="chips" style="margin-top:8px"><span class="note">Examples:</span>
  <button class="ex" data-s="windows, chrome, firefox, winrar, 7-zip, zoom, router">Home</button>
  <button class="ex" data-s="microsoft, fortinet, sonicwall, veeam, wordpress, synology">Small business</button>
  <button class="ex" data-s="citrix, ivanti, palo alto, vmware, sap, oracle, cisco, f5">Enterprise</button></div>
</div>
<div class="card answer" id="ans" hidden></div>
<div class="card status"><span id="desc"></span><span><b id="n"></b> records</span></div>

<div class="card tw"><table class="main"><thead id="th"></thead><tbody id="tb"></tbody></table></div>
<div class="pager"><span class="note" id="pg"></span><button class="btn" id="prev">‹ Prev</button><button class="btn" id="next">Next ›</button></div>
</div>

<div class="view" data-v="tm">
<section class="card proof">
 <div class="ptitle"><span class="tag-s">Time Machine</span><b>What if you had used this in 2025?</b></div>
 <p class="sub" style="margin-top:6px">We trained on 2024 only, ranked every CVE published January–September 2025 at the end of its publish month, then waited to see which ones CISA added to its exploited list (KEV). Below is every one of the <b id="tmPos"></b> that were. A rank inside the top <b id="tmK"></b> (out of <span id="tmPool"></span>) is the same share of CVEs as the benchmark's top 500.</p>
 <div class="kpis" id="tmKpis"></div>
</section>
<div class="card controls"><div class="seg" id="tmSeg"></div></div>
<div class="card tw"><table class="main tm"><thead><tr><th>CVE</th><th>Vendor · product</th><th>Our rank</th><th>CVSS first</th><th>EPSS first</th><th>Exploit code first</th><th>Outcome</th></tr></thead><tbody id="tmTb"></tbody></table></div>
<div class="note" style="margin-top:8px" id="tmNote"></div>
</div>

<div class="view" data-v="vend">
<section class="card proof">
 <div class="ptitle"><span class="tag-s">Vendors</span><b>Which suppliers carry the most predicted risk in 2026?</b></div>
 <p class="sub" style="margin-top:6px">For vendor-risk reviews, renewals and procurement. Counts come from our 3,000 highest-ranked 2026 CVEs. At most 20 CVEs per vendor go into the top 500, so the biggest vendors also show many in the watchlist. Click a vendor to see its CVEs.</p>
</section>
<div class="card controls"><input id="vq" placeholder="Filter vendors…" aria-label="Filter vendors"><label class="tog"><input type="checkbox" id="vmine"> Only my stack</label></div>
<div class="card tw"><table class="main vend"><thead><tr><th>Vendor</th><th>Fix now</th><th>Watchlist</th><th>Hidden risks</th><th>Look-alikes of past attacks</th><th>Earlier KEV entries</th><th>Best rank</th><th></th></tr></thead><tbody id="vTb"></tbody></table></div>
<div class="pager"><span class="note" id="vpg"></span><button class="btn" id="vmore">Show all</button></div>
</div>

<div class="view" data-v="find">
<h2>What the 2024–25 data says</h2>
<div class="finds" id="finds"></div>
</div>

<footer>Predictions, not confirmations: no CVE listed here was on CISA's KEV list at its snapshot. Ranks use no NIST-analysis fields (see COLUMNS_USED.md). Granite text is shown only when it passed the grounding validator. "Looks like" compares descriptions with KEV entries that were already listed at the CVE's snapshot.</footer>
</div>

<div class="modal" id="modal" role="dialog" aria-modal="true"><div class="card mbox" id="mbox"></div></div>

<script>
const ROWS=__ROWS__,TM=__TM__,BT=__BT__,FS=__FS__,RB=__RB__,POOL=__POOL__,ADOPTED=__ADOPTED__;
const $=s=>document.querySelector(s),esc=s=>String(s??"").replace(/[&<>"]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));
const pct=x=>(x*100).toFixed(x<0.01?2:0)+"%";
const tier=r=>r<=50?["CRITICAL","b-crit"]:r<=200?["HIGH","b-high"]:r<=500?["ELEVATED","b-elev"]:["WATCH","b-watch"];
// CISA SSVC-style decision (approximation: SSVC also weighs your own mission and exposure)
const ssvc=r=>r<=50?["Act","act now, out of cycle"]:r<=500?["Attend","escalate, patch sooner than usual"]:r<=3000?["Track*","watch closely"]:["Track","normal patch cycle"];
const hidden=r=>!r.c.length&&(r.e??0)<0.01;
const edge=r=>r.tg.includes("Edge device")||r.i==="yes";

// proof
const R=BT.results,kk=Object.keys(R.Ours).find(c=>c.includes("scaled")),k=BT.k_scaled;
const names=["Highest CVSS 3 first","EPSS first","Public exploit code first, then EPSS","Ours"],mx=Math.max(...names.map(n=>R[n][kk]));
$("#bars").innerHTML=`<div class="note" style="margin-bottom:4px">Later-exploited CVEs caught in the top ${k} (of ${BT.test_pool.toLocaleString()} CVEs published Jan–Sep 2025; ${BT.test_positives} later exploited)</div>`+
 names.map(n=>`<div class="bar ${n==="Ours"?"ours":""}"><span>${n==="Ours"?"Our model":esc(n)}</span><div class="track"><div class="fill" style="width:${R[n][kk]/mx*100}%"></div></div><b>${R[n][kk]}</b></div>`).join("");
const LBL={"main":"2025 Jan–Sep","second":"2024 Jul–Sep","quarterly: 2025-Q2":"2025 Apr–Jun","quarterly: 2025-Q3":"2025 Jul–Sep"};
const ck=Object.entries(RB).map(([name,v])=>{const res=v.results,kc=Object.keys(res[Object.keys(res)[0]]).find(c=>c.includes("scaled"));
 const ours=(res[ADOPTED]||res["current model (with vendor cap)"]||{})[kc];
 const base=Math.max(...Object.entries(res).filter(([n])=>n.startsWith("BASELINE")).map(([,x])=>x[kc]));
 const key=Object.keys(LBL).find(p=>name.startsWith(p));
 return `<tr><td>${esc(LBL[key]||name)}</td><td>${v.test_positives}</td><td class="${ours>base?"win":""}">${ours??"–"}</td><td>${base}</td></tr>`}).join("");
$("#checks").innerHTML=`<tr><th>Test window</th><th>Exploited</th><th>Ours</th><th>Best standard</th></tr>`+ck;

// KPIs
const TOP=ROWS.filter(r=>r.r<=500),bs=BT.bootstrap[Object.keys(BT.bootstrap)[0]];
$("#kpis").innerHTML=[
 ["Backtest catch",`${R.Ours[kk]} <span style="font-size:16px;color:var(--muted)">vs ${Math.max(...names.slice(0,3).map(n=>R[n][kk]))}</span>`,"c-white",`beats the best standard ranking in ${Math.round(bs.p_ours_better*100)}% of resamples`],
 ["Hidden risks in top 500",TOP.filter(hidden).length,"c-purple","no exploit code and EPSS < 1%: near the bottom of standard rankings"],
 ["Look-alikes found",TOP.filter(r=>r.nk).length,"c-green","of the top 500 closely match an already-exploited CVE"],
 ["Granite explanations",`${TOP.filter(r=>r.x).length}/500`,"c-blue","fact-checked; 0 claim a CVE is already exploited"]
].map(([l,v,c,s])=>`<div class="card kpi"><div class="kl">${l}</div><div class="kv ${c}">${v}</div><div class="ks">${s}</div></div>`).join("");

// ---------- local settings (this browser only) ----------
const store={get(k,d){try{const v=localStorage.getItem("btb_"+k);return v==null?d:JSON.parse(v)}catch(e){return d}},
 set(k,v){try{localStorage.setItem("btb_"+k,JSON.stringify(v))}catch(e){}}};
let PLAIN=store.get("plain",false),STACK=store.get("stack",[]),CMP=false;
const escRe=s=>s.replace(/[.*+?^${}()|[\]\\]/g,"\\$&");
let stackRe=[];
function setStack(list){STACK=list.map(s=>String(s).trim().toLowerCase()).filter(Boolean);store.set("stack",STACK);
 stackRe=STACK.map(t=>new RegExp("(^|[^a-z0-9])"+escRe(t)+"($|[^a-z0-9])","i"))}
setStack(Array.isArray(STACK)?STACK:[]);
const inStack=r=>stackRe.length>0&&stackRe.some(re=>re.test(r.v+" "+r.p+" "+r.d));

// ---------- plain-English layer (templates; facts only from the row) ----------
const ATT=[["Auth bypass","get in without a password"],["RCE","take control of it remotely"],["Command injection","run their own commands on it"],
 ["Deserialization","run their own code on it"],["File upload","plant malicious files on it"],["SQL injection","read or change its database"],
 ["Path traversal","read files they should not see"],["Privilege escalation","give themselves admin rights"],
 ["Memory corruption","crash it or run their own code"],["XSS","hijack a signed-in user through a booby-trapped link"],["DoS","knock it offline"]];
const GATT={"authentication bypass":"get in without a password","command injection":"run their own commands on it","remote code execution":"take control of it remotely",
 "path traversal / file read":"read files they should not see","deserialization":"run their own code on it","SQL injection":"read or change its database",
 "memory corruption":"crash it or run their own code","privilege escalation":"give themselves admin rights","cross-site scripting":"hijack a signed-in user through a booby-trapped link",
 "denial of service":"knock it offline","information disclosure":"see information they should not"};
const cap=s=>String(s||"").replace(/\b[a-z]/g,c=>c.toUpperCase());
// show a name the way the CVE's own description spells it (PAN-OS, FortiOS), else Title Case
function nice(name,d){name=String(name||"");if(!name)return "";const i=String(d||"").toLowerCase().indexOf(name.toLowerCase());
 return i>=0?String(d).substr(i,name.length):cap(name)}
function light(r){return r==null?`<span class="light l-grn"><i></i>Routine updates</span>`:r<=500?`<span class="light l-red"><i></i>Update now</span>`:`<span class="light l-amb"><i></i>Keep an eye on</span>`}
function trig(r){if(r.r<=500)return "";if(r.cp)return "Already scores like a top-500 CVE; held back only by the 20-per-vendor limit";
 const p=[];if(r.tc)p.push("if public exploit code appears");if(r.te!=null)p.push("if EPSS reaches "+(r.te*100).toFixed(r.te<0.01?1:0)+"%");
 return p.length?"Moves to Fix now "+p.join(" or "):""}
function plainWhy(r){
 const prod=nice(r.p||r.v,r.d)||"This software",a=ATT.find(([t])=>r.tg.includes(t)),what=a?a[1]:(GATT[r.a]||"misuse it");
 let s=`A flaw in ${esc(prod)} could let attackers ${what}.`;
 if(r.tg.includes("Edge device"))s+=" Its description points to a network-edge product (such as a VPN, firewall, router or gateway), the kind attackers scan the internet for.";
 else if(r.i==="yes")s+=" It is likely reachable from the internet.";
 if(r.vk)s+=` Attackers have already exploited ${r.vk} earlier ${esc(nice(r.v,r.d))} flaw${r.vk>1?"s":""}.`;
 if(r.c.length)s+=" Attack code is already public.";
 if(r.nk)s+=" It closely resembles a flaw criminals have already used.";
 if(r.r<=500)s+=" <b>Install the fix as soon as it is available. If you can't yet, limit who can reach it.</b>";
 else{s+=" Keep automatic updates on.";const t=trig(r);
  if(r.cp)s+=" It already scores as high as our urgent list.";
  else if(t)s+=" We'd move it to “update now” "+esc(t.replace(/^Moves to Fix now /,""))+".";}
 return s}
function std(r){const f=(n,l)=>`<div>${l} <span class="${n<=500?"hit":"miss"}">#${n.toLocaleString()}</span></div>`;return `<div class="std">${f(r.rc,"CVSS first")}${f(r.rx,"Exploit code first")}</div>`}

// ---------- filters ----------
const SEGS=[["fix","Fix now",r=>r.r<=500],["stack","My stack",inStack],["watch","Watchlist",r=>r.r>500],["hidden","Hidden risks",r=>r.r<=500&&hidden(r)],["code","Exploit code public",r=>r.c.length>0],["edge","Edge & internet-facing",edge],["look","Has look-alike",r=>!!r.nk],["all","All 3,000",r=>true]];
let seg="fix",page=0,PS=25,sortK="r",sortDir=1,view=[];
function renderSeg(){$("#seg").innerHTML=SEGS.map(([id,l,f])=>`<button data-s="${id}" class="${id==="hidden"?"hid":""}">${l}<span class="cnt">${id==="stack"&&!STACK.length?"set up":ROWS.filter(f).length}</span></button>`).join("")}
const DESC={fix:"Fix now: the 500 CVEs most likely to be exploited next (our submission).",watch:"Watchlist: ranks 501–3,000. Each row says what new evidence would move it into Fix now.",hidden:"Hidden risks: top-500 CVEs with no public exploit code and EPSS below 1%, which standard tools rank near the bottom.",code:"CVEs with public exploit code at their snapshot.",edge:"VPNs, firewalls, gateways and other internet-facing products.",look:"CVEs whose description closely matches an already-exploited CVE.",all:"The top 3,000 of 72,670 scored CVEs.",stack:"My stack: CVEs that mention the vendors and products you listed."};
const PDESC={fix:"Update now: the 500 flaws we expect attackers to use next.",watch:"Keep an eye on: lower risk today. We say what would make each one urgent.",stack:"Things you use: flaws that mention the apps and devices you listed."};
function apply(){const f=SEGS.find(s=>s[0]===seg)[2],q=$("#q").value.toLowerCase().trim();
 view=ROWS.filter(r=>f(r)&&(!q||[r.id,r.v,r.p,r.nk,r.d,r.tg.join(" "),r.a].join(" ").toLowerCase().includes(q)));
 const key=sortK,dir=sortDir;view.sort((a,b)=>{let x=a[key],y=b[key];
  if(key==="e"||key==="ns"||key==="vk"){return ((y??-1)-(x??-1))*dir}
  if(key==="pub"){return (y<x?-1:y>x?1:0)*dir}
  if(key==="id"){return (x<y?-1:x>y?1:0)*dir}
  return (x-y)*dir});
 page=0;answer(q);draw();}
function answer(q){const box=$("#ans");
 if(seg==="stack"&&!STACK.length){box.hidden=false;box.innerHTML=`List the products you use with <b>Edit my stack</b> to see only the CVEs that matter to you.`;return}
 if(!PLAIN||!q){box.hidden=true;return}
 const m=ROWS.filter(r=>[r.v,r.p,r.d].join(" ").toLowerCase().includes(q)),red=m.filter(r=>r.r<=500).length,amb=m.length-red;
 box.hidden=false;
 box.innerHTML=m.length?`<b>“${esc(q)}”</b> appears in ${m.length} of our 3,000 highest-risk 2026 CVEs: ${light(1)} <b>${red}</b> · ${light(600)} <b>${amb}</b>. ${red?"Update it as soon as fixes are out.":"Nothing urgent; keep automatic updates on."} Details below.`
  :`${light(null)} Nothing in our 3,000 highest-risk 2026 CVEs mentions <b>“${esc(q)}”</b>. Keep normal automatic updates on.`}
function epss(e){if(e==null)return `<span class="small">none yet</span>`;const c=e>=0.1?"e-hi":e>=0.01?"e-mid":"e-lo";return `<span class="mono epss ${c}">${e.toFixed(e<0.001?5:4)}</span>`}
function head(){
 const H=PLAIN?[["r","Rank"],["","How urgent"],["","What's affected"],["","What it means for you"],["",""]]
  :[["r","Rank"],["id","CVE"],["","Predicted risk"],["e","EPSS at snapshot"],["","Exploit code"],["vk","Vendor · history"],["ns","Looks like (past exploited)"]].concat(CMP?[["","Standard rankings would put it"]]:[]).concat([["","Why it's ranked here"],["",""]]);
 $("#th").innerHTML="<tr>"+H.map(([k,l])=>`<th${k?` data-k="${k}"`:""}>${l}${k&&k===sortK?` <span class="ar">${sortDir===1?"▲":"▼"}</span>`:""}</th>`).join("")+"</tr>"}
function row(r){const [t,tc]=tier(r.r);
 if(PLAIN)return `<tr><td class="mono" style="color:var(--muted)">#${r.r}</td><td>${light(r.r)}</td>
  <td><b>${esc(nice(r.p||r.v,r.d)||"Product not named")}</b>${!r.v&&r.as?`<div class="small">reported by ${esc(r.as)}</div>`:""}${r.p&&r.v?`<div class="small">${esc(nice(r.v,r.d))}</div>`:""}<div class="small mono">${r.id}</div></td>
  <td class="plainwhy">${plainWhy(r)}</td><td><button class="insp" data-id="${r.id}">Details</button></td></tr>`;
 const tg=trig(r);
 return `<tr>
 <td class="mono" style="color:var(--muted)">#${r.r}</td>
 <td><div class="cve mono">${r.id}</div><div class="small">${r.pub} · snapshot ${r.m}</div><div class="chips">${r.tg.slice(0,2).map(t=>`<span class="badge b-gry">${esc(t)}</span>`).join("")}</div></td>
 <td><span class="badge ${tc}">${t}</span><div class="small" style="margin-top:4px" title="CISA SSVC-style decision: ${ssvc(r.r)[1]}">SSVC: <b style="color:#e5e7eb">${ssvc(r.r)[0]}</b> · top ${(r.r/POOL*100).toFixed(r.r<73?3:2)}%</div>${hidden(r)&&r.r<=500?`<div style="margin-top:4px"><span class="badge b-pur">hidden risk</span></div>`:""}</td>
 <td>${epss(r.e)}<div class="small">${r.m>="2025-03"?"EPSS v4":"EPSS v3"}</div></td>
 <td>${r.c.length?`<div class="chips">${r.c.map(c=>`<span class="badge b-crit">${c}</span>`).join("")}</div>`:`<span class="small">none public</span>`}</td>
 <td>${r.v?`<b>${esc(r.v)}</b>`:`<span class="small">vendor not named · reported by ${esc(r.as||"unknown")}</span>`}${r.p?`<div class="small">${esc(r.p)}</div>`:""}${r.vk?`<div style="margin-top:3px"><span class="badge b-high">${r.vk} earlier KEV</span></div>`:""}</td>
 <td>${r.nk?`<span class="mono" style="color:var(--green)">${r.nk}</span><div class="small">similarity ${r.ns.toFixed(2)}${r.nki.date?" · exploited "+r.nki.date.slice(0,7):""}</div>`:`<span class="small">no close match</span>`}</td>
 ${CMP?`<td>${std(r)}</td>`:""}
 <td class="why">${esc((r.w.filter(w=>!w.startsWith("description resembles")).slice(0,2).join("; "))||r.w[0]||"")}${tg?`<div class="trig">⬆ ${esc(tg)}</div>`:""}</td>
 <td><button class="insp" data-id="${r.id}">Inspect</button></td></tr>`}
function draw(){
 document.querySelectorAll("#seg button").forEach(b=>b.classList.toggle("on",b.dataset.s===seg));
 let d=(PLAIN&&PDESC[seg])||DESC[seg];
 if(CMP&&!PLAIN&&seg==="fix")d+=` Sorting by CVSS would leave ${TOP.filter(r=>r.rc>500).length} of these 500 outside its top 500; sorting by exploit code would leave ${TOP.filter(r=>r.rx>500).length}.`;
 $("#desc").textContent=d;$("#n").textContent=view.length.toLocaleString();
 head();
 $("#tb").innerHTML=view.slice(page*PS,page*PS+PS).map(row).join("")||`<tr><td colspan="10" class="small" style="padding:20px">No CVEs match.</td></tr>`;
 $("#pg").textContent=view.length?`${page*PS+1}–${Math.min(view.length,page*PS+PS)} of ${view.length.toLocaleString()}`:"";
}
function inspect(id){const r=ROWS.find(x=>x.id===id);if(!r)return;const [t,tc]=tier(r.r),tg=trig(r);
 $("#mbox").innerHTML=`<div class="mhead"><div><div class="cve mono" style="font-size:20px">${r.id}</div><div class="small">Published ${r.pub} · snapshot ${r.m} · reported by ${esc(r.as)}</div>
 <div class="chips" style="margin-top:8px">${light(r.r)}<span class="badge ${tc}">${t} · rank #${r.r} of ${POOL.toLocaleString()}</span>${hidden(r)&&r.r<=500?'<span class="badge b-pur">hidden risk</span>':""}${inStack(r)?'<span class="badge b-ok">in my stack</span>':""}${r.tg.map(x=>`<span class="badge b-gry">${esc(x)}</span>`).join("")}</div></div>
 <button class="x" aria-label="Close" id="xbtn">×</button></div>
 <div class="sec"><h4>In plain English</h4><div class="plainwhy">${plainWhy(r)}</div></div>
 ${r.x?`<div class="sec gran"><h4>IBM Granite 4 · fact-checked explanation</h4>${esc(r.x)}${r.i||r.a?`<div class="chips" style="margin-top:8px">${r.i?`<span class="badge b-watch">internet-facing: ${esc(r.i)}</span>`:""}${r.a?`<span class="badge b-watch">${esc(r.a)}</span>`:""}</div>`:""}</div>`:""}
 <div class="grid2"><div class="sec"><h4>Why the model ranks it here</h4>${r.w.length?r.w.map(x=>`<div>• ${esc(x)}</div>`).join(""):"<span class='small'>–</span>"}</div>
 <div class="sec"><h4>Signals at snapshot</h4><div>EPSS: ${epss(r.e)}</div><div>Exploit code: ${r.c.length?esc(r.c.join(", ")):"none public"}</div><div>Vendor: <b>${esc(r.v||"unknown")}</b>${r.vk?` · ${r.vk} earlier KEV entries`:""}</div></div></div>
 <div class="grid2"><div class="sec"><h4>Why standard tools ${r.r<=500&&(r.rc>500||r.rx>500)?"miss it":"rank it differently"}</h4>${std(r)}<div class="small" style="margin-top:6px">Ranks among all ${POOL.toLocaleString()} scored CVEs. Red = outside that method's top 500.</div></div>
 <div class="sec"><h4>${r.r<=500?"Status":"What would move it to Fix now"}</h4>${r.r<=500?`In the top 500 (our submission). SSVC-style decision: <b>${ssvc(r.r)[0]}</b> (${ssvc(r.r)[1]}).`:esc(tg||"Several new signals at once; no single change is enough.")}<div class="small" style="margin-top:6px">${r.r<=500?"":"Model what-if: we re-scored this CVE with that one signal changed."}</div></div></div>
 ${bandOdds(r.r)?`<div class="sec"><h4>How often CVEs ranked like this were exploited</h4>${bandOdds(r.r)}<div class="small" style="margin-top:6px">Measured on the 2025 backtest, so it is an observed rate, not a guarantee. Small counts.</div></div>`:""}
 ${r.nk?`<div class="sec"><h4>Looks like an already-exploited CVE</h4><span class="mono" style="color:var(--green)">${r.nk}</span>: ${esc(r.nki.name||"")}<div class="small">Description similarity ${r.ns.toFixed(2)} · added to KEV ${esc(r.nki.date||"")}${r.nki.ransom?" · used in ransomware":""} · <a href="https://nvd.nist.gov/vuln/detail/${r.nk}" target="_blank" rel="noopener">NVD ↗</a></div></div>`:""}
 <div class="sec"><h4>Description</h4><div style="color:#d1d5db">${esc(r.d)}</div><div class="small" style="margin-top:6px"><a href="https://nvd.nist.gov/vuln/detail/${r.id}" target="_blank" rel="noopener">Open ${r.id} on NVD ↗</a></div></div>`;
 $("#modal").classList.add("open");$("#xbtn").onclick=closeM;}
function closeM(){$("#modal").classList.remove("open")}
$("#modal").addEventListener("click",e=>{if(e.target.id==="modal")closeM()});document.addEventListener("keydown",e=>{if(e.key==="Escape")closeM()});
$("#tb").addEventListener("click",e=>{const b=e.target.closest(".insp");if(b)inspect(b.dataset.id)});
$("#seg").addEventListener("click",e=>{const b=e.target.closest("button");if(b){seg=b.dataset.s;if(seg==="stack"&&!STACK.length){$("#stackbox").hidden=false;$("#stackIn").focus()}apply()}});
$("#q").addEventListener("input",apply);$("#sort").addEventListener("input",()=>{sortK=$("#sort").value;sortDir=1;apply()});
$("#ps").addEventListener("input",()=>{PS=+$("#ps").value;page=0;draw()});
$("#th").addEventListener("click",e=>{const th=e.target.closest("th[data-k]");if(!th)return;const k=th.dataset.k;sortDir=sortK===k?-sortDir:1;sortK=k;if(["r","e","vk","ns","pub"].includes(k))$("#sort").value=k;apply()});
$("#prev").onclick=()=>{if(page>0){page--;draw()}};$("#next").onclick=()=>{if((page+1)*PS<view.length){page++;draw()}};
$("#cmp").onchange=()=>{CMP=$("#cmp").checked;draw()};
function setPlain(p){PLAIN=!!p;store.set("plain",PLAIN);document.body.classList.toggle("plain",PLAIN);const b=$("#plainBtn");b.setAttribute("aria-pressed",String(PLAIN));b.textContent="Plain English: "+(PLAIN?"on":"off");
 $("#q").placeholder=PLAIN?"Do I need to worry about…? Type an app or device you use, e.g. Chrome, WinRAR, Fortinet":"Search CVE, vendor, product, look-alike, description…";apply()}
$("#plainBtn").onclick=()=>setPlain(!PLAIN);
$("#stackBtn").onclick=()=>{const b=$("#stackbox");b.hidden=!b.hidden;$("#stackIn").value=STACK.join(", ")};
$("#stackSave").onclick=()=>{setStack($("#stackIn").value.split(","));renderSeg();seg="stack";$("#stackbox").hidden=true;apply();drawVend()};
$("#stackIn").addEventListener("keydown",e=>{if(e.key==="Enter")$("#stackSave").click()});
document.querySelectorAll(".ex").forEach(b=>b.onclick=()=>{$("#stackIn").value=b.dataset.s});
$("#csv").onclick=()=>{const h=["rank","cve_id","tier","urgency","ssvc_style","published","snapshot_month","epss","exploit_code","vendor","product","vendor_prior_kev","looks_like","similarity","rank_if_cvss_first","rank_if_exploit_code_first","moves_up_if","why","plain_english","evidence","granite_explanation"];
 const q=v=>'"'+String(v??"").replace(/"/g,'""')+'"',strip=s=>s.replace(/<[^>]+>/g,"").replace(/&amp;/g,"&").replace(/&lt;/g,"<").replace(/&gt;/g,">").replace(/&quot;/g,'"');
 const b=new Blob([[h.join(",")].concat(view.map(r=>[r.r,r.id,tier(r.r)[0],r.r<=500?"update now":"keep an eye on",ssvc(r.r)[0],r.pub,r.m,r.e,r.c.join(";"),r.v,r.p,r.vk,r.nk,r.ns,r.rc,r.rx,trig(r),r.w.join("; "),strip(plainWhy(r)),r.ev,r.x].map(q).join(","))).join("\n")],{type:"text/csv"});
 const a=document.createElement("a");a.href=URL.createObjectURL(b);a.download="before_the_breach_"+seg+".csv";a.click()};

// ---------- Time Machine (2025 replay) ----------
const TB=["Highest CVSS 3 first","EPSS first","Public exploit code first, then EPSS"],TK=TM.k;
let tmMonth="all";
function drawTM(){if(!TM.cves||!TM.cves.length){$("#tmNote").textContent="Run python pipeline/backtest.py to build the replay.";return}
 $("#tmPos").textContent=TM.positives;$("#tmK").textContent=TK;$("#tmPool").textContent=TM.pool.toLocaleString();
 const C=TM.cves,ours=C.filter(c=>c.ranks.Ours<=TK),best=Math.max(...TB.map(b=>C.filter(c=>c.ranks[b]<=TK).length));
 const leads=ours.map(c=>c.lead_days).sort((a,b)=>a-b),med=leads.length?(leads[(leads.length-1)>>1]+leads[leads.length>>1])/2:0;
 const only=ours.filter(c=>c.ranks["Public exploit code first, then EPSS"]>TK).length;
 $("#tmKpis").innerHTML=[["Caught in time",`${ours.length} <span style="font-size:16px;color:var(--muted)">of ${TM.positives}</span>`,"c-white",`best standard ranking caught ${best}`],
  ["Median warning",`${Math.round(med)} days`,"c-green","between our list and CISA confirming the attack"],
  ["Only we caught",only,"c-purple","exploited CVEs the exploit-code ranking left outside its top "+TK],
  ["Longest warning",`${leads.length?leads[leads.length-1]:0} days`,"c-amber","before CISA's listing"]]
  .map(([l,v,c,s])=>`<div class="card kpi"><div class="kl">${l}</div><div class="kv ${c}">${v}</div><div class="ks">${s}</div></div>`).join("");
 const months=[...new Set(C.map(c=>c.month))].sort(),MN=["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"];
 $("#tmSeg").innerHTML=[["all","All of 2025"]].concat(months.map(m=>[m,MN[+m.slice(5)-1]+" 2025"])).map(([m,l])=>{const n=m==="all"?C.length:C.filter(c=>c.month===m).length,h=m==="all"?ours.length:ours.filter(c=>c.month===m).length;
  return `<button data-m="${m}" class="${m===tmMonth?"on":""}">${l}<span class="cnt">${h}/${n}</span></button>`}).join("");
 const rk=(n)=>`<td class="mono ${n<=TK?"in":"out"}">#${n.toLocaleString()}</td>`;
 $("#tmTb").innerHTML=C.filter(c=>tmMonth==="all"||c.month===tmMonth).map(c=>`<tr>
  <td><div class="cve mono">${c.id}</div><div class="small">published ${c.published} · CISA added ${c.kev_added}</div><div class="small" style="max-width:340px">${esc(c.desc.slice(0,140))}${c.desc.length>140?"…":""}</div></td>
  <td><b>${esc(c.vendor||"–")}</b>${c.product?`<div class="small">${esc(c.product)}</div>`:""}<div class="small">EPSS ${c.epss==null?"none":(c.epss*100).toFixed(2)+"%"} · ${c.code?"exploit code public":"no public code"}</div></td>
  ${rk(c.ranks.Ours)}${rk(c.ranks[TB[0]])}${rk(c.ranks[TB[1]])}${rk(c.ranks[TB[2]])}
  <td>${c.ranks.Ours<=TK?`<span class="badge b-ok">Flagged ${c.lead_days} day${c.lead_days===1?"":"s"} before CISA</span>`:`<span class="badge b-gry">Missed</span>`}${c.ranks.Ours<=TK&&c.ranks[TB[2]]>TK?`<div style="margin-top:4px"><span class="badge b-pur">standard tools missed it</span></div>`:""}</td></tr>`).join("");
 $("#tmNote").textContent="Green = inside the top "+TK+". "+TM.note+" Our ranks include the vendor limit (at most "+BT.vendor_cap+" per vendor in the top "+TK+"), exactly as in the backtest. The month buttons show caught / exploited."}
$("#tmSeg").addEventListener("click",e=>{const b=e.target.closest("button");if(b){tmMonth=b.dataset.m;drawTM()}});

// ---------- Vendor scorecard ----------
let vAll=false;
const VEND=(()=>{const m={};ROWS.forEach(r=>{const k=(r.v||"").toLowerCase().trim();if(!k)return;
 const o=m[k]||(m[k]={v:k,fix:0,watch:0,hid:0,look:0,kev:0,best:1e9,rows:[]});
 if(r.r<=500)o.fix++;else o.watch++;if(r.r<=500&&hidden(r))o.hid++;if(r.r<=500&&r.nk)o.look++;o.kev=Math.max(o.kev,r.vk);o.best=Math.min(o.best,r.r);o.rows.push(r)});
 return Object.values(m).sort((a,b)=>b.fix-a.fix||b.watch-a.watch||a.best-b.best)})();
function drawVend(){const q=$("#vq").value.toLowerCase().trim(),mine=$("#vmine").checked;
 const L=VEND.filter(o=>(!q||o.v.includes(q))&&(!mine||o.rows.some(inStack)));
 const S=vAll||q||mine?L:L.slice(0,50);
 $("#vTb").innerHTML=S.map(o=>`<tr><td><button class="vlink" data-v="${esc(o.v)}">${esc(nice(o.v,o.rows[0].d))}</button></td><td class="${o.fix?"in":"out"}">${o.fix}</td><td>${o.watch}</td><td>${o.hid||"–"}</td><td>${o.look||"–"}</td><td>${o.kev||"–"}</td><td class="mono">#${o.best}</td><td><button class="insp" data-v="${esc(o.v)}">View CVEs</button></td></tr>`).join("")||`<tr><td colspan="8" class="small" style="padding:20px">No vendors match.</td></tr>`;
 $("#vpg").textContent=`${S.length} of ${L.length} vendors`;$("#vmore").hidden=S.length===L.length}
$("#vq").addEventListener("input",drawVend);$("#vmine").onchange=drawVend;$("#vmore").onclick=()=>{vAll=true;drawVend()};
$("#vTb").addEventListener("click",e=>{const b=e.target.closest("[data-v]");if(!b)return;seg="all";$("#q").value=b.dataset.v;show("rank");apply()});

// ---------- tabs ----------
function show(v){document.querySelectorAll(".view").forEach(x=>x.classList.toggle("on",x.dataset.v===v));
 document.querySelectorAll("#tabs button").forEach(b=>b.classList.toggle("on",b.dataset.v===v));
 try{history.replaceState(null,"","#"+v)}catch(e){}}
$("#tabs").addEventListener("click",e=>{const b=e.target.closest("button");if(b)show(b.dataset.v)});
renderSeg();drawTM();drawVend();


// findings
const L=FS.feature_lifts,A=FS.assigner_lifts;
$("#finds").innerHTML=[
 [pct(FS.pos_share_no_code_and_low_epss),"c-purple","of later-exploited CVEs had no public exploit code and EPSS < 1% at publication. Standard tools can't see them coming."],
 ["0 of "+L.kw_wp_plugin.n.toLocaleString(),"c-green","WordPress-plugin CVEs were later exploited. Safe to deprioritise."],
 [L.kw_auth_bypass.lift.toFixed(1)+"×","c-red","more likely to be exploited when the description says authentication bypass or unauthenticated."],
 [A["vulncheck.com"].lift.toFixed(1)+"×","c-amber","more likely when VulnCheck assigned the CVE."],
 [pct(FS.critical_cvss_hit_rate),"c-white","of critical-CVSS (9.0+) CVEs were exploited. Severity alone is a weak guide."],
 [pct(FS.leak_analyzed_share.exploited)+" vs "+pct(FS.leak_analyzed_share.others),"c-blue","were 'Analyzed' by NIST, exploited vs others. NIST's data leaks the answer, so we excluded it."]
].map(([v,c,l])=>`<div class="card find"><div class="kv ${c}">${v}</div><div class="ks">${l}</div></div>`).join("");
setPlain(PLAIN);
// ---------- Start here: the story in six steps ----------
function hbar(rows,max,fmt,cls){return rows.map(([label,v,c,tip])=>`<div class="hb" title="${esc(tip||label+": "+fmt(v))}"><span class="hl">${label}</span><div class="track"><div class="fill ${c||""}" style="width:${Math.max(v/max*100,v>0?1.5:0)}%"></div></div><b>${fmt(v)}</b></div>`).join("")}
function drawStart(){
 const L=FS.feature_lifts,A=FS.assigner_lifts,base=FS.base_rate,oneIn=Math.round(1/base);
 const B=["Highest CVSS 3 first","EPSS first","Public exploit code first, then EPSS"],best=Math.max(...B.map(n=>R[n][kk]));
 const C=TM.cves||[],caught=C.filter(c=>c.ranks.Ours<=TM.k),leads=caught.map(c=>c.lead_days).sort((a,b)=>a-b);
 const med=leads.length?(leads[(leads.length-1)>>1]+leads[leads.length>>1])/2:0;
 $("#stProblem").innerHTML=[[POOL.toLocaleString(),"2026 CVEs to rank (the scoreboard)"],["1 in "+oneIn.toLocaleString(),"2024–25 CVEs ended up exploited"],
  [FS.critical_cvss_count.toLocaleString(),"“critical” CVSS 9+ CVEs in 2024–25. Fixing them all would catch "+pct(FS.critical_cvss_hit_rate)+" exploited per ticket"]]
  .map(([v,l])=>`<div class="card hero"><div class="kv c-white">${v}</div><div class="ks">${l}</div></div>`).join("");
 const lk=FS.leak_analyzed_share,lc=FS.leak_nvd_cvss_share;
 $("#stLeak").innerHTML=`<div class="legend"><span><i class="sw s-red"></i>later exploited</span><span><i class="sw s-gry"></i>all other CVEs</span></div>`+
  [["NIST status says “Analyzed”",lk],["Has a CVSS score written by NIST",lc]].map(([t,v])=>`<div class="pair"><div class="pt">${t}</div>${hbar([["Exploited",v.exploited,"f-red"],["Others",v.others,"f-gry"]],1,pct)}</div>`).join("")+
  `<div class="note">A field that is 100% for one group and 74% for the other is a giveaway, not a signal. Other dropped fields: product lists (CPEs), reference links, CWE and last-modified date. Full list in COLUMNS_USED.md.</div>`;
 const nc=FS.pos_share_no_code_and_low_epss;
 $("#stBlind").innerHTML=`<div class="bigrow"><div class="kv c-purple">${pct(nc)}</div><div class="ks">of CVEs later exploited had <b>no public exploit code and EPSS below 1%</b> at the end of their publish month. A ranking built only on those signals puts them near the bottom.</div></div>
  <div class="stack" title="Exploited CVEs, 2024–25 (${FS.positives})"><div class="seg1" style="width:${nc*100}%"><span>${pct(nc)} invisible to standard signals</span></div><div class="seg2" style="width:${(1-nc)*100}%"><span>${pct(1-nc)} had a warning</span></div></div>
  <div class="note">${FS.positives} CVEs published 2024–25 that CISA later listed as exploited. Our model reads the description, vendor history and look-alikes to catch these.</div>`;
 const items=[["Public exploit code exists",L.any_exploit_code],["VulnCheck reported it",A["vulncheck.com"]],["Authentication bypass",L.kw_auth_bypass],["Deserialization",L.kw_deserial],
  ["Path traversal",L.kw_path_trav],["Remote code execution",L.kw_rce],["Critical CVSS (9+)",{lift:FS.critical_cvss_hit_rate/base,n:FS.critical_cvss_count}],["Vendor already on KEV",L.vendor_matched],["Edge device (VPN, firewall…)",L.kw_edge],
  ["SQL injection",L.kw_sqli],["Cross-site scripting",L.kw_xss],["Denial of service",L.kw_dos],["WordPress plugin",L.kw_wp_plugin]].sort((a,b)=>b[1].lift-a[1].lift||b[1].n-a[1].n);
 const lo=Math.log10(0.1),hi=Math.log10(25),x=v=>(Math.log10(Math.max(v,0.1))-lo)/(hi-lo)*100,one=x(1);
 $("#stLift").innerHTML=`<div class="legend"><span><i class="sw s-red"></i>more likely than average</span><span><i class="sw s-blu"></i>less likely</span><span class="note">log scale · hover for counts</span></div>`+
  items.map(([t,o])=>{const v=o.lift,up=v>=1,zero=v===0,a=Math.min(x(v),one),b=Math.max(x(v),one);
   return `<div class="lift" title="${esc(t)}: ${zero?"0 exploited":v.toFixed(1)+"× the average rate"} (${o.n.toLocaleString()} CVEs${o.positives!=null?", "+o.positives+" exploited":""})">
    <span class="hl">${t}</span><div class="ltrack"><div class="axis1" style="left:${one}%"></div>${zero?`<div class="zero">0 of ${o.n.toLocaleString()}</div>`:`<div class="lbar ${up?"f-red":"f-blu"}" style="left:${a}%;width:${Math.max(b-a,0.8)}%"></div>`}</div>
    <b class="${zero?"c-blue":""}">${zero?"0×":v>=10?Math.round(v)+"×":v.toFixed(v<1?2:1)+"×"}</b></div>`}).join("")+
  `<div class="lscale"><span style="left:${x(0.1)}%">0.1×</span><span style="left:${one}%">1× average</span><span style="left:${x(10)}%">10×</span></div>
  <div class="note">Severity is not useless: critical CVSS raises the odds 3.6×. But it is one signal among many, and several things a description says on day one are as strong or stronger. Ranking by CVSS alone caught ${R["Highest CVSS 3 first"][kk]} exploited CVEs in our 2025 test; combining all of these caught ${R.Ours[kk]}. ${L.kw_wp_plugin.n.toLocaleString()} WordPress-plugin and ${L.kw_dos.n.toLocaleString()} denial-of-service CVEs produced zero exploited.</div>`;
 const names=["Highest CVSS 3 first","EPSS first","Public exploit code first, then EPSS","Ours"],mx=Math.max(...names.map(n=>R[n][kk]));
 $("#stProof").innerHTML=`<div class="ct">Exploited CVEs caught in the top ${k}<span class="note"> (same share as the benchmark's top 500; ${BT.test_positives} exploited among ${BT.test_pool.toLocaleString()})</span></div>`+
  hbar(names.map(n=>[n==="Ours"?"<b>Our model</b>":esc(n),R[n][kk],n==="Ours"?"f-blu":"f-gry"]),mx,v=>String(v));
 const wins=Object.values(RB).filter(v=>{const res=v.results,kc=Object.keys(res[Object.keys(res)[0]]).find(c=>c.includes("scaled"));const o=(res[ADOPTED]||res["current model (with vendor cap)"]||{})[kc];
  return o>Math.max(...Object.entries(res).filter(([n])=>n.startsWith("BASELINE")).map(([,x])=>x[kc]))}).length,nRB=Object.keys(RB).length;
 const pm=BT.per_month,worse=pm.filter(m=>m.Ours<Math.max(...B.map(n=>m[n]))).length;
 $("#stSure").innerHTML=`<div class="ct">Is ${R.Ours[kk]} vs ${best} just luck? With ${BT.test_positives} positives, we checked four ways:</div>
  <ul class="checks">
   <li><b>${Math.round(bs.p_ours_better*100)}%</b> of 1,000 resamples of the test set: ours still ahead</li>
   <li><b>${pm.length-worse} of ${pm.length}</b> months: never behind the best standard ranking${worse?"":" in any month"}</li>
   <li><b>${wins} of ${nRB}</b> separate out-of-time windows ahead (1 behind in the smallest, 13 exploited)</li>
   <li><b>~${Math.round(med/7)} weeks</b> median warning before CISA confirmed the attack, for the ${caught.length} we caught</li></ul>
  <button class="btn" data-go="tm">Replay 2025 CVE by CVE →</button>`;
}
document.addEventListener("click",e=>{const b=e.target.closest("[data-go]");if(!b)return;const g=b.dataset.go;
 if(g==="tm"||g==="vend"){show(g);window.scrollTo(0,0);return}
 show("rank");seg="fix";$("#q").value="";if(g==="plain"&&!PLAIN)setPlain(true);else if(g==="fix"&&PLAIN)setPlain(false);else apply();window.scrollTo(0,0)});

// ---------- patch-budget slider (2025 replay, ranks within each month) ----------
const BSTEPS=[10,25,50,100,150,200,300,500,750,1000],BM=[["Highest CVSS 3 first","CVSS first"],["EPSS first","EPSS first"],["Public exploit code first, then EPSS","Exploit code first"],["Ours","Our model"]];
function drawBudget(){const C=TM.cves||[];if(!C.length||!C[0].mranks){$("#budget").hidden=true;return}
 const N=BSTEPS[+$("#bud").value],mp=Object.values(TM.month_pool||{}),avg=mp.length?mp.reduce((a,b)=>a+b,0)/mp.length:3900,nm=mp.length||9;
 const got=Object.fromEntries(BM.map(([k])=>[k,C.filter(c=>c.mranks[k]<=N).length])),mx=Math.max(1,...Object.values(got));
 $("#budN").textContent=N.toLocaleString()+" a month";$("#budP").textContent=`of ~${Math.round(avg).toLocaleString()} new CVEs (${(N/avg*100).toFixed(N/avg<0.01?1:0)}%)`;
 $("#budBars").innerHTML=hbar(BM.map(([k,l])=>[k==="Ours"?"<b>"+l+"</b>":l,got[k],k==="Ours"?"f-blu":"f-gry",`${l}: ${got[k]} of ${C.length} exploited CVEs caught`]),mx,v=>`${v}/${C.length}`);
 const ours=got.Ours,bestK=BM.slice(0,3).reduce((a,[k])=>got[k]>got[a]?k:a,BM[0][0]),best=got[bestK],bestL=BM.find(b=>b[0]===bestK)[1];
 const need=k=>{const r=C.map(c=>c.mranks[k]).sort((a,b)=>a-b);return ours>0&&ours<=r.length?r[ours-1]:null},nb=need(bestK);
 const per=v=>v?`1 in ${Math.round(N*nm/v).toLocaleString()}`:"none";
 $("#budStats").innerHTML=[
  [`+${ours-best}`,"c-green",`more exploited CVEs caught than the best standard method (${bestL}: ${best}) for the same effort`],
  [nb?`${(nb/N).toFixed(1)}×`:"–","c-amber",nb?`the effort: ${bestL.toLowerCase()} needs ~${nb.toLocaleString()} patches a month to catch the same ${ours}`:"no standard method reaches our count"],
  [per(ours),"c-white",`of our patches hit a CVE later exploited, vs ${per(got["Highest CVSS 3 first"])} sorting by CVSS. Overall: 1 in ${Math.round(TM.pool/TM.positives).toLocaleString()}`]
 ].map(([v,c,l])=>`<div class="bstat"><div class="kv ${c}">${v}</div><div class="ks">${l}</div></div>`).join("")}
$("#bud").addEventListener("input",drawBudget);
// ---------- 2025 hit rate for a 2026 rank band (shown in Inspect) ----------
const BANDS=[[1,100],[101,500],[501,1500],[1501,3000]];
function bandOdds(rank){const C=TM.cves||[];if(!C.length)return "";const b=BANDS.find(([lo,hi])=>rank>=lo&&rank<=hi);if(!b)return "";
 const f=TM.pool/POOL,lo=Math.max(1,Math.round((b[0]-1)*f)+1),hi=Math.round(b[1]*f),n=hi-lo+1,hit=C.filter(c=>c.ranks.Ours>=lo&&c.ranks.Ours<=hi).length;
 return hit?`In the 2025 test, <b>${hit} of ${n.toLocaleString()}</b> CVEs ranked in the equivalent band (2026 ranks ${b[0].toLocaleString()}–${b[1].toLocaleString()}) were later exploited: about <b>1 in ${Math.round(n/hit).toLocaleString()}</b>, vs 1 in ${Math.round(TM.pool/TM.positives).toLocaleString()} for an average CVE.`
  :`In the 2025 test, none of the ${n.toLocaleString()} CVEs in the equivalent band (2026 ranks ${b[0].toLocaleString()}–${b[1].toLocaleString()}) was later exploited.`}
drawStart();drawBudget();
show(["start","rank","tm","vend","find"].includes(location.hash.slice(1))?location.hash.slice(1):"start");
</script></body></html>"""


def main():
    rows, bt, fs, rb, tm = load()
    html = (HTML.replace("__ROWS__", json.dumps(rows, separators=(",", ":")))
                .replace("__TM__", json.dumps(tm, separators=(",", ":")))
                .replace("__BT__", json.dumps(bt, default=float))
                .replace("__FS__", json.dumps(fs, default=float))
                .replace("__RB__", json.dumps(rb, default=float))
                .replace("__POOL__", str(POOL))
                .replace("__ADOPTED__", json.dumps(ADOPTED)))
    out = os.path.join(core.ROOT, "dashboard.html")
    open(out, "w", encoding="utf-8").write(html)
    print(f"wrote {out} ({len(html) / 1e6:.1f} MB, {len(rows)} CVEs, "
          f"{sum(1 for r in rows if r['x'])} with Granite explanations)")


if __name__ == "__main__":
    main()
