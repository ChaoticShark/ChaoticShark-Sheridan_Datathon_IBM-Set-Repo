# Before the Breach

**Know which security flaws attackers will use next, before they do.**

Every year tens of thousands of new software security flaws are announced, far more than any team can fix. Only a small fraction (about 1 in 750) is ever used in a real attack. Before the Breach ranks every new flaw by how likely attackers are to use it, explains each one in plain language, and tells you what to fix first.

### 👉 [Try the live dashboard](https://chaoticshark.github.io/ChaoticShark-Sheridan_Datathon_IBM-Set-Repo/dashboard.html)
No installation or sign-up. It opens in your browser and walks you through the story in six short steps.

## Who it's for
| If you are… | You get… |
|---|---|
| **A security or IT team** | A ranked "fix now" list of 500 flaws, the evidence behind each one, and an alert for when a lower-priority flaw should move up |
| **A business owner or everyday user** | A Plain English mode with simple traffic lights (update now / keep an eye on), and a search box that answers "do I need to worry about this app?" |
| **Someone choosing suppliers** | A scorecard of which software vendors carry the most predicted risk this year |

## Does it work?
We tested it fairly: we trained it only on 2024 information, then checked its predictions for 2025 against the US government's official list of flaws confirmed as used in attacks.
- **It caught more real attacks:** 18 among its top picks, where the best standard method caught 14 (about 30% more) and sorting by severity score caught 8.
- **It gave early warning:** typically about **5 weeks** before the attack was officially confirmed.
- **It saves effort:** a team fixing 200 flaws a month would have covered **33 of the 52** attacked flaws with our list, versus 22 with the best standard method. Matching our result the standard way takes about 3 times the work.

## Why you can trust it
- **Every ranking comes with its reasons**, so you can see why a flaw is ranked high.
- **Explanations are written by IBM Granite AI and fact-checked automatically.** The AI is not allowed to claim something has already been attacked, or to invent numbers.
- **We removed data that would have let it "cheat"**, then proved the test was fair with automated checks that anyone can re-run.
- **Private by design:** the dashboard runs in your browser, and the list of software you use is never sent anywhere.

## Jargon, in one line each
- **CVE:** the official ID for a publicly announced security flaw (e.g. CVE-2026-0265).
- **CISA KEV:** the US Cybersecurity and Infrastructure Security Agency's list of flaws confirmed as exploited in real attacks.
- **CVSS:** a 0–10 severity score. It says how bad a flaw *could* be, not how likely it is to be used.
- **EPSS:** a public estimate of the chance a flaw gets exploited soon.
- **Exploit code:** published instructions or tools for attacking a flaw.

---

# For technical reviewers

**IBM track, Sheridan Datathon 2026 (Team Hackermen).** Start with [MODEL_CARD.md](MODEL_CARD.md) (the model on one page) and [COLUMNS_USED.md](COLUMNS_USED.md) (which data we used and why). `dashboard.html` also works offline when opened locally.

## The problem in one line
Over 92,000 CVEs were published in 2026. In 2024–25 only about 1 in 750 was later confirmed exploited. In our 2025 test, ranking by severity (CVSS) or by EPSS found only 8 exploited CVEs in a top 500.

## Results (walk-forward backtest, same shape as the benchmark)
Trained on 2024. Tested on CVEs published Jan–Sep 2025 that were not yet on CISA's exploited list (KEV), with labels = added to KEV by 2025-12-31.

| Ranking | Hits in benchmark-scaled top 243 | Hits in top 500 |
|---|---|---|
| Highest CVSS 3 first | 8 | 8 |
| EPSS first | 8 | 8 |
| Public exploit code first, then EPSS | 14 | 18 |
| **Ours** | **18** | **22** |

- Ours beat the best baseline in **91% of 1,000 bootstrap resamples** and was **never worse in any single month**.
- Ahead of the best baseline in **3 of 4 out-of-time checks** (2025 Jan–Sep, 2024 Q3, 2025 Q2), and 1 behind in the smallest one (2025 Q3, 13 exploited CVEs). See `results/robustness.json`. Rejected experiments are in `results/robustness_variants.json` and `results/experiments.json`.
- *The test pool (35k CVEs) is about half the size of the scoreboard (72.7k), so the "benchmark-scaled" column is the fair comparison to a top 500 on the real benchmark.*

## How it works
1. **Leak-safe inputs only** ([COLUMNS_USED.md](COLUMNS_USED.md)). NIST reviews exploited CVEs first, so `nvd_status`, product lists, reference links and even NIST's CVSS score quietly reveal the answer: 100% of later-exploited CVEs were "Analyzed" vs 74% of the rest. We drop them all and prove it with an automated leak test.
2. **What we use instead:**
   - EPSS and exploit-code flags *as of the snapshot month*
   - a text model trained on every CVE description since 2015
   - weakness-type and exposure keywords from the description
   - the reporting organisation's track record
   - each vendor's and product's history on the KEV list, counted only up to the snapshot date
   - similarity to the closest *already-listed* exploited CVE ("looks like CVE-2024-0012"), also shown to users as evidence
3. **Model:** a regularised logistic regression trained on a rolling pool of every CVE up to 24 months old in each 2024–2025 month. Each feature's contribution to a CVE's score becomes its plain-English "why".
4. **IBM Granite** (`granite4:3b` via Ollama) writes a two-sentence explanation per top CVE and extracts vendor, product, internet exposure and attack type. A validator rejects any output that claims a CVE is already exploited, quotes numbers not in its input, or doesn't read as a prediction. Rejected outputs are retried once, then replaced by a template.

## The dashboard: who it's for
`dashboard.html` is one offline file. It opens on **Start here**, which tells the story in six steps with charts: the problem, the NIST leak, why standard signals are blind on day one, what actually predicts exploitation, the proof, and a "pick your starting point" choice for each type of user. The other tabs:
- **2026 ranking.** *Fix now* (top 500) and *Watchlist* (501–3,000). Every watchlist CVE says what would move it into Fix now (re-scored with exploit code present, or with a higher EPSS). *Compare with standard rankings* shows where CVSS-first and exploit-code-first sorting would put each CVE. Inspect opens the evidence, the closest already-exploited look-alike and Granite's explanation.
- **Patch budget slider** (Start here, step 5): pick how many CVEs your team patches a month, and see how many later-exploited 2025 CVEs each method would have caught. At 200 a month: ours 33 of 52, the best standard method 22, which would need about 3× the patches to match us. Inspect also shows how often CVEs in that rank band were exploited in 2025 (e.g. about 1 in 12 for 2026 ranks 1–100, vs 1 in 678 overall).
- **SSVC-style decisions.** Every CVE is also labelled in CISA's SSVC vocabulary: *Act* (top 50), *Attend* (51–500), *Track\** (watchlist) or *Track*. It's an approximation, because real SSVC also weighs your own mission and exposure.
- **Plain English** (header toggle) is for non-specialists. It shows traffic lights and template sentences built only from the row's facts, and the search becomes "Do I need to worry about…?".
- **My Stack** saves the vendors and products you use in your own browser (localStorage; nothing is sent) and filters everything to them.
- **Time Machine** replays the 2025 backtest one CVE at a time: our rank vs each standard ranking for every CVE later exploited, and how many days before CISA's listing we flagged it (median about 5 weeks).
- **Vendors** is a scorecard of predicted 2026 risk per supplier, for vendor reviews and procurement.

None of these change the ranking. They read extra display-only columns (`rank_cvss`, `rank_code`, `trig_code`, `trig_epss`, `capped`) and `results/timemachine_2025.json`. `verify.py` checks that the replay matches the backtest and that the vendor cap holds.

## Run it
```bash
pip install -r requirements.txt
# put the organisers' data files in data/
python run_all.py                 # backtest -> robustness -> score 2026 -> Granite -> verify
python run_all.py --no-granite    # if Ollama is not available
```

| Output | What it is |
|---|---|
| `top500.csv` | Submission file: one column, `cve_id` |
| `results/top500_detailed.csv` | The 500 with scores, signals and plain-English reasons |
| `results/scoreboard_ranked.csv` | All 72,670 scoreboard CVEs ranked |
| `results/granite_explanations.csv` | Granite explanations, vendor, product, exposure, attack type, `validated` flag |
| `results/backtest.json`, `robustness.json`, `experiments.json` | Every evaluation number, including rejected variants |
| `dashboard.html` | Interactive dashboard (open in any browser, works offline) |
| `results/timemachine_2025.json` | 2025 replay: every later-exploited CVE, each method's rank, days of warning |
| `results/findings_stats.json` | The statistics behind [DATATHON_ANALYSIS_FINDINGS.md](DATATHON_ANALYSIS_FINDINGS.md) |

`python pipeline/verify.py` runs the integrity checklist (leaky columns, point-in-time history, train/test separation, sane baselines, Granite never claiming exploitation, submission format) and prints PASS/FAIL.

## Repository layout
```
pipeline/   core.py (leak-safe data + features), text_model.py, model.py (locked model),
            backtest.py, robustness.py, score_2026.py, granite_layer.py, embeddings.py,
            findings_stats.py, build_dashboard.py, verify.py
            (experiments.py, exp2.py, ranker.py = early exploration, superseded by model.py)
results/    all outputs and evaluation logs
legacy/     v1 of the project (retired: it used leaky columns; see legacy/README.md)
```

## IBM technology used
- **IBM Granite 4 (3B)** for grounded explanations and structured extraction
- *Explored, not used:* IBM Granite Embedding (30M) for "looks like this past exploited CVE" matching (`pipeline/embeddings.py`). It was too slow to embed every CVE on a laptop CPU, so the shipped model uses TF-IDF similarity limited to KEV entries known at each snapshot.

## Outside data
None. Only the files provided by the organisers.
