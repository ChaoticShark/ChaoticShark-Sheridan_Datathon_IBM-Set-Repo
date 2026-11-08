# Devpost write-up

## Project write-up (as submitted on Devpost)

**Before the Breach: predicting which new CVEs attackers will use, and saying why**

Security teams can't patch 90,000 new CVEs a year, and the usual shortcuts don't work. "Fix every critical" means 8,269 tickets in our 2024–25 data, of which only 0.47% were ever exploited. EPSS and exploit-code feeds miss most attacks before they happen: **60% of CVEs that later landed on CISA's KEV list had no public exploit code and EPSS below 1%** at the end of their publish month.

**What we found** (2024–25, 64k CVEs, 85 later exploited):
- **NIST's own data leaks the answer.** 100% of later-exploited CVEs were "Analyzed" by NIST vs 74% of others, because NIST reviews attacked CVEs first. Even CVSS leaks: whether the score came from NIST or the vendor depends on that review. We removed all of it, proved the leak with an automated test, and our score went *up*.
- **What a description says beats its severity score.** Authentication bypass: 4.9x more likely to be exploited. Deserialization: 4.0x. Cross-site scripting, the most common bug: 0.13x. **6,232 WordPress-plugin CVEs and 2,722 denial-of-service CVEs produced zero exploited.**
- **Who reports a CVE matters.** CVEs assigned by VulnCheck were exploited at 15.6x the base rate.
- **Attackers return to the same vendors.** 67% of exploited CVEs came from vendors already on KEV, vs 37% of all CVEs.

**What we built:**
- A leak-safe ranking model: logistic regression over snapshot-time EPSS and exploit flags, a text model of 10 years of CVE descriptions, exposure and weakness keywords, reporter track record, and point-in-time vendor/product KEV history.
- IBM Granite 4 writes a two-sentence, engineer-facing explanation for every top CVE and extracts vendor, product, internet exposure and attack type.
- A validator rejects any Granite output that claims a CVE is already exploited, invents numbers, or doesn't read as a prediction.
- An interactive dashboard (one offline HTML file) built for three kinds of user:
  - **Security teams:** *Fix now* (top 500) and *Watchlist* (501–3,000) views. Every watchlist CVE says what would move it up ("if public exploit code appears or EPSS reaches 1%"). A *Compare* toggle shows where CVSS-first and exploit-code-first sorting would put each CVE. CSV export goes straight into a ticket queue.
  - **Everyone else:** *Plain English* mode swaps the jargon for traffic lights ("Update now" / "Keep an eye on") and one-paragraph explanations. Typing "Do I need to worry about WinRAR?" gives a direct answer.
  - **Planning and procurement:** *My Stack* saves the products you run (in the browser only) and filters everything to them. A *Vendor scorecard* ranks suppliers by predicted 2026 risk.
- **Patch budget slider:** "I can patch 200 CVEs a month" → in the 2025 replay, ours caught 33 of 52 later-exploited CVEs, the best standard ranking 22. Matching us would take about 3× the patches.
- **Time Machine:** replays 2025 one CVE at a time, showing where each method ranked every CVE that was later exploited and how many days before CISA's listing we flagged it (median about 5 weeks).

**Proof:** a walk-forward backtest shaped exactly like the benchmark (train 2024 → test Jan–Sep 2025, judged on KEV adds by year end):
- **18 hits vs 14** for the best standard ranking (exploit code first, then EPSS) at the benchmark-scaled cutoff, and **22 vs 18** in the top 500. CVSS-first and EPSS-first found 8.
- Better in 91% of 1,000 bootstrap resamples, never worse in any month, and ahead in 3 of 4 separate out-of-time checks (1 behind in the smallest).
- Every top CVE shows its closest already-exploited look-alike, e.g. CitrixBleed 2 → the original CitrixBleed.
- For the 2026 list, 478 of our top 500 would fall outside a CVSS-first top 500: this is not a re-sort of what teams already see.
- Example: a Fortinet authentication bypass (CVE-2025-24472) with EPSS 0.04% and no exploit code. We ranked it #69; the exploit-code baseline ranked it #13,488. CISA added it to KEV 18 days after our list would have flagged it.

**Columns used:** see `COLUMNS_USED.md`. Snapshot-month EPSS and exploit flags; `description`, `assigner`, `cvss4_score`, `published`; KEV entries dated before each snapshot. **Not used:** `nvd_status`, `n_affected_cpes`, `n_references`, `affected_products.csv`, `references.csv`, CVSS 3, `cwe_ids`.

**IBM technology:** IBM Granite 4 (`granite4:3b`) via Ollama for grounded explanations and structured extraction.

**Outside data:** none.

**Honest limits:** 52 test positives, so small differences are noisy. KEV only counts confirmed attacks. Descriptions may have been edited after publication.

---

## Reproducibility checklist
- [x] `python run_all.py` runs end to end, and `python pipeline/verify.py` reports 0 FAIL (33 checks pass, 2 known Granite warnings)
- [x] `top500.csv` has exactly one column, `cve_id`, with 500 unique IDs that are all in `scoreboard_2026.csv`
- [x] Organisers' data files are excluded from the repo (`.gitignore`); put them in `data/` to re-run
- [x] Every number in this write-up matches `results/backtest.json`, `results/robustness.json` and `results/timemachine_2025.json`
