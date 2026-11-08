# Findings: what predicts exploitation (and what doesn't)

**Data:** scoreboard-shaped pools rebuilt from 2024 and 2025: CVEs published Jan–Sep, not on CISA KEV at the end of their publish month, labelled by whether they were added to KEV by the end of that year. That gives 64,119 CVEs, of which 85 were later exploited (a base rate of 0.13%, about 1 in 750). All numbers are in `results/findings_stats.json` and `results/backtest.json` and can be regenerated with `python pipeline/findings_stats.py`.

*(The v1 findings, based on a leaky score, are archived in `legacy/DATATHON_ANALYSIS_FINDINGS_v1.md`.)*

---

## 1. The answer key leaks into NIST's own data, so we had to remove it
| Signal | Later-exploited CVEs | All other CVEs |
|---|---|---|
| NIST status `Analyzed`/`Modified` | **100%** | 74% |
| CVSS 3 score supplied by NIST (not the vendor) | **65%** | 48% |

NIST analyses exploited CVEs first, so "has NIST looked at it?" partly encodes "was it attacked?". We dropped `nvd_status`, product lists, reference links, CWE and **all CVSS 3 data**. Keeping only vendor-supplied CVSS isn't enough, because "missing because NIST replaced it" is itself a leak. We caught that in our own first version. Removing it *improved* the backtest. Details are in [COLUMNS_USED.md](COLUMNS_USED.md).

## 2. Most exploited CVEs look harmless to standard tools at publication
- **60%** of later-exploited CVEs had **no public exploit code *and* EPSS below 1%** at the end of their publish month.
- **86%** had EPSS below 1%.
- When they were exploited, KEV listed them a median of **36 days** after the snapshot.

This is why EPSS-first and code-first rankings plateau: they can only see the 40% that already show public signals. In our 2026 top 500, **256 CVEs have no exploit code and EPSS < 1%**. These are risks that EPSS and exploit-code rankings would put near the bottom.

## 3. Severity is a weak predictor
8,269 CVEs scored CVSS ≥ 9.0 (critical). Only **0.47%** were later exploited. "Fix all criticals" means 8,269 tickets to catch about 39 attacks, and it misses everything below 9.0.

## 4. What the description says matters more than the score
Exploitation rate when the description mentions… (lift = times more likely than average):

| Description says | CVEs | Later exploited | Lift |
|---|---|---|---|
| Public exploit code exists (signal, not text) | 1,393 | 34 | **18.4x** |
| Authentication bypass / unauthenticated | 4,922 | 32 | **4.9x** |
| Deserialization | 750 | 4 | 4.0x |
| Path traversal | 1,416 | 7 | 3.7x |
| Remote code execution | 5,598 | 24 | 3.2x |
| Edge device (VPN, firewall, gateway) | 2,375 | 7 | 2.2x |
| SQL injection | 4,996 | 3 | 0.45x |
| Cross-site scripting | 11,755 | 2 | **0.13x** |
| Denial of service | 2,722 | **0** | 0 |
| **WordPress plugin** | **6,232** | **0** | **0** |

**6,232 WordPress-plugin CVEs (10% of all new CVEs) produced zero KEV entries.** XSS is the most common weakness and almost never makes KEV. A team that deprioritises these two categories frees about 28% of its queue at almost no risk.

## 5. Who reports the CVE is a signal
| Reporting organisation (CNA) | CVEs | Later exploited | Lift |
|---|---|---|---|
| **VulnCheck** | 436 | 9 | **15.6x** |
| HackerOne | 199 | 2 | 7.6x |
| Apache | 363 | 3 | 6.2x |
| Fortinet | 255 | 2 | 5.9x |
| Microsoft | 1,683 | 7 | 3.1x |
| MITRE (default) | 8,321 | 12 | 1.1x |

VulnCheck often assigns CVEs to bugs it has seen exploited or that are ready to exploit. Its CVEs are about 1 in 48, against 1 in 750 overall.

## 6. Attackers return to the same vendors
**67%** of later-exploited CVEs came from a vendor that was already on KEV, against 37% of all CVEs. The repeat names were Microsoft, Ivanti, Adobe, VMware, Progress, Apache, Fortinet, SonicWall and SolarWinds. Our model gets most of this signal from the description text and each product's KEV history.

---

## Result: earlier and better than the standard rankings
Walk-forward backtest: train on 2024, test on Jan–Sep 2025 (35,280 CVEs, 52 later exploited).

| Ranking | Hits in benchmark-scaled top 243 | Top 500 | Top 1000 |
|---|---|---|---|
| Highest CVSS 3 first | 8 | 8 | 14 |
| EPSS first | 8 | 8 | 13 |
| Public exploit code first, then EPSS | 14 | 18 | 22 |
| **Ours** | **18** | **22** | **25** |

- Better than the best baseline in **91% of 1,000 bootstrap resamples**, and **never worse in any month** (better in 4 of 9).
- **Four out-of-time checks** (`results/robustness.json`), each retrained only on what was known at its start, labels included:

  | Test window | Exploited later | Ours | Best baseline |
  |---|---|---|---|
  | 2025 Jan–Sep (main) | 52 | **18** | 14 |
  | 2024 Jul–Sep | 12 | **4** | 1 |
  | 2025 Apr–Jun (quarterly walk-forward) | 19 | **11** | 9 |
  | 2025 Jul–Sep (quarterly walk-forward) | 13 | 1 | **2** |

  (Each is at that window's benchmark-scaled cutoff.) Ahead in 3 of 4 windows. In the smallest window (13 exploited) we are 1 behind at the scaled cutoff but ahead in the top 500 (6 vs 5). With this few positives, 1 hit is noise.
- **Found what others miss:**
  - CVE-2025-24472 (Fortinet authentication bypass): EPSS 0.04%, no exploit code. Ours ranked it **#69**; the exploit-code-first baseline ranked it **#13,488**. CISA listed it 18 days after our list would have flagged it.
  - CVE-2025-9242 (WatchGuard Fireware): ours **#88** vs **#1,726**.
  - CVE-2025-34028 (Commvault, VulnCheck-assigned): ours **#50** vs **#74**.

### Time Machine: how much warning would it have given?
`results/timemachine_2025.json` replays the backtest one CVE at a time. For each of the 52 CVEs that CISA later listed, it records our rank and each standard ranking's rank, using only what was known at the end of the CVE's publish month.
- We caught **18 of 52** in the benchmark-scaled top 243. The best standard ranking caught 14.
- For the 18 we caught, CISA's listing came a **median of about 5 weeks later** (35.5 days) after our list would have flagged it. The longest gap was 162 days and the shortest 1 day.
- **5 of the 18** were outside the exploit-code-first ranking's top 243.
- It also works in reverse for 2026: **478 of our top 500 would fall outside the top 500 if you sorted by CVSS**, and 366 if you sorted by exploit code. Our list is not a re-shuffle of what teams already look at.

### Patch budget: what it means for a real team
If a team patches the top N new CVEs each month of Jan–Sep 2025 (ranked within each month, using only what was known then), the later-exploited CVEs caught out of 52 are:

| Patches per month | CVSS first | EPSS first | Exploit code first | **Ours** | Exploit-code-first needs, to match us |
|---|---|---|---|---|---|
| 25 | 6 | 8 | 14 | **18** | ~46 a month |
| 100 | 11 | 10 | 21 | **25** | ~260 a month |
| 200 | 17 | 16 | 22 | **33** | ~659 a month |
| 500 | 21 | 27 | 32 | **41** | ~1,865 a month |

Ours catches the most at every budget. To match it, the best standard ranking needs roughly 2–4× the patching effort. In the dashboard's Start here tab, this is an interactive slider.

## 7. New exploits look like old exploits
For every CVE we find the most similar description among exploited-list entries that were **already listed at its snapshot**. Examples:
- CVE-2025-24472 (Fortinet authentication bypass) → CVE-2024-55591, the earlier exploited Fortinet authentication bypass.
- CVE-2025-5777 ("CitrixBleed 2") → CVE-2023-4966, the original CitrixBleed.
- Our 2026 #1, CVE-2026-0265 (Palo Alto) → CVE-2024-0012 (similarity 0.80, exploited Nov 2024).

As a model feature it was neutral-to-positive on all four checks, so we kept it. It is also shown to users as evidence. *(Idea from teammate Dariusz Ruszkowski's version; we rebuilt it so the vocabulary and matches use only KEV entries known at the time.)*

## IBM Granite: what it does and how well
- 500/500 top CVEs have a Granite 4 (3B) explanation. 497 passed the grounding validator and 3 fell back to a template. **0 claim a CVE is already exploited.**
- Vendor extraction checked against NIST's product list on 150 CVEs from 2025: **57% exact**, 25% "unknown" (Granite abstained) and 18% a different name, often the platform rather than NIST's vendor label. Granite's extraction is therefore **display-only**. The ranking uses its own vendor matching.

## Honest limits
- Small numbers: 52 test positives. Differences of 1–3 hits are within noise, which is why we report bootstrap and per-month results.
- KEV only covers *confirmed* attacks. CVEs exploited but never listed count as misses for every method.
- Descriptions are today's versions. 36 scoreboard descriptions mention exploitation. All are dated at or before publication (checked automatically), so we keep them as legitimate early warnings. Hiding them would lower the backtest from 18 to 16.
- A per-vendor cap (at most 20 per vendor in the top 500) was neutral in the backtest. We keep it to avoid betting 20+ slots on a single advisory.
