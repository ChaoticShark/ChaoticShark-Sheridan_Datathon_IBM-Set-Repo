# Model card: Before the Breach exploitation ranker

| | |
|---|---|
| **What it predicts** | How likely a newly published CVE is to be added to CISA's Known Exploited Vulnerabilities (KEV) list. Output is a ranking; the top 500 is the submission. |
| **Intended use** | Deciding what to patch first. Explaining why each CVE is ranked where it is. |
| **Not for** | Proving a CVE *is* exploited, or replacing your own exposure and asset context. A low rank does not mean safe. |
| **Model** | L2-regularised logistic regression (C = 0.05, balanced class weights), with median imputation and scaling, over 25 features. A 20-per-vendor cap is applied to the top 500. |
| **Training data (2026 model)** | Rolling monthly pools for 2024-01 to 2025-10: every CVE up to 24 months old, labelled "joins KEV within 4 months". Negatives are subsampled at 15% and re-weighted. 226,504 rows, 368 positive. Everything comes from knowledge up to 2025-12-31. |
| **Inputs** | EPSS and exploit-code flags at the snapshot month; a TF-IDF text model of descriptions since 2015; description keywords (auth bypass, RCE, edge device, XSS, DoS, WordPress plugin…); the reporter's past KEV rate; vendor and product KEV history counted only up to the snapshot; CVSS 4 from the reporter; age; similarity to already-listed KEV entries. Full list and reasons: `COLUMNS_USED.md`. |
| **Excluded on purpose** | `nvd_status`, CPE / product lists, reference links, CVSS 3 (both sources), CWE, last-modified. These leak the answer (see the leak test in `verify.py`). |
| **Evaluation** | Walk-forward: train 2024 → test Jan–Sep 2025 (35,280 CVEs, 52 later exploited), judged at the top 243 (same share as the benchmark's top 500 of 72,670). Ours 18, exploit-code-first 14, EPSS-first 8, CVSS-first 8. Top 500: 22 vs 18. Ahead in 91% of bootstrap resamples, never behind in any month, ahead in 3 of 4 out-of-time windows. |
| **Explanations** | Each "why" is the CVE's largest feature contributions (coefficient × scaled value). IBM Granite 4 (3B) writes a two-sentence explanation from those facts. A validator blocks claims of exploitation and invented numbers. Granite never affects the rank. |
| **Known limitations** | Few positives, so results are noisy. KEV only counts confirmed exploitation. Vendor names are matched from description text, and 15 top-500 CVEs name no vendor. Descriptions can be edited after publication (checked: none of the exploitation mentions is dated after its snapshot). |
| **Reading the weights** | Features overlap (e.g. vendor vs product KEV history, keywords vs the text model), so a single coefficient's sign is not a standalone finding. Use `DATATHON_ANALYSIS_FINDINGS.md` for the plain rates behind each signal. |
| **Fairness to vendors** | Vendors with a long KEV history score higher. That reflects attacker behaviour, not product quality, and it can lag behind vendors that improve. |
| **Reproduce** | `python run_all.py`, then `python pipeline/verify.py` (0 FAIL expected). Re-scoring gives an identical top 500. |
