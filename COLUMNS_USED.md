# Columns used and why

The brief warns that the NIST files are *today's* versions. NIST analyses exploited CVEs first, so several columns quietly reveal the answer. Every column our ranking uses is listed below. Anything not listed is not used. `python pipeline/verify.py` checks this automatically.

## Used

| File | Column | How it's used | Why it's safe |
|---|---|---|---|
| `scoreboard_2026.csv` / `exploit_signals_*.csv` | `epss` | log EPSS, plus a "no EPSS yet" flag | Value at the end of the snapshot month |
| same | `exploitdb`, `metasploit`, `nuclei`, `poc_github` | each flag, plus "any public exploit code" | Value at the end of the snapshot month |
| same | `snapshot_month`, `published` | age of the CVE at the snapshot | Known at publication |
| `vulnerabilities.csv` | `description` | (1) Text model (TF-IDF + logistic regression) trained on 2015+ CVEs with KEV as the label, using only KEV entries known by the cutoff. (2) Keyword flags: authentication bypass, edge device, RCE, command injection, DoS, XSS, WordPress plugin, remote/local, needs an account, needs a user click. (3) Matching vendor and product names against KEV. | Every CVE has a description from publication, including the 51k that NIST never analysed |
| `vulnerabilities.csv` | `assigner` | Smoothed historical KEV rate per reporting organisation, plus a token in the text model | Known at publication |
| `vulnerabilities.csv` | `cvss4_score` | as-is | Only reporting organisations supply CVSS 4. NIST does not add it |
| `known_exploited.csv` | `vendor`, `product`, `date_added`, `known_ransomware_use` | Vendor/product KEV history counted **only with `date_added` on or before the snapshot**. Also the training labels. | Strictly point in time. The 2026 scoring uses only the KEV list as of 2025-12-31 |

## Not used (and the evidence)

| Column | Why it was dropped |
|---|---|
| `nvd_status` | In the 2025 test season, 100% of later-exploited CVEs are `Analyzed`/`Modified` vs 65% of the rest (verify.py leak test) |
| `n_affected_cpes`, all of `affected_products.csv` | Product lists are added when NIST analyses a CVE, so they reveal the same thing. Our old "Attack Matrix Size" score was built on this, so it was removed |
| `n_references`, all of `references.csv` | News and threat-report links are added after attacks |
| `cvss3_*` (score, vector, components) | Whether the score comes from the reporting organisation or NIST depends on NIST analysis. 54% of later-exploited CVEs had a NIST score vs 37% of the rest. Blanking only NIST's scores turns "missing" into a leak, so we dropped CVSS 3 entirely (the strict option). It is used only for the "Highest CVSS first" **baseline** |
| `cwe_ids` | It can't be told apart from what NIST filled in later. We read the weakness type from the description keywords instead |
| `last_modified` | Always mid-2026 or later |

## Known residual risk
- **Descriptions can be edited after publication.** 36 scoreboard descriptions mention real-world exploitation (e.g. "as exploited in the wild in August 2026"). We checked every one: **none cites a date after the CVE's snapshot month**. They are dated at or before publication, i.e. written by MITRE or the vendor when the CVE was assigned. `verify.py` re-checks this on every run. We also tested hiding these claims from the model (`MASK_CLAIMS=1`): the 2025 backtest fell from 18 to 16, because such at-publication statements are a genuine early warning. So they stay.
- **Vendor names come from the first ~100 characters of the description** (where the affected product is named) to avoid incidental matches such as "…via sudo".
- `weakness_types.csv` is not used by the model. It is used only to label CWE names in the dashboard.
