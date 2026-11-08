# Legacy (v1): kept for reference, not used for the submission

These files are the project's first version. They are **not** used to produce `top500.csv`.

| File | What it was | Why it was retired |
|---|---|---|
| `Granite_CVE_Analyzer/` | v1 scoring (Composite Threat Index + "Attack Matrix Size") and Granite summaries | AMS was built on `affected_products.csv`, and CVSS came from NIST. Both leak the answer for 2026 CVEs (see `../COLUMNS_USED.md`). Its Granite summaries could claim "actively exploited", which was untrue by construction |
| `csv_compare_agent/` | CSV schema/diff agent with a fixed 0.6x pre-v4 EPSS discount | The discount was a guess. v2 uses within-month EPSS percentiles and lets the model learn the weights |
| `demo_compare.py` | Demo for the agent above | Same |
| `generate_dashboard.py`, `dashboard.html` | v1 dashboard | Showed the leaky v1 scores and an `nvd_status`-based section. Replaced by the v2 dashboard |
| `DATATHON_ANALYSIS_FINDINGS_v1.md` | v1 findings | Numbers came from the leaky v1 score |

The v1 top 500 is at `../results/legacy_top500_v1_leaky.csv`.
