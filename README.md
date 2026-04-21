# How Good Is EPSS, Really? A Five-Year Empirical Evaluation

Analysis scripts and data for the paper:

> [Author]. *How Good Is EPSS, Really? A Five-Year Empirical 
> Evaluation Correcting for Look-Ahead Bias.* Submitted 2026.

## Quick start

pip install requests pandas openpyxl scikit-learn matplotlib pyarrow tqdm
python run_full_v6_corrected.py

## What it does

Pulls 5 years of CVE data (2021-2025), retrieves time-matched 
historical EPSS scores, applies a 12-month fixed observation window, 
and computes MCC / efficiency / coverage metrics with look-ahead 
bias quantification and multi-source weaponisation validation.

Runtime: 2-4 hours (mostly EPSS API calls). Idempotent with 
checkpoints in ./checkpoints_v6/.

## Data sources

All public, no cost:
- NVD (NIST): CVE records and CVSS scores
- FIRST: EPSS historical and current scores
- CISA: Known Exploited Vulnerabilities catalog
- GitHub: Nuclei templates, PoC-in-GitHub, Metasploit modules

## Outputs

- multiyear_results_v6_corrected.xlsx (main 5-year results)
- threshold_sensitivity_v6_corrected.xlsx
- lookahead_bias_v6_corrected.xlsx
- exploit_validation_v6_corrected.xlsx
- mcc_trajectory_corrected.png
- cve_full_dataset_v6.parquet (full per-CVE replication dataset)

## License

MIT. Data sources subject to their respective provider terms.

## Contact

Stephin Paul
Desh Bhagat University, Punjab, India
ORCID: 0009-0004-1378-0664