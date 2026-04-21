"""
FULL 5-YEAR EMPIRICAL ANALYSIS (v6)
====================================
Single-script run for the reframed paper:
  - 5-year cohort (2021-2025)
  - Time-matched historical EPSS at 30 days post-publication for each CVE
  - Option B observation window: only CVEs with full 12-month observation period
    counted in "exploited" denominator (so cross-cohort metrics are comparable)
  - Multi-source weaponization validation (Nuclei + PoC-in-GitHub + Metasploit)
    across ALL years, not just 2023
  - Look-ahead bias quantification (current vs historical EPSS)
  - Threshold sensitivity sweep (10 EPSS thresholds, 0.01 to 0.50)
  - Per-cohort MCC trajectory

Designed for reproducibility:
  - Idempotent: each phase saves a checkpoint .pkl/.json file. Re-running the
    script picks up from the last completed checkpoint.
  - Self-contained: pip install requirements, then python run_full_v6.py
  - Estimated runtime: 3-5 hours wall-clock (most of it in Phase 3 EPSS pull)

Outputs:
  - multiyear_results_v6.xlsx       (main 5-year cohort table + per-year details)
  - exploit_validation_v6.xlsx      (multi-source validation per year)
  - lookahead_bias_v6.xlsx          (current vs historical EPSS impact)
  - threshold_sensitivity_v6.xlsx   (threshold sweep)
  - mcc_trajectory.png              (5-year MCC chart)
  - cve_full_dataset_v6.parquet     (the full per-CVE dataset for replication)

USAGE:
    pip install requests pandas openpyxl scikit-learn matplotlib pyarrow tqdm
    python run_full_v6.py

If interrupted, just re-run; checkpoints will resume.
"""

import os
import sys
import json
import time
import gzip
import pickle
import re
from datetime import datetime, timezone, timedelta
from pathlib import Path

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import pandas as pd
from sklearn.metrics import matthews_corrcoef
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from tqdm import tqdm

# =============================================================================
# CONFIGURATION
# =============================================================================
NVD_API_KEY = "ae8a783b-231d-4e54-b1ba-d2d80294ce0f"

YEARS = [2021, 2022, 2023, 2024, 2025]
EPSS_THRESHOLD_MAIN = 0.10
CVSS_HIGH_THRESHOLD = 7.0

# Observation window for Option B: only count exploitation evidence within
# this many months of CVE publication. CVEs whose 12-month observation window
# extends past today are EXCLUDED from the exploited-denominator analysis to
# keep cross-cohort metrics apples-to-apples.
OBSERVATION_WINDOW_DAYS = 365

# Today's date for observation cutoff calculation
TODAY = datetime(2026, 4, 16, tzinfo=timezone.utc)

# Threshold sweep values
THRESHOLD_SWEEP = [0.01, 0.02, 0.05, 0.075, 0.10, 0.15, 0.20, 0.25, 0.35, 0.50]

CHECKPOINT_DIR = Path("./checkpoints_v6")
CHECKPOINT_DIR.mkdir(exist_ok=True)

OUT_MAIN = "multiyear_results_v6.xlsx"
OUT_EXPLOIT = "exploit_validation_v6.xlsx"
OUT_BIAS = "lookahead_bias_v6.xlsx"
OUT_THRESHOLD = "threshold_sensitivity_v6.xlsx"
OUT_DATASET = "cve_full_dataset_v6.parquet"
OUT_CHART = "mcc_trajectory.png"

USER_AGENT = "research-script/v6"

# =============================================================================
# HELPERS
# =============================================================================
def ck_path(name):
    return CHECKPOINT_DIR / name

def save_ck(name, obj):
    with open(ck_path(name), "wb") as f:
        pickle.dump(obj, f)

def load_ck(name):
    p = ck_path(name)
    if p.exists():
        with open(p, "rb") as f:
            return pickle.load(f)
    return None

def http_get(url, headers=None, params=None, timeout=60, max_retries=5):
    """GET with exponential backoff on 429/5xx."""
    h = {"User-Agent": USER_AGENT}
    if headers:
        h.update(headers)
    backoff = 2.0
    for attempt in range(max_retries):
        try:
            r = requests.get(url, headers=h, params=params, timeout=timeout, verify=False)
            if r.status_code == 200:
                return r
            if r.status_code in (429, 502, 503, 504):
                wait = backoff ** (attempt + 1)
                print(f"    [{r.status_code}] backoff {wait:.1f}s on {url[:80]}")
                time.sleep(wait)
                continue
            return r  # Other status codes returned as-is
        except requests.exceptions.RequestException as e:
            wait = backoff ** (attempt + 1)
            print(f"    [exception {type(e).__name__}] backoff {wait:.1f}s on {url[:80]}")
            time.sleep(wait)
    return None


# =============================================================================
# PHASE 1: NVD CVE PULL (per year)
# =============================================================================
def pull_nvd_year(year):
    """Pull all CVEs published in a given year from NVD API 2.0."""
    ck_file = f"nvd_{year}.pkl"
    cached = load_ck(ck_file)
    if cached is not None:
        print(f"  [Phase 1] Year {year}: loaded {len(cached)} CVEs from checkpoint")
        return cached

    print(f"  [Phase 1] Year {year}: fetching from NVD API")
    cves = []
    headers = {"apiKey": NVD_API_KEY}

    # NVD API caps at 120-day windows. Iterate per quarter.
    quarters = [
        (f"{year}-01-01T00:00:00.000", f"{year}-03-31T23:59:59.999"),
        (f"{year}-04-01T00:00:00.000", f"{year}-06-30T23:59:59.999"),
        (f"{year}-07-01T00:00:00.000", f"{year}-09-30T23:59:59.999"),
        (f"{year}-10-01T00:00:00.000", f"{year}-12-31T23:59:59.999"),
    ]

    for q_start, q_end in quarters:
        start_idx = 0
        page_size = 2000
        while True:
            params = {
                "pubStartDate": q_start,
                "pubEndDate": q_end,
                "resultsPerPage": page_size,
                "startIndex": start_idx,
            }
            r = http_get(
                "https://services.nvd.nist.gov/rest/json/cves/2.0",
                headers=headers,
                params=params,
                timeout=120,
            )
            if r is None or r.status_code != 200:
                print(f"    Failed page at startIndex {start_idx} for {q_start[:10]}: status {r.status_code if r else 'none'}")
                time.sleep(10)
                continue

            data = r.json()
            vulns = data.get("vulnerabilities", [])
            for v in vulns:
                c = v.get("cve", {})
                cve_id = c.get("id")
                published = c.get("published")
                if not cve_id or not published:
                    continue

                # Extract CVSS - prefer v3.1 > v3.0 > v2.0
                cvss_score = None
                cvss_severity = None
                cvss_version = None
                metrics = c.get("metrics", {})
                for key in ("cvssMetricV31", "cvssMetricV30"):
                    if key in metrics and metrics[key]:
                        m0 = metrics[key][0]
                        cvss_score = m0.get("cvssData", {}).get("baseScore")
                        cvss_severity = m0.get("cvssData", {}).get("baseSeverity")
                        cvss_version = m0.get("cvssData", {}).get("version")
                        break
                if cvss_score is None and "cvssMetricV2" in metrics and metrics["cvssMetricV2"]:
                    m0 = metrics["cvssMetricV2"][0]
                    cvss_score = m0.get("cvssData", {}).get("baseScore")
                    cvss_severity = m0.get("baseSeverity")
                    cvss_version = "2.0"

                cves.append({
                    "cve_id": cve_id,
                    "published": published,
                    "cvss_score": cvss_score,
                    "cvss_severity": cvss_severity,
                    "cvss_version": cvss_version,
                    "year": year,
                })

            total = data.get("totalResults", 0)
            start_idx += page_size
            print(f"    {q_start[:10]}: {start_idx}/{total} ({len(cves)} cumulative)", end="\r")
            if start_idx >= total:
                break
            time.sleep(0.6)  # NVD API key allows 50 req / 30 sec
        print()

    print(f"  [Phase 1] Year {year}: {len(cves)} CVEs total")
    save_ck(ck_file, cves)
    return cves


def phase1_nvd_pull():
    print("\n" + "=" * 70)
    print("  PHASE 1: NVD CVE pull (5 years)")
    print("=" * 70)
    all_cves = []
    for year in YEARS:
        all_cves.extend(pull_nvd_year(year))
    return pd.DataFrame(all_cves)


# =============================================================================
# PHASE 2: KEV CATALOG (with date-added)
# =============================================================================
def phase2_kev():
    print("\n" + "=" * 70)
    print("  PHASE 2: CISA KEV catalog")
    print("=" * 70)

    ck_file = "kev.pkl"
    cached = load_ck(ck_file)
    if cached is not None:
        print(f"  Loaded {len(cached)} KEV entries from checkpoint")
        return cached

    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    r = http_get(url, timeout=60)
    if r is None or r.status_code != 200:
        raise RuntimeError(f"KEV fetch failed: {r.status_code if r else 'no response'}")

    data = r.json()
    rows = []
    for v in data.get("vulnerabilities", []):
        rows.append({
            "cve_id": v.get("cveID"),
            "kev_date_added": v.get("dateAdded"),
            "kev_vendor": v.get("vendorProject"),
            "kev_product": v.get("product"),
            "kev_due_date": v.get("dueDate"),
        })
    df = pd.DataFrame(rows)
    print(f"  KEV entries: {len(df)}")
    save_ck(ck_file, df)
    return df


# =============================================================================
# PHASE 3: HISTORICAL EPSS (time-matched, 30 days post-pub per CVE)
# =============================================================================
def pull_epss_for_cve(cve_id, target_date):
    """
    Pull EPSS score for a CVE on a specific historical date.
    target_date: date object or 'YYYY-MM-DD' string
    Returns (epss, percentile) or (None, None) if not available.
    """
    if isinstance(target_date, datetime):
        date_str = target_date.strftime("%Y-%m-%d")
    elif isinstance(target_date, str):
        date_str = target_date[:10]
    else:
        date_str = str(target_date)

    url = "https://api.first.org/data/v1/epss"
    params = {"cve": cve_id, "date": date_str}
    r = http_get(url, params=params, timeout=30, max_retries=3)
    if r is None or r.status_code != 200:
        return None, None
    data = r.json().get("data", [])
    if not data:
        return None, None
    return float(data[0].get("epss", 0)), float(data[0].get("percentile", 0))


def pull_epss_batch(cve_list, date_str):
    """
    Pull EPSS scores for a batch of CVEs on a specific historical date.
    The FIRST.org API accepts comma-separated CVEs with ?date= param.
    Max ~100 CVEs per request to keep URL length reasonable.
    Returns dict: cve_id -> (epss, percentile)
    """
    results = {}
    batch_size = 100
    for i in range(0, len(cve_list), batch_size):
        batch = cve_list[i:i + batch_size]
        url = "https://api.first.org/data/v1/epss"
        params = {"cve": ",".join(batch), "date": date_str}
        r = http_get(url, params=params, timeout=60, max_retries=5)
        if r is not None and r.status_code == 200:
            data = r.json().get("data", [])
            for item in data:
                cve_id = item.get("cve", "").upper()
                epss = float(item.get("epss", 0))
                pct = float(item.get("percentile", 0))
                results[cve_id] = (epss, pct)
        time.sleep(0.3)
    return results


def phase3_historical_epss(cve_df):
    """
    For each CVE, fetch historical EPSS at exactly 30 days after publication.
    Uses the FIRST.org API with batched CVE queries per date (up to 100 CVEs
    per request). This is much faster than downloading full bulk feeds.
    """
    print("\n" + "=" * 70)
    print("  PHASE 3: Historical EPSS pull (time-matched)")
    print("=" * 70)

    ck_file = "historical_epss.pkl"
    cached = load_ck(ck_file)
    if cached is not None:
        print(f"  Loaded {len(cached)} historical EPSS entries from checkpoint")
        return cached

    # Load partial checkpoint if exists
    partial_file = ck_file + ".partial"
    epss_results = load_ck(partial_file) or {}
    if epss_results:
        print(f"  Resuming from partial checkpoint: {len(epss_results)} CVEs already scored")

    # Compute target date per CVE: published + 30 days
    cve_df = cve_df.copy()
    cve_df["pub_dt"] = pd.to_datetime(cve_df["published"], utc=True, errors="coerce")
    cve_df = cve_df[cve_df["pub_dt"].notna()].copy()
    cve_df["target_date"] = (cve_df["pub_dt"] + pd.Timedelta(days=30)).dt.strftime("%Y-%m-%d")

    # Filter out CVEs already in partial checkpoint
    if epss_results:
        cve_df = cve_df[~cve_df["cve_id"].isin(epss_results)].copy()

    # Group CVEs by target_date
    epss_min_date = "2021-04-14"  # EPSS v1 went public April 2021

    grouped = cve_df.groupby("target_date")
    unique_dates = sorted(grouped.groups.keys())
    print(f"  CVEs remaining: {len(cve_df)} across {len(unique_dates)} unique target dates")

    dates_processed = 0
    progress = tqdm(unique_dates, desc="EPSS batch dates")
    for target_date in progress:
        cves_for_date = grouped.get_group(target_date)["cve_id"].tolist()

        # Skip if before EPSS public availability
        if target_date < epss_min_date:
            for cve in cves_for_date:
                epss_results[cve] = (None, None, target_date)
            continue

        # Use batched API call (100 CVEs per request)
        batch_results = pull_epss_batch(cves_for_date, target_date)
        for cve in cves_for_date:
            if cve.upper() in batch_results:
                e, p = batch_results[cve.upper()]
                epss_results[cve] = (float(e), float(p), target_date)
            else:
                epss_results[cve] = (None, None, target_date)

        dates_processed += 1
        # Save partial checkpoint every 100 dates
        if dates_processed % 100 == 0:
            save_ck(partial_file, epss_results)
            progress.set_postfix(saved=len(epss_results))

    save_ck(ck_file, epss_results)
    print(f"  Historical EPSS captured for {sum(1 for v in epss_results.values() if v[0] is not None)} of {len(epss_results)} CVEs")
    return epss_results


# =============================================================================
# PHASE 4: CURRENT EPSS (for look-ahead bias quantification)
# =============================================================================
def phase4_current_epss(cve_ids):
    print("\n" + "=" * 70)
    print("  PHASE 4: Current EPSS (for look-ahead bias)")
    print("=" * 70)

    ck_file = "current_epss.pkl"
    cached = load_ck(ck_file)
    if cached is not None:
        print(f"  Loaded {len(cached)} current EPSS entries from checkpoint")
        return cached

    # Use today's bulk feed
    today_str = TODAY.strftime("%Y-%m-%d")
    bulk_url = f"https://epss.cyentia.com/epss_scores-{today_str}.csv.gz"
    print(f"  Fetching bulk feed for {today_str}...")
    r = http_get(bulk_url, timeout=180, max_retries=5)

    if r is None or r.status_code != 200:
        # Try yesterday's
        yesterday = (TODAY - timedelta(days=1)).strftime("%Y-%m-%d")
        bulk_url = f"https://epss.cyentia.com/epss_scores-{yesterday}.csv.gz"
        print(f"  Today's feed not available, trying {yesterday}...")
        r = http_get(bulk_url, timeout=180, max_retries=5)

    if r is None or r.status_code != 200:
        raise RuntimeError("Could not fetch current EPSS bulk feed")

    from io import BytesIO
    bf = BytesIO(r.content)
    bulk_df = pd.read_csv(bf, compression="gzip", comment="#")
    bulk_dict = dict(zip(bulk_df["cve"].str.upper(), zip(bulk_df["epss"], bulk_df["percentile"])))

    current = {}
    for cve in cve_ids:
        if cve.upper() in bulk_dict:
            e, p = bulk_dict[cve.upper()]
            current[cve] = (float(e), float(p))
        else:
            current[cve] = (None, None)

    print(f"  Current EPSS captured for {sum(1 for v in current.values() if v[0] is not None)} of {len(cve_ids)} CVEs")
    save_ck(ck_file, current)
    return current


# =============================================================================
# PHASE 5: BUILD MASTER DATASET WITH OPTION B OBSERVATION WINDOW
# =============================================================================
def phase5_build_master(cve_df, kev_df, hist_epss, curr_epss):
    print("\n" + "=" * 70)
    print("  PHASE 5: Build master dataset with Option B observation window")
    print("=" * 70)

    df = cve_df.copy()
    df["pub_dt"] = pd.to_datetime(df["published"], utc=True, errors="coerce")
    df = df[df["pub_dt"].notna()].copy()

    # Merge KEV
    kev = kev_df.copy()
    kev["kev_dt"] = pd.to_datetime(kev["kev_date_added"], utc=True, errors="coerce")
    df = df.merge(kev[["cve_id", "kev_dt"]], on="cve_id", how="left")
    df["on_kev"] = df["kev_dt"].notna()

    # Merge historical EPSS
    df["hist_epss"] = df["cve_id"].map(lambda c: hist_epss.get(c, (None, None, None))[0])
    df["hist_pct"] = df["cve_id"].map(lambda c: hist_epss.get(c, (None, None, None))[1])

    # Merge current EPSS
    df["curr_epss"] = df["cve_id"].map(lambda c: curr_epss.get(c, (None, None))[0])
    df["curr_pct"] = df["cve_id"].map(lambda c: curr_epss.get(c, (None, None))[1])

    # Option B observation window:
    # observation_end = min(pub_dt + 365 days, TODAY)
    # If pub_dt + 365 days > TODAY, we cannot fully observe this CVE (excluded).
    df["obs_window_end"] = df["pub_dt"] + pd.Timedelta(days=OBSERVATION_WINDOW_DAYS)
    df["fully_observed"] = df["obs_window_end"] <= TODAY

    # Exploitation flag under Option B: KEV-listed AND added to KEV within
    # the 12-month observation window of CVE publication.
    # CORRECTED: removed kev_dt >= pub_dt constraint.
    # CVEs added to KEV before NVD publication are definitively exploited.
    df["exploited_in_window"] = (
        df["on_kev"] &
        (df["kev_dt"] <= df["obs_window_end"])
    )

    # Framework Stage 1 (KEV-listed AS OF observation_end) and Stage 2 (EPSS >= threshold using historical)
    df["stage1"] = df["on_kev"] & (df["kev_dt"] <= df["obs_window_end"])
    df["stage2_hist"] = (df["hist_epss"].fillna(0) >= EPSS_THRESHOLD_MAIN) & ~df["stage1"]
    df["stage2_curr"] = (df["curr_epss"].fillna(0) >= EPSS_THRESHOLD_MAIN) & ~df["stage1"]
    df["framework_urgent_hist"] = df["stage1"] | df["stage2_hist"]
    df["framework_urgent_curr"] = df["stage1"] | df["stage2_curr"]

    # CVSS baseline
    df["cvss_urgent"] = df["cvss_score"].fillna(0) >= CVSS_HIGH_THRESHOLD

    # Save full dataset
    df.to_parquet(OUT_DATASET, index=False)
    print(f"  Master dataset saved: {OUT_DATASET}")
    print(f"  Total CVEs: {len(df)}")
    print(f"  Fully observed (12-month window complete): {df['fully_observed'].sum()}")
    print(f"  Exploited within observation window: {df['exploited_in_window'].sum()}")

    return df


# =============================================================================
# PHASE 6: MULTI-SOURCE WEAPONIZATION VALIDATION
# =============================================================================
def download_nuclei_cves():
    print("\n  [6.1] Downloading Nuclei CVE templates...")
    nuclei = set()
    tree_url = "https://api.github.com/repos/projectdiscovery/nuclei-templates/git/trees/main?recursive=1"
    r = http_get(tree_url, headers={"Accept": "application/vnd.github.v3+json"}, timeout=180, max_retries=5)
    if r and r.status_code == 200:
        for item in r.json().get("tree", []):
            path = item.get("path", "")
            m = re.search(r"cves/\d{4}/(CVE-\d{4}-\d+)\.yaml", path, re.IGNORECASE)
            if m:
                nuclei.add(m.group(1).upper())
    print(f"    Nuclei: {len(nuclei)} CVEs")
    return nuclei


def download_pocingithub_cves():
    print("\n  [6.2] Downloading PoC-in-GitHub...")
    poc = set()
    tree_url = "https://api.github.com/repos/nomi-sec/PoC-in-GitHub/git/trees/master?recursive=1"
    r = http_get(tree_url, headers={"Accept": "application/vnd.github.v3+json"}, timeout=180, max_retries=5)
    if r and r.status_code == 200:
        for item in r.json().get("tree", []):
            path = item.get("path", "")
            m = re.search(r"(CVE-\d{4}-\d+)\.json", path, re.IGNORECASE)
            if m:
                poc.add(m.group(1).upper())
    print(f"    PoC-in-GitHub: {len(poc)} CVEs")
    return poc


def download_metasploit_cves():
    print("\n  [6.3] Downloading Metasploit modules metadata...")
    msf = set()
    url = "https://raw.githubusercontent.com/rapid7/metasploit-framework/master/db/modules_metadata_base.json"
    r = http_get(url, timeout=180, max_retries=5)
    if r and r.status_code == 200:
        try:
            data = r.json()
            for mod_name, mod_data in data.items():
                refs = mod_data.get("references", [])
                for ref in refs:
                    if isinstance(ref, str) and ref.upper().startswith("CVE-"):
                        msf.add(ref.strip().upper())
                    elif isinstance(ref, list) and len(ref) >= 2 and str(ref[0]).upper() == "CVE":
                        msf.add(f"CVE-{ref[1]}".upper())
        except Exception as e:
            print(f"    Parse failed: {e}")
    print(f"    Metasploit: {len(msf)} CVEs")
    return msf


def phase6_multisource(master_df):
    print("\n" + "=" * 70)
    print("  PHASE 6: Multi-source weaponization validation")
    print("=" * 70)

    ck_file = "multisource.pkl"
    cached = load_ck(ck_file)
    if cached is not None:
        print(f"  Loaded multisource sets from checkpoint")
        nuclei, poc, msf = cached
    else:
        nuclei = download_nuclei_cves()
        poc = download_pocingithub_cves()
        msf = download_metasploit_cves()
        save_ck(ck_file, (nuclei, poc, msf))

    # Add columns to master
    master_df["in_nuclei"] = master_df["cve_id"].str.upper().isin(nuclei)
    master_df["in_poc_github"] = master_df["cve_id"].str.upper().isin(poc)
    master_df["in_metasploit"] = master_df["cve_id"].str.upper().isin(msf)
    master_df["multisource_count"] = (
        master_df["in_nuclei"].astype(int) +
        master_df["in_poc_github"].astype(int) +
        master_df["in_metasploit"].astype(int)
    )
    master_df["any_source"] = master_df["multisource_count"] > 0

    # Per-year multisource summary
    rows = []
    for year in YEARS:
        yr = master_df[master_df["year"] == year]
        stage2 = yr[yr["stage2_hist"]]
        kev_yr = yr[yr["stage1"]]
        if len(stage2) == 0:
            continue

        rows.append({
            "year": year,
            "stage2_count": len(stage2),
            "kev_count": len(kev_yr),
            "stage2_in_nuclei": stage2["in_nuclei"].sum(),
            "stage2_in_poc": stage2["in_poc_github"].sum(),
            "stage2_in_msf": stage2["in_metasploit"].sum(),
            "stage2_any": stage2["any_source"].sum(),
            "stage2_2plus": (stage2["multisource_count"] >= 2).sum(),
            "stage2_3plus": (stage2["multisource_count"] >= 3).sum(),
            # Lift = (in source for stage2 / |stage2|) / (in source for cohort / |cohort|)
            "nuclei_lift": ((stage2["in_nuclei"].sum() / len(stage2)) /
                            (yr["in_nuclei"].sum() / len(yr))) if yr["in_nuclei"].sum() else None,
            "poc_lift": ((stage2["in_poc_github"].sum() / len(stage2)) /
                         (yr["in_poc_github"].sum() / len(yr))) if yr["in_poc_github"].sum() else None,
            "msf_lift": ((stage2["in_metasploit"].sum() / len(stage2)) /
                         (yr["in_metasploit"].sum() / len(yr))) if yr["in_metasploit"].sum() else None,
        })

    multisource_df = pd.DataFrame(rows)

    # Save per-year details
    with pd.ExcelWriter(OUT_EXPLOIT, engine="openpyxl") as w:
        multisource_df.to_excel(w, sheet_name="Per Year", index=False)
        for year in YEARS:
            yr = master_df[(master_df["year"] == year) & master_df["stage2_hist"]]
            if len(yr) == 0:
                continue
            cols = ["cve_id", "cvss_score", "hist_epss", "in_nuclei", "in_poc_github",
                    "in_metasploit", "multisource_count", "exploited_in_window"]
            yr[cols].to_excel(w, sheet_name=f"Stage2 {year}", index=False)

    print(f"  Saved: {OUT_EXPLOIT}")
    return master_df, multisource_df


# =============================================================================
# PHASE 7: METRICS & THRESHOLD SENSITIVITY
# =============================================================================
def compute_metrics(df_year, threshold=EPSS_THRESHOLD_MAIN):
    """Compute confusion-matrix metrics for one year at one threshold."""
    # Restrict to fully-observed CVEs (Option B)
    df = df_year[df_year["fully_observed"]].copy()
    if len(df) == 0:
        return None

    df["fw_urgent"] = df["stage1"] | (
        (df["hist_epss"].fillna(0) >= threshold) & ~df["stage1"]
    )

    y_true = df["exploited_in_window"].astype(int).values
    y_fw = df["fw_urgent"].astype(int).values
    y_cvss = df["cvss_urgent"].astype(int).values

    total = len(df)
    exploited = int(y_true.sum())

    # Framework
    fw_urgent = int(y_fw.sum())
    fw_caught = int(((y_true == 1) & (y_fw == 1)).sum())
    fw_coverage = (fw_caught / exploited * 100) if exploited else 0
    fw_efficiency = (fw_caught / fw_urgent * 100) if fw_urgent else 0
    fw_reduction = (1 - fw_urgent / total) * 100 if total else 0
    fw_mcc = matthews_corrcoef(y_true, y_fw) if len(set(y_true)) > 1 and len(set(y_fw)) > 1 else 0

    # CVSS
    cvss_urgent = int(y_cvss.sum())
    cvss_caught = int(((y_true == 1) & (y_cvss == 1)).sum())
    cvss_coverage = (cvss_caught / exploited * 100) if exploited else 0
    cvss_efficiency = (cvss_caught / cvss_urgent * 100) if cvss_urgent else 0
    cvss_mcc = matthews_corrcoef(y_true, y_cvss) if len(set(y_true)) > 1 and len(set(y_cvss)) > 1 else 0

    return {
        "threshold": threshold,
        "total_observed": total,
        "exploited": exploited,
        "cvss_urgent": cvss_urgent,
        "cvss_caught": cvss_caught,
        "cvss_coverage": round(cvss_coverage, 2),
        "cvss_efficiency": round(cvss_efficiency, 2),
        "cvss_mcc": round(cvss_mcc, 4),
        "fw_urgent": fw_urgent,
        "fw_caught": fw_caught,
        "fw_coverage": round(fw_coverage, 2),
        "fw_efficiency": round(fw_efficiency, 2),
        "fw_reduction": round(fw_reduction, 2),
        "fw_mcc": round(fw_mcc, 4),
    }


def phase7_metrics(master_df):
    print("\n" + "=" * 70)
    print("  PHASE 7: Metrics + threshold sensitivity")
    print("=" * 70)

    # Per-year main results at threshold 0.10
    main_rows = []
    for year in YEARS:
        yr_df = master_df[master_df["year"] == year]
        m = compute_metrics(yr_df, EPSS_THRESHOLD_MAIN)
        if m is None:
            continue
        m["year"] = year

        # Look-ahead bias: same year, current EPSS
        observed = yr_df[yr_df["fully_observed"]].copy()
        curr_stage2 = ((observed["curr_epss"].fillna(0) >= EPSS_THRESHOLD_MAIN) & ~observed["stage1"]).sum()
        hist_stage2 = ((observed["hist_epss"].fillna(0) >= EPSS_THRESHOLD_MAIN) & ~observed["stage1"]).sum()
        m["stage2_hist"] = int(hist_stage2)
        m["stage2_curr"] = int(curr_stage2)
        m["bias_inflation"] = int(curr_stage2 - hist_stage2)

        main_rows.append(m)

    main_df = pd.DataFrame(main_rows)

    # Threshold sensitivity sweep
    sweep_rows = []
    for year in YEARS:
        yr_df = master_df[master_df["year"] == year]
        for t in THRESHOLD_SWEEP:
            m = compute_metrics(yr_df, t)
            if m is not None:
                m["year"] = year
                sweep_rows.append(m)
    sweep_df = pd.DataFrame(sweep_rows)

    # Look-ahead bias detail
    bias_rows = []
    for year in YEARS:
        yr_df = master_df[(master_df["year"] == year) & master_df["fully_observed"]].copy()
        if len(yr_df) == 0:
            continue
        for t in THRESHOLD_SWEEP:
            yr_df["fw_hist"] = yr_df["stage1"] | (
                (yr_df["hist_epss"].fillna(0) >= t) & ~yr_df["stage1"]
            )
            yr_df["fw_curr"] = yr_df["stage1"] | (
                (yr_df["curr_epss"].fillna(0) >= t) & ~yr_df["stage1"]
            )
            hist_n = int(yr_df["fw_hist"].sum())
            curr_n = int(yr_df["fw_curr"].sum())
            hist_caught = int((yr_df["fw_hist"] & yr_df["exploited_in_window"]).sum())
            curr_caught = int((yr_df["fw_curr"] & yr_df["exploited_in_window"]).sum())
            bias_rows.append({
                "year": year,
                "threshold": t,
                "hist_urgent": hist_n,
                "curr_urgent": curr_n,
                "inflation": curr_n - hist_n,
                "inflation_ratio": round(curr_n / hist_n, 2) if hist_n else None,
                "hist_efficiency": round(hist_caught / hist_n * 100, 2) if hist_n else None,
                "curr_efficiency": round(curr_caught / curr_n * 100, 2) if curr_n else None,
            })
    bias_df = pd.DataFrame(bias_rows)

    # Write outputs
    with pd.ExcelWriter(OUT_MAIN, engine="openpyxl") as w:
        main_df.to_excel(w, sheet_name="Main 5-Year Results", index=False)

    with pd.ExcelWriter(OUT_THRESHOLD, engine="openpyxl") as w:
        sweep_df.to_excel(w, sheet_name="Threshold Sweep", index=False)

    with pd.ExcelWriter(OUT_BIAS, engine="openpyxl") as w:
        bias_df.to_excel(w, sheet_name="Look-Ahead Bias", index=False)

    print(f"  Saved: {OUT_MAIN}, {OUT_THRESHOLD}, {OUT_BIAS}")
    return main_df, sweep_df, bias_df


# =============================================================================
# PHASE 8: MCC TRAJECTORY CHART
# =============================================================================
def phase8_chart(main_df):
    print("\n" + "=" * 70)
    print("  PHASE 8: MCC trajectory chart")
    print("=" * 70)

    fig, ax = plt.subplots(figsize=(8, 5))
    ax.plot(main_df["year"], main_df["fw_mcc"], "o-", linewidth=2, markersize=8, label="Framework (KEV + EPSS @ 0.10)")
    ax.plot(main_df["year"], main_df["cvss_mcc"], "s--", linewidth=2, markersize=8, label="CVSS-only (>= 7.0)", color="gray")
    ax.set_xlabel("CVE Publication Year")
    ax.set_ylabel("Matthews Correlation Coefficient")
    ax.set_title("Five-Year MCC Trajectory: Framework vs CVSS-only Baseline")
    ax.set_ylim(-0.05, 1.0)
    ax.grid(True, alpha=0.3)
    ax.legend()
    for _, r in main_df.iterrows():
        ax.annotate(f"{r['fw_mcc']:.2f}", (r["year"], r["fw_mcc"]),
                    textcoords="offset points", xytext=(0, 10), ha="center", fontsize=9)
    plt.tight_layout()
    plt.savefig(OUT_CHART, dpi=150)
    plt.close()
    print(f"  Saved: {OUT_CHART}")


# =============================================================================
# MAIN
# =============================================================================
def main():
    t0 = time.time()
    print("Five-Year Vulnerability Prioritization Analysis (v6)")
    print(f"Started: {datetime.now().isoformat()}")
    print(f"Years: {YEARS}")
    print(f"Observation window: {OBSERVATION_WINDOW_DAYS} days")
    print(f"EPSS threshold (main): {EPSS_THRESHOLD_MAIN}")
    print(f"Threshold sweep: {THRESHOLD_SWEEP}")
    print(f"Today (cutoff): {TODAY.isoformat()}")

    cve_df = phase1_nvd_pull()
    print(f"\n  Total CVEs collected: {len(cve_df)}")

    kev_df = phase2_kev()
    hist_epss = phase3_historical_epss(cve_df)
    curr_epss = phase4_current_epss(cve_df["cve_id"].tolist())
    master_df = phase5_build_master(cve_df, kev_df, hist_epss, curr_epss)
    master_df, ms_df = phase6_multisource(master_df)
    main_df, sweep_df, bias_df = phase7_metrics(master_df)
    phase8_chart(main_df)

    elapsed = time.time() - t0
    print("\n" + "=" * 70)
    print(f"  COMPLETE in {elapsed/60:.1f} minutes")
    print("=" * 70)
    print("\n  Files produced:")
    for f in [OUT_MAIN, OUT_EXPLOIT, OUT_BIAS, OUT_THRESHOLD, OUT_DATASET, OUT_CHART]:
        if os.path.exists(f):
            print(f"    {f}  ({os.path.getsize(f)/1024:.1f} KB)")

    print("\n  KEY RESULTS:")
    print(main_df[["year", "total_observed", "exploited", "stage2_hist", "fw_efficiency",
                   "fw_reduction", "fw_mcc", "cvss_mcc", "bias_inflation"]].to_string(index=False))


if __name__ == "__main__":
    main()
