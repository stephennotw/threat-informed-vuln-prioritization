"""
THREAT-INFORMED VULNERABILITY PRIORITIZATION — RETROSPECTIVE ANALYSIS v5
=========================================================================
CHANGES FROM v4:
  - Uses time-matched historical EPSS scores (30 days after CVE publication)
    via the FIRST EPSS API historical endpoint, eliminating look-ahead bias
  - Cross-validates EPSS-elevated CVEs against ExploitDB for independent
    evidence of exploit availability
  - Decomposes results into Stage 1 (KEV) and Stage 2 (EPSS) independently
  - Performs a Stage 3 sample: checks ATT&CK mappings for a subset of
    EPSS-elevated CVEs using MITRE CTID data
  - Reports both current-day and historical EPSS results for comparison

HOW TO USE:
    pip install requests pandas openpyxl
    python run_analysis_v5.py

Takes about 10-20 minutes (historical EPSS requires per-date API calls).
"""

import requests
import pandas as pd
import json
import lzma
import sys
import time
from datetime import datetime, timedelta
from collections import defaultdict

ANALYSIS_YEAR = 2023
EPSS_THRESHOLD = 0.10
CVSS_HIGH_THRESHOLD = 7.0
OUTPUT_FILE = "analysis_results_v5.xlsx"
EPSS_OFFSET_DAYS = 30  # Pull EPSS score this many days after CVE publication
STAGE3_SAMPLE_SIZE = 30  # Number of EPSS-elevated CVEs to check for ATT&CK mappings


def download_kev():
    print("\n[1/5] Downloading CISA KEV catalog...")
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    try:
        r = requests.get(url, timeout=60)
        r.raise_for_status()
        vulns = r.json().get("vulnerabilities", [])
        kev_ids = set(v.get("cveID", "").strip().upper() for v in vulns if v.get("cveID"))
        # Also capture dateAdded for each KEV entry
        kev_dates = {}
        for v in vulns:
            cve_id = v.get("cveID", "").strip().upper()
            date_added = v.get("dateAdded", "")
            if cve_id and date_added:
                kev_dates[cve_id] = date_added
        print(f"      Got {len(kev_ids)} KEV entries.")
        return kev_ids, kev_dates
    except Exception as e:
        print(f"      ERROR: {e}")
        sys.exit(1)


def download_epss_current():
    """Download current-day EPSS scores (for comparison with historical)."""
    print("\n[2/5] Downloading current EPSS scores...")
    url = "https://epss.cyentia.com/epss_scores-current.csv.gz"
    try:
        df = pd.read_csv(url, compression="gzip", comment="#")
        df.columns = [c.strip() for c in df.columns]
        df = df.rename(columns={"cve": "cve_id", "epss": "epss_score_current"})
        df["epss_score_current"] = pd.to_numeric(df["epss_score_current"], errors="coerce")
        df["cve_id"] = df["cve_id"].str.strip().str.upper()
        print(f"      Got current EPSS scores for {len(df)} CVEs.")
        return df[["cve_id", "epss_score_current"]].set_index("cve_id")
    except Exception as e:
        print(f"      ERROR: {e}")
        sys.exit(1)


def download_epss_historical(cve_dates_dict):
    """
    Download time-matched historical EPSS scores.
    For each CVE, pull the EPSS score from EPSS_OFFSET_DAYS after publication.
    Uses the FIRST EPSS API: GET https://api.first.org/data/v1/epss?cve=CVE-...&date=YYYY-MM-DD

    To avoid excessive API calls, we batch by date (group CVEs by their
    target lookup date) and use the bulk date endpoint.
    """
    print(f"\n[3/5] Downloading historical EPSS scores ({EPSS_OFFSET_DAYS} days after publication)...")
    print(f"      This may take 10-15 minutes due to API rate limits.")

    # Group CVEs by their target EPSS lookup date
    date_to_cves = defaultdict(list)
    for cve_id, pub_date_str in cve_dates_dict.items():
        try:
            pub_date = datetime.strptime(pub_date_str[:10], "%Y-%m-%d")
            target_date = pub_date + timedelta(days=EPSS_OFFSET_DAYS)
            # EPSS data starts from 2022-02-04; clamp if needed
            earliest = datetime(2022, 2, 4)
            if target_date < earliest:
                target_date = earliest
            # Don't request future dates
            if target_date > datetime.now():
                target_date = datetime.now() - timedelta(days=1)
            date_str = target_date.strftime("%Y-%m-%d")
            date_to_cves[date_str].append(cve_id)
        except (ValueError, TypeError):
            continue

    print(f"      {len(cve_dates_dict)} CVEs grouped into {len(date_to_cves)} unique dates.")

    results = {}
    dates_processed = 0
    total_dates = len(date_to_cves)

    for date_str, cves in sorted(date_to_cves.items()):
        dates_processed += 1
        # FIRST EPSS API allows bulk CVE queries per date
        # Process in batches of 100 CVEs per request
        for batch_start in range(0, len(cves), 100):
            batch = cves[batch_start:batch_start + 100]
            cve_param = ",".join(batch)
            url = f"https://api.first.org/data/v1/epss?cve={cve_param}&date={date_str}"

            success = False
            for attempt in range(3):
                try:
                    r = requests.get(url, timeout=60)
                    if r.status_code == 429:
                        wait = 10 + attempt * 10
                        print(f"      Rate limited. Waiting {wait}s...")
                        time.sleep(wait)
                        continue
                    r.raise_for_status()
                    data = r.json()
                    for entry in data.get("data", []):
                        cve_id = entry.get("cve", "").strip().upper()
                        epss = entry.get("epss")
                        if cve_id and epss is not None:
                            results[cve_id] = float(epss)
                    success = True
                    break
                except Exception as e:
                    if attempt < 2:
                        time.sleep(5)
                    else:
                        print(f"      Warning: Failed for date {date_str} batch: {e}")

        if dates_processed % 20 == 0 or dates_processed == total_dates:
            print(f"      Progress: {dates_processed}/{total_dates} dates, {len(results)} scores collected...")

        # Rate limit: ~1 request per second
        time.sleep(1.0)

    print(f"      Done: historical EPSS scores for {len(results)} CVEs.")

    df = pd.DataFrame([
        {"cve_id": k, "epss_score_historical": v}
        for k, v in results.items()
    ])
    if len(df) == 0:
        print("      WARNING: No historical EPSS scores retrieved.")
        return pd.DataFrame(columns=["cve_id", "epss_score_historical"]).set_index("cve_id")
    return df.set_index("cve_id")


def extract_cvss_from_item(item):
    """Extract a CVSS base score from a single CVE item."""
    cve_obj = item.get("cve", item)
    metrics = cve_obj.get("metrics", {})
    for key in ["cvssMetricV31", "cvssMetricV30"]:
        if key in metrics and len(metrics[key]) > 0:
            score = metrics[key][0].get("cvssData", {}).get("baseScore")
            if score is not None:
                return score
    if "cvssMetricV2" in metrics and len(metrics["cvssMetricV2"]) > 0:
        score = metrics["cvssMetricV2"][0].get("cvssData", {}).get("baseScore")
        if score is not None:
            return score
    impact = item.get("impact", {})
    if "baseMetricV3" in impact:
        score = impact["baseMetricV3"].get("cvssV3", {}).get("baseScore")
        if score is not None:
            return score
    if "baseMetricV2" in impact:
        score = impact["baseMetricV2"].get("cvssV2", {}).get("baseScore")
        if score is not None:
            return score
    for key in ["baseScore", "cvss_score", "base_score", "score"]:
        if key in item:
            return item[key]
        if key in cve_obj:
            return cve_obj[key]
    return None


def extract_cve_id(item):
    """Extract CVE ID from a single item."""
    cve_obj = item.get("cve", {})
    if isinstance(cve_obj, dict):
        cve_id = cve_obj.get("id", "")
        if cve_id:
            return cve_id.strip().upper()
        meta = cve_obj.get("CVE_data_meta", {})
        cve_id = meta.get("ID", "")
        if cve_id:
            return cve_id.strip().upper()
    for key in ["id", "cveID", "cve_id", "ID", "cveId"]:
        cve_id = item.get(key, "")
        if isinstance(cve_id, str) and cve_id.upper().startswith("CVE-"):
            return cve_id.strip().upper()
    return None


def extract_pub_date(item):
    """Extract publication date from a CVE item."""
    cve_obj = item.get("cve", item)
    # NVD 2.0 format
    pub = cve_obj.get("published", "")
    if pub:
        return pub[:10]
    # Legacy format
    meta = cve_obj.get("CVE_data_meta", {})
    pub = meta.get("publishedDate", "")
    if pub:
        return pub[:10]
    pub = item.get("publishedDate", "")
    if pub:
        return pub[:10]
    return None


def download_nvd_bulk(year):
    print(f"\n[4/5] Downloading NVD data for {year}...")
    url = f"https://github.com/fkie-cad/nvd-json-data-feeds/releases/latest/download/CVE-{year}.json.xz"
    print(f"      Downloading from GitHub...")

    try:
        r = requests.get(url, timeout=300, stream=True)
        r.raise_for_status()
        total = int(r.headers.get("content-length", 0))
        downloaded = 0
        chunks = []
        for chunk in r.iter_content(chunk_size=1024 * 1024):
            chunks.append(chunk)
            downloaded += len(chunk)
            if total > 0:
                mb = downloaded / 1024 / 1024
                pct = downloaded / total * 100
                print(f"      Downloaded {mb:.1f} MB ({pct:.0f}%)...", end="\r")
        print(f"      Download complete: {downloaded/1024/1024:.1f} MB              ")

        raw = b"".join(chunks)
        print("      Decompressing...")
        try:
            decompressed = lzma.decompress(raw)
        except lzma.LZMAError:
            decompressed = raw

        data = json.loads(decompressed)
        items = None
        if isinstance(data, dict):
            print(f"      JSON keys: {list(data.keys())}")
            for key in ["vulnerabilities", "CVE_Items", "cve_items",
                        "CVE_items", "cveItems", "items", "cves", "results"]:
                if key in data and isinstance(data[key], list):
                    items = data[key]
                    print(f"      Found CVE list under key '{key}': {len(items)} items")
                    break
            if items is None:
                for key, val in data.items():
                    if isinstance(val, list) and len(val) > 100:
                        items = val
                        print(f"      Using key '{key}' as CVE list: {len(items)} items")
                        break
        elif isinstance(data, list):
            items = data
            print(f"      JSON is a list: {len(items)} items")

        if not items:
            print("      ERROR: Could not find CVE list in JSON.")
            print("      Falling back to NVD API...")
            return download_nvd_api(year)

        if len(items) > 0:
            sample = items[0]
            sample_id = extract_cve_id(sample)
            sample_score = extract_cvss_from_item(sample)
            print(f"      Sample: ID={sample_id}, CVSS={sample_score}")

        records = []
        for item in items:
            cve_id = extract_cve_id(item)
            if cve_id:
                cvss_score = extract_cvss_from_item(item)
                pub_date = extract_pub_date(item)
                records.append({
                    "cve_id": cve_id,
                    "cvss_score": cvss_score,
                    "pub_date": pub_date
                })

        if len(records) == 0:
            print("      Parsed 0 records. Falling back to NVD API...")
            return download_nvd_api(year)

        df = pd.DataFrame(records)
        df["cvss_score"] = pd.to_numeric(df["cvss_score"], errors="coerce")
        print(f"      Parsed {len(df)} CVEs, {df['cvss_score'].notna().sum()} with CVSS scores.")
        return df

    except Exception as e:
        print(f"      Bulk download failed: {e}")
        print("      Falling back to NVD API...")
        return download_nvd_api(year)


def download_nvd_api(year):
    print(f"\n      Using NVD API for {year} CVEs...")
    print("      This takes 10-20 min due to rate limits.\n")
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    all_records = []
    start_index = 0
    results_per_page = 2000
    total = None

    while True:
        params = {
            "pubStartDate": f"{year}-01-01T00:00:00.000-00:00",
            "pubEndDate": f"{year}-12-31T23:59:59.999-00:00",
            "startIndex": start_index,
            "resultsPerPage": results_per_page,
        }
        success = False
        for attempt in range(5):
            try:
                r = requests.get(base_url, params=params, timeout=120)
                if r.status_code in (403, 429):
                    wait = 30 + attempt * 15
                    print(f"      Rate limited ({r.status_code}). Waiting {wait}s...")
                    time.sleep(wait)
                    continue
                r.raise_for_status()
                data = r.json()
                success = True
                break
            except Exception as e:
                wait = 15 + attempt * 10
                print(f"      Error: {e}. Retry {attempt+1}/5 in {wait}s...")
                time.sleep(wait)

        if not success:
            if len(all_records) > 0:
                print(f"      Continuing with {len(all_records)} CVEs collected.")
                break
            print("      No data collected. Exiting.")
            sys.exit(1)

        if total is None:
            total = data.get("totalResults", 0)
            print(f"      Total CVEs to download: {total}")

        for item in data.get("vulnerabilities", []):
            cve_id = extract_cve_id(item)
            cvss_score = extract_cvss_from_item(item)
            pub_date = extract_pub_date(item)
            if cve_id:
                all_records.append({
                    "cve_id": cve_id,
                    "cvss_score": cvss_score,
                    "pub_date": pub_date
                })

        start_index += results_per_page
        print(f"      Progress: {len(all_records)}/{total}...")
        if start_index >= total:
            break
        time.sleep(8)

    df = pd.DataFrame(all_records)
    df["cvss_score"] = pd.to_numeric(df["cvss_score"], errors="coerce")
    print(f"      Done: {len(df)} CVEs, {df['cvss_score'].notna().sum()} with CVSS scores.")
    return df


def download_exploitdb_cves():
    """
    Download ExploitDB's files_exploits.csv to get CVE mappings.
    This lets us check which CVEs have public exploit code.
    Falls back to the GitLab mirror if primary source fails.
    """
    print("\n[5/5] Downloading ExploitDB CVE mappings...")
    urls = [
        "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv",
        "https://raw.githubusercontent.com/offensive-security/exploitdb/master/files_exploits.csv",
    ]

    for url in urls:
        try:
            df = pd.read_csv(url, timeout=60)
            # The 'codes' column contains semicolon-separated references including CVE IDs
            cve_set = set()
            if "codes" in df.columns:
                for codes_str in df["codes"].dropna():
                    for code in str(codes_str).split(";"):
                        code = code.strip().upper()
                        if code.startswith("CVE-"):
                            cve_set.add(code)
            print(f"      Got ExploitDB references for {len(cve_set)} unique CVEs.")
            return cve_set
        except Exception as e:
            print(f"      Source failed ({e}), trying next...")

    print("      WARNING: Could not download ExploitDB data. Skipping cross-validation.")
    return set()


def download_attack_cve_mappings():
    """
    Download MITRE CTID CVE-to-ATT&CK mappings for Stage 3 sample analysis.
    Uses the published mapping data from the Center for Threat-Informed Defense.
    """
    print("\n[bonus] Downloading MITRE ATT&CK CVE mappings for Stage 3 sample...")
    # CTID publishes mappings as JSON/STIX; try the enterprise layer CSV
    urls = [
        "https://raw.githubusercontent.com/center-for-threat-informed-defense/attack_to_cve/main/data/cve_attack_mapping.json",
        "https://raw.githubusercontent.com/center-for-threat-informed-defense/attack_to_cve/main/output/cve_attack_mapping.json",
    ]

    mappings = {}  # cve_id -> list of technique IDs

    for url in urls:
        try:
            r = requests.get(url, timeout=60)
            r.raise_for_status()
            data = r.json()
            # Handle different JSON structures
            if isinstance(data, list):
                for item in data:
                    cve = item.get("cve_id", item.get("cve", "")).strip().upper()
                    tech = item.get("technique_id", item.get("technique", ""))
                    if cve and tech:
                        mappings.setdefault(cve, []).append(tech)
            elif isinstance(data, dict):
                for cve, techs in data.items():
                    cve = cve.strip().upper()
                    if isinstance(techs, list):
                        mappings[cve] = techs
                    elif isinstance(techs, str):
                        mappings[cve] = [techs]
            print(f"      Got ATT&CK mappings for {len(mappings)} CVEs.")
            return mappings
        except Exception as e:
            print(f"      Source failed ({e}), trying next...")

    print("      WARNING: Could not download ATT&CK mappings. Stage 3 sample will be skipped.")
    return {}


def run_analysis(nvd_df, epss_current_df, epss_historical_df, kev_ids, kev_dates,
                 exploitdb_cves, attack_mappings):
    print("\n" + "=" * 70)
    print("  RUNNING ANALYSIS")
    print("=" * 70)

    nvd_df["on_kev"] = nvd_df["cve_id"].isin(kev_ids)
    nvd_df = nvd_df.join(epss_current_df, on="cve_id", how="left")
    nvd_df = nvd_df.join(epss_historical_df, on="cve_id", how="left")
    nvd_df["has_exploitdb"] = nvd_df["cve_id"].isin(exploitdb_cves)

    df = nvd_df[nvd_df["cvss_score"].notna()].copy()

    total = len(df)
    total_exploited = df["on_kev"].sum()

    print(f"\n  CVEs in {ANALYSIS_YEAR} cohort with CVSS:  {total:,}")
    print(f"  CVEs with current EPSS scores:        {df['epss_score_current'].notna().sum():,}")
    print(f"  CVEs with historical EPSS scores:      {df['epss_score_historical'].notna().sum():,}")
    print(f"  CVEs confirmed exploited (KEV):        {total_exploited}")
    print(f"  CVEs with ExploitDB entries:           {df['has_exploitdb'].sum():,}")

    if total_exploited == 0:
        print("\n  WARNING: No KEV-listed CVEs found in this year's cohort.")
        return

    # ════════════════════════════════════════════════
    # CVSS-Only baseline
    # ════════════════════════════════════════════════
    df["cvss_urgent"] = df["cvss_score"] >= CVSS_HIGH_THRESHOLD
    cvss_urgent_n = df["cvss_urgent"].sum()
    cvss_caught = df[df["cvss_urgent"] & df["on_kev"]].shape[0]
    cvss_missed = int(total_exploited) - cvss_caught
    cvss_coverage = cvss_caught / total_exploited * 100
    cvss_efficiency = cvss_caught / cvss_urgent_n * 100 if cvss_urgent_n else 0

    # ════════════════════════════════════════════════
    # Framework with CURRENT EPSS (for comparison — shows look-ahead bias)
    # ════════════════════════════════════════════════
    def fw_tier_current(row):
        if row["on_kev"]:
            return "Immediate"
        if pd.notna(row["epss_score_current"]) and row["epss_score_current"] >= EPSS_THRESHOLD:
            return "Accelerated"
        return "Standard"

    df["fw_tier_current"] = df.apply(fw_tier_current, axis=1)
    df["fw_urgent_current"] = df["fw_tier_current"].isin(["Immediate", "Accelerated"])
    fw_cur_urgent_n = df["fw_urgent_current"].sum()
    fw_cur_caught = df[df["fw_urgent_current"] & df["on_kev"]].shape[0]
    fw_cur_coverage = fw_cur_caught / total_exploited * 100
    fw_cur_efficiency = fw_cur_caught / fw_cur_urgent_n * 100 if fw_cur_urgent_n else 0

    # ════════════════════════════════════════════════
    # Framework with HISTORICAL EPSS (primary result — no look-ahead bias)
    # ════════════════════════════════════════════════
    def fw_tier_historical(row):
        if row["on_kev"]:
            return "Immediate"
        if pd.notna(row["epss_score_historical"]) and row["epss_score_historical"] >= EPSS_THRESHOLD:
            return "Accelerated"
        return "Standard"

    df["fw_tier_historical"] = df.apply(fw_tier_historical, axis=1)
    df["fw_urgent_historical"] = df["fw_tier_historical"].isin(["Immediate", "Accelerated"])
    fw_hist_urgent_n = df["fw_urgent_historical"].sum()
    fw_hist_caught = df[df["fw_urgent_historical"] & df["on_kev"]].shape[0]
    fw_hist_coverage = fw_hist_caught / total_exploited * 100
    fw_hist_efficiency = fw_hist_caught / fw_hist_urgent_n * 100 if fw_hist_urgent_n else 0
    volume_reduction_hist = (1 - fw_hist_urgent_n / cvss_urgent_n) * 100 if cvss_urgent_n else 0

    # ════════════════════════════════════════════════
    # Stage decomposition (historical)
    # ════════════════════════════════════════════════
    stage1_immediate = df[df["fw_tier_historical"] == "Immediate"]
    stage1_count = len(stage1_immediate)
    stage1_exploited = stage1_immediate["on_kev"].sum()

    stage2_accelerated = df[df["fw_tier_historical"] == "Accelerated"]
    stage2_count = len(stage2_accelerated)
    stage2_exploited = stage2_accelerated["on_kev"].sum()
    # By design, Stage 2 Accelerated CVEs are NOT on KEV (KEV -> Immediate at Stage 1)
    # So stage2_exploited should be 0. But let's report it honestly.

    stage2_with_exploitdb = df[(df["fw_tier_historical"] == "Accelerated") & df["has_exploitdb"]].shape[0]

    # KEV CVEs caught by Stage 1 that CVSS would have missed
    kev_below_cvss = df[df["on_kev"] & (df["cvss_score"] < CVSS_HIGH_THRESHOLD)].shape[0]

    # ════════════════════════════════════════════════
    # Stage 3 sample: ATT&CK mapping check
    # ════════════════════════════════════════════════
    stage3_results = []
    if attack_mappings:
        accelerated_cves = df[df["fw_tier_historical"] == "Accelerated"]["cve_id"].tolist()
        sample = accelerated_cves[:STAGE3_SAMPLE_SIZE]
        for cve_id in sample:
            techniques = attack_mappings.get(cve_id, [])
            stage3_results.append({
                "cve_id": cve_id,
                "has_attack_mapping": len(techniques) > 0,
                "techniques": "; ".join(techniques) if techniques else "None",
                "technique_count": len(techniques)
            })
        mapped_count = sum(1 for r in stage3_results if r["has_attack_mapping"])
        print(f"\n  Stage 3 sample ({len(sample)} CVEs): {mapped_count} have ATT&CK mappings.")

    # ════════════════════════════════════════════════
    # PRINT RESULTS
    # ════════════════════════════════════════════════
    print(f"\n  {'':50} {'CVSS-Only':>12} {'FW (Hist)':>12} {'FW (Current)':>12}")
    print(f"  {'-'*50} {'-'*12} {'-'*12} {'-'*12}")
    print(f"  {'CVEs flagged urgent':<50} {cvss_urgent_n:>12,} {fw_hist_urgent_n:>12,} {fw_cur_urgent_n:>12,}")
    print(f"  {'Exploited CVEs caught':<50} {cvss_caught:>12} {fw_hist_caught:>12} {fw_cur_caught:>12}")
    print(f"  {'Coverage (% exploited caught)':<50} {cvss_coverage:>11.1f}% {fw_hist_coverage:>11.1f}% {fw_cur_coverage:>11.1f}%")
    print(f"  {'Efficiency (% urgent actually exploited)':<50} {cvss_efficiency:>11.2f}% {fw_hist_efficiency:>11.2f}% {fw_cur_efficiency:>11.2f}%")
    print(f"  {'Volume reduction vs CVSS-only':<50} {'---':>12} {volume_reduction_hist:>11.1f}% {'(biased)':>12}")

    print(f"\n  STAGE DECOMPOSITION (Historical EPSS):")
    print(f"    Stage 1 (KEV → Immediate):      {stage1_count:>6,} CVEs  ({int(stage1_exploited)} exploited)")
    print(f"    Stage 2 (EPSS → Accelerated):    {stage2_count:>6,} CVEs  ({int(stage2_exploited)} exploited by KEV)")
    print(f"      — of which have ExploitDB:     {stage2_with_exploitdb:>6,} CVEs")
    print(f"    Standard:                        {len(df) - stage1_count - stage2_count:>6,} CVEs")
    print(f"    KEV CVEs below CVSS 7.0:         {kev_below_cvss:>6}")

    if stage3_results:
        mapped = sum(1 for r in stage3_results if r["has_attack_mapping"])
        print(f"\n  STAGE 3 SAMPLE ({len(stage3_results)} EPSS-elevated CVEs):")
        print(f"    With ATT&CK mapping:             {mapped}")
        print(f"    Without ATT&CK mapping:          {len(stage3_results) - mapped}")

    # ════════════════════════════════════════════════
    # SAVE EXCEL
    # ════════════════════════════════════════════════
    print(f"\n  Saving {OUTPUT_FILE}...")

    summary_data = {
        "Metric": [
            "Analysis year", "Total CVEs analysed",
            "CVEs confirmed exploited (KEV)", "EPSS threshold",
            "EPSS score type (primary)", "",
            "CVSS-Only: flagged urgent", "CVSS-Only: exploited caught",
            "CVSS-Only: coverage (%)", "CVSS-Only: efficiency (%)", "",
            "Framework (Historical EPSS): flagged urgent",
            "Framework (Historical EPSS): exploited caught",
            "Framework (Historical EPSS): coverage (%)",
            "Framework (Historical EPSS): efficiency (%)",
            "Volume reduction vs CVSS-only (%)", "",
            "Stage 1 (KEV): CVEs assigned Immediate",
            "Stage 1: Exploited CVEs caught",
            "Stage 2 (EPSS): CVEs assigned Accelerated",
            "Stage 2: CVEs with ExploitDB entries",
            "Stage 2: ExploitDB rate (%)",
            "KEV CVEs below CVSS 7.0 (caught by Stage 1, missed by CVSS)", "",
            "Framework (Current EPSS — BIASED): flagged urgent",
            "Framework (Current EPSS — BIASED): exploited caught",
            "Framework (Current EPSS — BIASED): coverage (%)",
            "Framework (Current EPSS — BIASED): efficiency (%)",
            "NOTE: Current EPSS results shown for comparison only — they contain look-ahead bias"
        ],
        "Value": [
            ANALYSIS_YEAR, total,
            int(total_exploited), EPSS_THRESHOLD,
            f"Historical ({EPSS_OFFSET_DAYS} days post-publication)", "",
            int(cvss_urgent_n), cvss_caught,
            round(cvss_coverage, 1), round(cvss_efficiency, 2), "",
            int(fw_hist_urgent_n),
            fw_hist_caught,
            round(fw_hist_coverage, 1), round(fw_hist_efficiency, 2),
            round(volume_reduction_hist, 1), "",
            stage1_count,
            int(stage1_exploited),
            stage2_count,
            stage2_with_exploitdb,
            round(stage2_with_exploitdb / stage2_count * 100, 1) if stage2_count else 0,
            kev_below_cvss, "",
            int(fw_cur_urgent_n),
            fw_cur_caught,
            round(fw_cur_coverage, 1), round(fw_cur_efficiency, 2),
            "DO NOT USE IN PAPER"
        ]
    }

    summary = pd.DataFrame(summary_data)

    export = df[[
        "cve_id", "cvss_score", "pub_date",
        "epss_score_historical", "epss_score_current",
        "on_kev", "has_exploitdb",
        "fw_tier_historical", "fw_tier_current"
    ]].copy()
    export.columns = [
        "CVE ID", "CVSS Score", "Publication Date",
        "EPSS Score (Historical)", "EPSS Score (Current)",
        "On KEV", "Has ExploitDB Entry",
        "Framework Tier (Historical)", "Framework Tier (Current)"
    ]

    # Stage 3 sample sheet
    stage3_df = pd.DataFrame(stage3_results) if stage3_results else pd.DataFrame()

    with pd.ExcelWriter(OUTPUT_FILE, engine="openpyxl") as w:
        summary.to_excel(w, sheet_name="Summary", index=False)
        export.head(60000).to_excel(w, sheet_name="CVE Details", index=False)
        if len(stage3_df) > 0:
            stage3_df.to_excel(w, sheet_name="Stage 3 Sample", index=False)

    print(f"  Saved.\n")

    # ════════════════════════════════════════════════
    # COPY-PASTE TEXT FOR PAPER
    # ════════════════════════════════════════════════
    print("=" * 70)
    print("  NUMBERS FOR YOUR PAPER (Historical EPSS — primary results):")
    print("=" * 70)
    print(f"""
Cohort: {total:,} CVEs from {ANALYSIS_YEAR} with CVSS scores.
Exploited (KEV): {int(total_exploited)}

CVSS-Only (>=7.0):
  Flagged urgent:    {cvss_urgent_n:,}
  Exploited caught:  {cvss_caught}
  Coverage:          {cvss_coverage:.1f}%
  Efficiency:        {cvss_efficiency:.2f}%
  Missed:            {cvss_missed} exploited CVEs below 7.0

Framework (Historical EPSS, Stages 1-2):
  Flagged urgent:    {fw_hist_urgent_n:,}
  Exploited caught:  {fw_hist_caught} (all via Stage 1/KEV by design)
  Coverage:          {fw_hist_coverage:.1f}% (structural — see paper text)
  Efficiency:        {fw_hist_efficiency:.2f}%
  Volume reduction:  {volume_reduction_hist:.1f}%

Stage 2 cross-validation:
  EPSS-elevated CVEs:        {stage2_count:,}
  With ExploitDB entries:    {stage2_with_exploitdb}
  ExploitDB rate:            {round(stage2_with_exploitdb / stage2_count * 100, 1) if stage2_count else 0}%

Comparison: current-day vs historical EPSS:
  Current EPSS flagged:      {fw_cur_urgent_n:,} (biased)
  Historical EPSS flagged:   {fw_hist_urgent_n:,} (unbiased)
  Difference:                {fw_cur_urgent_n - fw_hist_urgent_n:,} additional CVEs from look-ahead bias
""")


if __name__ == "__main__":
    print("=" * 70)
    print("  THREAT-INFORMED VULNERABILITY PRIORITIZATION")
    print("  Retrospective Analysis v5 (Historical EPSS + Cross-Validation)")
    print("=" * 70)
    print(f"  Year: {ANALYSIS_YEAR}  |  EPSS threshold: {EPSS_THRESHOLD}")
    print(f"  EPSS offset: {EPSS_OFFSET_DAYS} days post-publication")

    kev_ids, kev_dates = download_kev()
    epss_current_df = download_epss_current()
    nvd_df = download_nvd_bulk(ANALYSIS_YEAR)

    # Build CVE -> publication date mapping for historical EPSS lookup
    cve_pub_dates = {}
    for _, row in nvd_df.iterrows():
        if pd.notna(row.get("pub_date")):
            cve_pub_dates[row["cve_id"]] = row["pub_date"]
    print(f"\n      {len(cve_pub_dates)} CVEs have publication dates for historical EPSS lookup.")

    epss_historical_df = download_epss_historical(cve_pub_dates)
    exploitdb_cves = download_exploitdb_cves()
    attack_mappings = download_attack_cve_mappings()

    run_analysis(nvd_df, epss_current_df, epss_historical_df, kev_ids, kev_dates,
                 exploitdb_cves, attack_mappings)

    print("  All done. Use the HISTORICAL EPSS numbers in your paper.")
    print("  Current EPSS numbers shown for comparison only (look-ahead bias).")
    print("=" * 70)
