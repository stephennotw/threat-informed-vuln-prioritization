"""
THREAT-INFORMED VULNERABILITY PRIORITIZATION — RETROSPECTIVE ANALYSIS
=====================================================================
HOW TO USE:
    pip install requests pandas openpyxl
    python run_analysis.py

Takes about 2-5 minutes total.
"""

import requests
import pandas as pd
import json
import lzma
import sys
import time

ANALYSIS_YEAR = 2023
EPSS_THRESHOLD = 0.10
CVSS_HIGH_THRESHOLD = 7.0
OUTPUT_FILE = "analysis_results.xlsx"


def download_kev():
    print("\n[1/3] Downloading CISA KEV catalog...")
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    try:
        r = requests.get(url, timeout=60)
        r.raise_for_status()
        vulns = r.json().get("vulnerabilities", [])
        kev_ids = set(v.get("cveID", "").strip().upper() for v in vulns if v.get("cveID"))
        print(f"      Got {len(kev_ids)} KEV entries.")
        return kev_ids
    except Exception as e:
        print(f"      ERROR: {e}")
        sys.exit(1)


def download_epss():
    print("\n[2/3] Downloading EPSS scores...")
    url = "https://epss.cyentia.com/epss_scores-current.csv.gz"
    try:
        df = pd.read_csv(url, compression="gzip", comment="#")
        df.columns = [c.strip() for c in df.columns]
        df = df.rename(columns={"cve": "cve_id", "epss": "epss_score"})
        df["epss_score"] = pd.to_numeric(df["epss_score"], errors="coerce")
        df["cve_id"] = df["cve_id"].str.strip().str.upper()
        print(f"      Got EPSS scores for {len(df)} CVEs.")
        return df[["cve_id", "epss_score"]].set_index("cve_id")
    except Exception as e:
        print(f"      ERROR: {e}")
        sys.exit(1)


def extract_cvss_from_item(item):
    """
    Extract a CVSS base score from a single CVE item.
    Handles multiple JSON structures by searching common key patterns.
    """
    # ── Structure A: NVD 2.0 API format ──
    # {"cve": {"id": "CVE-...", "metrics": {"cvssMetricV31": [...]}}}
    cve_obj = item.get("cve", item)  # might be nested or flat
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

    # ── Structure B: Legacy NVD 1.1 format ──
    # {"impact": {"baseMetricV3": {"cvssV3": {"baseScore": 9.8}}}}
    impact = item.get("impact", {})
    if "baseMetricV3" in impact:
        score = impact["baseMetricV3"].get("cvssV3", {}).get("baseScore")
        if score is not None:
            return score
    if "baseMetricV2" in impact:
        score = impact["baseMetricV2"].get("cvssV2", {}).get("baseScore")
        if score is not None:
            return score

    # ── Structure C: flat score fields ──
    for key in ["baseScore", "cvss_score", "base_score", "score"]:
        if key in item:
            return item[key]
        if key in cve_obj:
            return cve_obj[key]

    return None


def extract_cve_id(item):
    """Extract CVE ID from a single item, handling multiple structures."""
    # NVD 2.0: item["cve"]["id"]
    cve_obj = item.get("cve", {})
    if isinstance(cve_obj, dict):
        cve_id = cve_obj.get("id", "")
        if cve_id:
            return cve_id.strip().upper()
        # Legacy 1.1: item["cve"]["CVE_data_meta"]["ID"]
        meta = cve_obj.get("CVE_data_meta", {})
        cve_id = meta.get("ID", "")
        if cve_id:
            return cve_id.strip().upper()

    # Flat: item["id"] or item["cveID"] or item["cve_id"]
    for key in ["id", "cveID", "cve_id", "ID", "cveId"]:
        cve_id = item.get(key, "")
        if isinstance(cve_id, str) and cve_id.upper().startswith("CVE-"):
            return cve_id.strip().upper()

    return None


def download_nvd_bulk(year):
    print(f"\n[3/3] Downloading NVD data for {year}...")

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

        # Find the list of CVE items regardless of key name
        items = None
        if isinstance(data, dict):
            print(f"      JSON keys: {list(data.keys())}")
            # Try every key that looks like it holds the CVE list
            for key in ["vulnerabilities", "CVE_Items", "cve_items",
                        "CVE_items", "cveItems", "items", "cves", "results"]:
                if key in data and isinstance(data[key], list):
                    items = data[key]
                    print(f"      Found CVE list under key '{key}': {len(items)} items")
                    break
            # If none matched, try any list-valued key
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
            print(f"      Keys found: {list(data.keys()) if isinstance(data, dict) else 'N/A'}")
            print("      Falling back to NVD API...")
            return download_nvd_api(year)

        # Show a sample item so we can debug if needed
        if len(items) > 0:
            sample = items[0]
            sample_id = extract_cve_id(sample)
            sample_score = extract_cvss_from_item(sample)
            print(f"      Sample: ID={sample_id}, CVSS={sample_score}")
            if sample_id is None:
                print(f"      Sample item keys: {list(sample.keys()) if isinstance(sample, dict) else type(sample)}")

        # Parse all items
        records = []
        for item in items:
            cve_id = extract_cve_id(item)
            if cve_id:
                cvss_score = extract_cvss_from_item(item)
                records.append({"cve_id": cve_id, "cvss_score": cvss_score})

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
            print("      Failed after 5 retries on this page.")
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
            if cve_id:
                all_records.append({"cve_id": cve_id, "cvss_score": cvss_score})

        start_index += results_per_page
        print(f"      Progress: {len(all_records)}/{total}...")

        if start_index >= total:
            break
        time.sleep(8)

    df = pd.DataFrame(all_records)
    df["cvss_score"] = pd.to_numeric(df["cvss_score"], errors="coerce")
    print(f"      Done: {len(df)} CVEs, {df['cvss_score'].notna().sum()} with CVSS scores.")
    return df


def run_analysis(nvd_df, epss_df, kev_ids):
    print("\n" + "=" * 70)
    print("  RUNNING ANALYSIS")
    print("=" * 70)

    nvd_df["on_kev"] = nvd_df["cve_id"].isin(kev_ids)
    nvd_df = nvd_df.join(epss_df, on="cve_id", how="left")
    df = nvd_df[nvd_df["cvss_score"].notna()].copy()

    total = len(df)
    total_exploited = df["on_kev"].sum()

    print(f"\n  CVEs in {ANALYSIS_YEAR} cohort with CVSS:  {total:,}")
    print(f"  CVEs with EPSS scores:               {df['epss_score'].notna().sum():,}")
    print(f"  CVEs confirmed exploited (KEV):       {total_exploited}")

    if total_exploited == 0:
        print("\n  WARNING: No KEV-listed CVEs found in this year's cohort.")
        print("  Try changing ANALYSIS_YEAR to 2022 or 2021.")
        return

    # CVSS-only
    df["cvss_urgent"] = df["cvss_score"] >= CVSS_HIGH_THRESHOLD
    cvss_urgent_n = df["cvss_urgent"].sum()
    cvss_caught = df[df["cvss_urgent"] & df["on_kev"]].shape[0]
    cvss_coverage = cvss_caught / total_exploited * 100
    cvss_efficiency = cvss_caught / cvss_urgent_n * 100 if cvss_urgent_n else 0

    # Framework
    def fw_tier(row):
        if row["on_kev"]:
            return "Immediate"
        if pd.notna(row["epss_score"]) and row["epss_score"] >= EPSS_THRESHOLD:
            return "Accelerated"
        return "Standard"

    df["fw_tier"] = df.apply(fw_tier, axis=1)
    df["fw_urgent"] = df["fw_tier"].isin(["Immediate", "Accelerated"])
    fw_urgent_n = df["fw_urgent"].sum()
    fw_caught = df[df["fw_urgent"] & df["on_kev"]].shape[0]
    fw_coverage = fw_caught / total_exploited * 100
    fw_efficiency = fw_caught / fw_urgent_n * 100 if fw_urgent_n else 0
    volume_reduction = (1 - fw_urgent_n / cvss_urgent_n) * 100 if cvss_urgent_n else 0

    print(f"\n  {'':45} {'CVSS-Only':>12} {'Framework':>12}")
    print(f"  {'-'*45} {'-'*12} {'-'*12}")
    print(f"  {'CVEs flagged urgent':<45} {cvss_urgent_n:>12,} {fw_urgent_n:>12,}")
    print(f"  {'Exploited CVEs caught':<45} {cvss_caught:>12} {fw_caught:>12}")
    print(f"  {'Coverage (% exploited caught)':<45} {cvss_coverage:>11.1f}% {fw_coverage:>11.1f}%")
    print(f"  {'Efficiency (% urgent actually exploited)':<45} {cvss_efficiency:>11.2f}% {fw_efficiency:>11.2f}%")
    print(f"  {'Volume reduction vs CVSS-only':<45} {'---':>12} {volume_reduction:>11.1f}%")

    print(f"\n  CVSS-Only breakdown:")
    for label, mask in [("Urgent (>=7.0)", df["cvss_urgent"]),
                        ("Not urgent (<7.0)", ~df["cvss_urgent"])]:
        n = mask.sum()
        ex = df[mask & df["on_kev"]].shape[0]
        print(f"    {label:<25} {n:>8,} CVEs   ({ex} exploited)")

    print(f"\n  Framework breakdown (Stages 1-2):")
    for tier in ["Immediate", "Accelerated", "Standard"]:
        mask = df["fw_tier"] == tier
        n = mask.sum()
        ex = df[mask & df["on_kev"]].shape[0]
        print(f"    {tier:<25} {n:>8,} CVEs   ({ex} exploited)")

    # Save Excel
    print(f"\n  Saving {OUTPUT_FILE}...")
    summary = pd.DataFrame({
        "Metric": [
            "Analysis year", "Total CVEs analysed",
            "CVEs confirmed exploited (KEV)", "EPSS threshold", "",
            "CVSS-Only: flagged urgent", "CVSS-Only: exploited caught",
            "CVSS-Only: coverage (%)", "CVSS-Only: efficiency (%)", "",
            "Framework: flagged urgent", "Framework: exploited caught",
            "Framework: coverage (%)", "Framework: efficiency (%)",
            "Volume reduction vs CVSS-only (%)"
        ],
        "Value": [
            ANALYSIS_YEAR, total, int(total_exploited), EPSS_THRESHOLD, "",
            int(cvss_urgent_n), cvss_caught,
            round(cvss_coverage, 1), round(cvss_efficiency, 2), "",
            int(fw_urgent_n), fw_caught,
            round(fw_coverage, 1), round(fw_efficiency, 2),
            round(volume_reduction, 1)
        ]
    })

    export = df[["cve_id", "cvss_score", "epss_score", "on_kev", "fw_tier"]].copy()
    export.columns = ["CVE ID", "CVSS Score", "EPSS Score", "On KEV", "Framework Tier"]

    with pd.ExcelWriter(OUTPUT_FILE, engine="openpyxl") as w:
        summary.to_excel(w, sheet_name="Summary", index=False)
        export.head(60000).to_excel(w, sheet_name="CVE Details", index=False)

    print(f"  Saved.\n")

    print("=" * 70)
    print("  COPY THIS INTO SECTION 7.3 OF YOUR PAPER:")
    print("=" * 70)
    print(f"""
The retrospective analysis examined {total:,} CVEs published in {ANALYSIS_YEAR}
that had CVSS base scores available in the NVD. Of these, {int(total_exploited)}
subsequently appeared on the CISA KEV catalog, confirming real-world
exploitation.

Under a CVSS-only approach (flagging all CVEs scored {CVSS_HIGH_THRESHOLD} or
above as urgent), {cvss_urgent_n:,} CVEs were classified as High or Critical.
This captured {cvss_caught} of the {int(total_exploited)} exploited CVEs
({cvss_coverage:.1f}% coverage) but at an efficiency of just
{cvss_efficiency:.2f}%, meaning that only approximately {max(1,round(cvss_efficiency,1))}
in every 100 urgent CVEs were actually exploited.

The proposed framework (applying Stage 1 KEV check and Stage 2 EPSS threshold
at {EPSS_THRESHOLD}) flagged {fw_urgent_n:,} CVEs as Immediate or Accelerated.
This captured {fw_caught} of {int(total_exploited)} exploited CVEs
({fw_coverage:.1f}% coverage) with an efficiency of {fw_efficiency:.2f}%.
The framework reduced the volume of urgent items by {volume_reduction:.1f}%
compared to CVSS-only.

Stage 3 (ATT&CK relevance) and Stage 4 (environmental adjustment) could not
be applied in this retrospective analysis due to the absence of
organisation-specific data and incomplete CVE-to-ATT&CK mappings. The results
therefore represent a conservative test of the framework using only its first
two stages.
""")


if __name__ == "__main__":
    print("=" * 70)
    print("  THREAT-INFORMED VULNERABILITY PRIORITIZATION")
    print("  Retrospective Analysis v4")
    print("=" * 70)
    print(f"  Year: {ANALYSIS_YEAR}  |  EPSS threshold: {EPSS_THRESHOLD}")

    kev_ids = download_kev()
    epss_df = download_epss()
    nvd_df = download_nvd_bulk(ANALYSIS_YEAR)
    run_analysis(nvd_df, epss_df, kev_ids)

    print("  All done. Use the numbers above in your paper.")
    print("=" * 70)