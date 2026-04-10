"""
MULTI-YEAR RETROSPECTIVE ANALYSIS + GREYYNOISE CROSS-VALIDATION
================================================================
Runs the same historical EPSS analysis for 2021, 2022, 2023, and 2024.
Also checks Stage 2 CVEs against GreyNoise Community API for exploitation evidence.

HOW TO USE:
    pip install requests pandas openpyxl
    python run_multiyear.py

Runtime: 30-60 minutes (mostly historical EPSS API calls).
"""

import requests
import pandas as pd
import json
import lzma
import sys
import time
from datetime import datetime, timedelta
from collections import defaultdict

YEARS = [2021, 2022, 2023, 2024]
EPSS_THRESHOLD = 0.10
CVSS_HIGH_THRESHOLD = 7.0
EPSS_OFFSET_DAYS = 30
OUTPUT_FILE = "multiyear_results.xlsx"


def download_kev():
    print("\n[KEV] Downloading CISA KEV catalog...")
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    r = requests.get(url, timeout=60)
    r.raise_for_status()
    vulns = r.json().get("vulnerabilities", [])
    kev_ids = set(v.get("cveID", "").strip().upper() for v in vulns if v.get("cveID"))
    print(f"    Got {len(kev_ids)} KEV entries.")
    return kev_ids


def download_epss_current():
    print("\n[EPSS] Downloading current EPSS scores...")
    url = "https://epss.cyentia.com/epss_scores-current.csv.gz"
    df = pd.read_csv(url, compression="gzip", comment="#")
    df.columns = [c.strip() for c in df.columns]
    df = df.rename(columns={"cve": "cve_id", "epss": "epss_current"})
    df["epss_current"] = pd.to_numeric(df["epss_current"], errors="coerce")
    df["cve_id"] = df["cve_id"].str.strip().str.upper()
    print(f"    Got scores for {len(df)} CVEs.")
    return df[["cve_id", "epss_current"]].set_index("cve_id")


def extract_cvss(item):
    cve_obj = item.get("cve", item)
    metrics = cve_obj.get("metrics", {})
    for key in ["cvssMetricV31", "cvssMetricV30"]:
        if key in metrics and len(metrics[key]) > 0:
            s = metrics[key][0].get("cvssData", {}).get("baseScore")
            if s is not None: return s
    if "cvssMetricV2" in metrics and len(metrics["cvssMetricV2"]) > 0:
        s = metrics["cvssMetricV2"][0].get("cvssData", {}).get("baseScore")
        if s is not None: return s
    impact = item.get("impact", {})
    for k in ["baseMetricV3", "baseMetricV2"]:
        if k in impact:
            sub = "cvssV3" if "V3" in k else "cvssV2"
            s = impact[k].get(sub, {}).get("baseScore")
            if s is not None: return s
    return None


def extract_id(item):
    cve_obj = item.get("cve", {})
    if isinstance(cve_obj, dict):
        cid = cve_obj.get("id", "")
        if cid: return cid.strip().upper()
        cid = cve_obj.get("CVE_data_meta", {}).get("ID", "")
        if cid: return cid.strip().upper()
    for k in ["id", "cveID", "cve_id"]:
        cid = item.get(k, "")
        if isinstance(cid, str) and cid.upper().startswith("CVE-"):
            return cid.strip().upper()
    return None


def extract_pub_date(item):
    cve_obj = item.get("cve", item)
    for k in ["published", "publishedDate"]:
        d = cve_obj.get(k, "") or item.get(k, "")
        if d: return d[:10]
    return None


def download_nvd(year):
    print(f"\n[NVD] Downloading {year}...")
    url = f"https://github.com/fkie-cad/nvd-json-data-feeds/releases/latest/download/CVE-{year}.json.xz"
    try:
        r = requests.get(url, timeout=300, stream=True)
        r.raise_for_status()
        raw = b"".join(r.iter_content(1024*1024))
        try: data = json.loads(lzma.decompress(raw))
        except: data = json.loads(raw)
        
        items = None
        if isinstance(data, dict):
            for k in ["vulnerabilities", "CVE_Items"]:
                if k in data and isinstance(data[k], list):
                    items = data[k]; break
            if not items:
                for k, v in data.items():
                    if isinstance(v, list) and len(v) > 100:
                        items = v; break
        elif isinstance(data, list):
            items = data
        
        if not items:
            print(f"    Could not parse {year}")
            return pd.DataFrame()
        
        records = []
        for item in items:
            cid = extract_id(item)
            if cid:
                records.append({
                    "cve_id": cid,
                    "cvss": extract_cvss(item),
                    "pub_date": extract_pub_date(item)
                })
        df = pd.DataFrame(records)
        df["cvss"] = pd.to_numeric(df["cvss"], errors="coerce")
        print(f"    {len(df)} CVEs, {df['cvss'].notna().sum()} with CVSS.")
        return df
    except Exception as e:
        print(f"    Failed: {e}")
        return pd.DataFrame()


def download_historical_epss(cve_dates):
    print(f"\n[EPSS-HIST] Downloading historical scores for {len(cve_dates)} CVEs...")
    date_groups = defaultdict(list)
    for cve, pub in cve_dates.items():
        try:
            pd_dt = datetime.strptime(pub[:10], "%Y-%m-%d")
            target = pd_dt + timedelta(days=EPSS_OFFSET_DAYS)
            earliest = datetime(2022, 2, 4)
            if target < earliest: target = earliest
            if target > datetime.now(): target = datetime.now() - timedelta(days=1)
            date_groups[target.strftime("%Y-%m-%d")].append(cve)
        except: pass
    
    print(f"    Grouped into {len(date_groups)} dates.")
    results = {}
    done = 0
    
    for date_str, cves in sorted(date_groups.items()):
        for i in range(0, len(cves), 100):
            batch = cves[i:i+100]
            url = f"https://api.first.org/data/v1/epss?cve={','.join(batch)}&date={date_str}"
            for attempt in range(3):
                try:
                    r = requests.get(url, timeout=60)
                    if r.status_code == 429:
                        time.sleep(10 + attempt * 10); continue
                    r.raise_for_status()
                    for entry in r.json().get("data", []):
                        cid = entry.get("cve", "").strip().upper()
                        epss = entry.get("epss")
                        if cid and epss is not None:
                            results[cid] = float(epss)
                    break
                except Exception as e:
                    if attempt == 2: pass
            time.sleep(1.0)
        done += 1
        if done % 20 == 0:
            print(f"    {done}/{len(date_groups)} dates, {len(results)} scores...")
    
    print(f"    Done: {len(results)} historical scores.")
    return pd.DataFrame([{"cve_id": k, "epss_hist": v} for k, v in results.items()]).set_index("cve_id") if results else pd.DataFrame(columns=["cve_id", "epss_hist"]).set_index("cve_id")


def check_greynoise(cve_list):
    """Check CVEs against GreyNoise Community API for exploitation evidence."""
    print(f"\n[GREYNOISE] Checking {len(cve_list)} CVEs...")
    print("    Using GreyNoise Community API (free, no key required)")
    
    results = {}
    for i, cve in enumerate(sorted(cve_list)):
        url = f"https://api.greynoise.io/v3/community/{cve}"
        try:
            r = requests.get(url, timeout=10,
                           headers={"User-Agent": "research-script",
                                    "Accept": "application/json"})
            if r.status_code == 200:
                data = r.json()
                results[cve] = {
                    "seen": data.get("seen", False),
                    "classification": data.get("classification", "unknown"),
                    "noise": data.get("noise", False),
                    "riot": data.get("riot", False),
                    "name": data.get("name", ""),
                    "message": data.get("message", "")
                }
            elif r.status_code == 404:
                results[cve] = {"seen": False, "classification": "not_found"}
            else:
                results[cve] = {"seen": False, "classification": f"error_{r.status_code}"}
        except Exception as e:
            results[cve] = {"seen": False, "classification": f"error"}
        
        if (i + 1) % 10 == 0:
            print(f"    Progress: {i+1}/{len(cve_list)}")
        time.sleep(1.0)  # Rate limit: 1 req/sec for community API
    
    seen_count = sum(1 for v in results.values() if v.get("seen"))
    malicious = sum(1 for v in results.values() if v.get("classification") == "malicious")
    print(f"    Seen by GreyNoise: {seen_count}/{len(cve_list)}")
    print(f"    Classified malicious: {malicious}")
    return results


def analyze_year(nvd_df, epss_current, epss_hist, kev_ids, year):
    nvd_df["on_kev"] = nvd_df["cve_id"].isin(kev_ids)
    nvd_df = nvd_df.join(epss_current, on="cve_id", how="left")
    nvd_df = nvd_df.join(epss_hist, on="cve_id", how="left")
    df = nvd_df[nvd_df["cvss"].notna()].copy()
    
    total = len(df)
    exploited = df["on_kev"].sum()
    if exploited == 0:
        return {"year": year, "total": total, "exploited": 0, "note": "No KEV CVEs"}
    
    # CVSS-only
    cvss_u = (df["cvss"] >= CVSS_HIGH_THRESHOLD).sum()
    cvss_c = ((df["cvss"] >= CVSS_HIGH_THRESHOLD) & df["on_kev"]).sum()
    
    # Framework (historical)
    fw_urgent = df["on_kev"] | (df["epss_hist"].fillna(0) >= EPSS_THRESHOLD)
    fw_u = fw_urgent.sum()
    fw_c = (fw_urgent & df["on_kev"]).sum()
    stage2 = ((df["epss_hist"].fillna(0) >= EPSS_THRESHOLD) & ~df["on_kev"]).sum()
    
    # Framework (current - biased)
    fw_cur = df["on_kev"] | (df["epss_current"].fillna(0) >= EPSS_THRESHOLD)
    fw_cu = fw_cur.sum()
    
    import numpy as np
    # MCC for framework
    tp = (fw_urgent & df["on_kev"]).sum()
    fp = (fw_urgent & ~df["on_kev"]).sum()
    fn = (~fw_urgent & df["on_kev"]).sum()
    tn = (~fw_urgent & ~df["on_kev"]).sum()
    denom = np.sqrt(float((tp+fp)*(tp+fn)*(tn+fp)*(tn+fn)))
    mcc_fw = (tp*tn - fp*fn) / denom if denom > 0 else 0
    
    # MCC for CVSS
    cvss_mask = df["cvss"] >= CVSS_HIGH_THRESHOLD
    tp2 = (cvss_mask & df["on_kev"]).sum()
    fp2 = (cvss_mask & ~df["on_kev"]).sum()
    fn2 = (~cvss_mask & df["on_kev"]).sum()
    tn2 = (~cvss_mask & ~df["on_kev"]).sum()
    denom2 = np.sqrt(float((tp2+fp2)*(tp2+fn2)*(tn2+fp2)*(tn2+fn2)))
    mcc_cvss = (tp2*tn2 - fp2*fn2) / denom2 if denom2 > 0 else 0
    
    return {
        "year": year,
        "total": total,
        "exploited": int(exploited),
        "cvss_urgent": int(cvss_u),
        "cvss_caught": int(cvss_c),
        "cvss_coverage": round(cvss_c / exploited * 100, 1),
        "cvss_efficiency": round(cvss_c / cvss_u * 100, 2) if cvss_u else 0,
        "cvss_mcc": round(mcc_cvss, 4),
        "fw_urgent": int(fw_u),
        "fw_caught": int(fw_c),
        "fw_coverage": round(fw_c / exploited * 100, 1),
        "fw_efficiency": round(fw_c / fw_u * 100, 2) if fw_u else 0,
        "fw_reduction": round((1 - fw_u / cvss_u) * 100, 1) if cvss_u else 0,
        "fw_mcc": round(mcc_fw, 4),
        "stage2_count": int(stage2),
        "fw_current_urgent": int(fw_cu),
        "bias_inflation": int(fw_cu - fw_u),
        "kev_below_7": int(((df["cvss"] < 7.0) & df["on_kev"]).sum())
    }


if __name__ == "__main__":
    print("=" * 70)
    print("  MULTI-YEAR RETROSPECTIVE ANALYSIS")
    print("=" * 70)
    
    kev_ids = download_kev()
    epss_current = download_epss_current()
    
    all_results = []
    all_stage2_cves = {}
    
    for year in YEARS:
        nvd = download_nvd(year)
        if len(nvd) == 0:
            continue
        
        # Build pub date map
        pub_dates = {}
        for _, row in nvd.iterrows():
            if pd.notna(row.get("pub_date")):
                pub_dates[row["cve_id"]] = row["pub_date"]
        
        epss_hist = download_historical_epss(pub_dates)
        result = analyze_year(nvd.copy(), epss_current, epss_hist, kev_ids, year)
        all_results.append(result)
        
        # Collect Stage 2 CVEs for GreyNoise check
        nvd_tmp = nvd.copy()
        nvd_tmp = nvd_tmp.join(epss_hist, on="cve_id", how="left")
        nvd_tmp["on_kev"] = nvd_tmp["cve_id"].isin(kev_ids)
        stage2 = nvd_tmp[(nvd_tmp["epss_hist"].fillna(0) >= EPSS_THRESHOLD) & ~nvd_tmp["on_kev"]]
        all_stage2_cves[year] = set(stage2["cve_id"])
        
        print(f"\n  {year}: {result}")
    
    # GreyNoise check on all Stage 2 CVEs (combined across years)
    combined_stage2 = set()
    for cves in all_stage2_cves.values():
        combined_stage2 |= cves
    
    print(f"\n  Total Stage 2 CVEs across all years: {len(combined_stage2)}")
    
    greynoise_results = {}
    if len(combined_stage2) > 0 and len(combined_stage2) <= 500:
        greynoise_results = check_greynoise(combined_stage2)
    elif len(combined_stage2) > 500:
        # Sample 200 for GreyNoise
        import random
        sample = random.sample(sorted(combined_stage2), min(200, len(combined_stage2)))
        print(f"  Sampling {len(sample)} for GreyNoise check...")
        greynoise_results = check_greynoise(sample)
    
    # Print summary
    print("\n" + "=" * 70)
    print("  MULTI-YEAR SUMMARY")
    print("=" * 70)
    
    print(f"\n{'Year':>6} {'Total':>8} {'KEV':>5} {'CVSS-U':>8} {'FW-U':>6} {'CVSS-Cov':>9} {'FW-Cov':>7} {'CVSS-Eff':>9} {'FW-Eff':>7} {'Reduct':>7} {'CVSS-MCC':>9} {'FW-MCC':>7}")
    print("-" * 100)
    for r in all_results:
        if r.get("exploited", 0) > 0:
            print(f"{r['year']:>6} {r['total']:>8,} {r['exploited']:>5} {r['cvss_urgent']:>8,} {r['fw_urgent']:>6,} {r['cvss_coverage']:>8.1f}% {r['fw_coverage']:>6.1f}% {r['cvss_efficiency']:>8.2f}% {r['fw_efficiency']:>6.2f}% {r['fw_reduction']:>6.1f}% {r['cvss_mcc']:>9.4f} {r['fw_mcc']:>7.4f}")
    
    # GreyNoise summary
    if greynoise_results:
        seen = sum(1 for v in greynoise_results.values() if v.get("seen"))
        malicious = sum(1 for v in greynoise_results.values() if v.get("classification") == "malicious")
        benign = sum(1 for v in greynoise_results.values() if v.get("classification") == "benign")
        print(f"\n  GreyNoise results ({len(greynoise_results)} Stage 2 CVEs checked):")
        print(f"    Seen:       {seen}")
        print(f"    Malicious:  {malicious}")
        print(f"    Benign:     {benign}")
        print(f"    Not found:  {len(greynoise_results) - seen}")
    
    # Save
    print(f"\n  Saving {OUTPUT_FILE}...")
    results_df = pd.DataFrame(all_results)
    
    with pd.ExcelWriter(OUTPUT_FILE, engine="openpyxl") as w:
        results_df.to_excel(w, sheet_name="Multi-Year Summary", index=False)
        if greynoise_results:
            gn_df = pd.DataFrame([
                {"CVE ID": k, "Seen": v.get("seen"), "Classification": v.get("classification"),
                 "Name": v.get("name", "")}
                for k, v in greynoise_results.items()
            ])
            gn_df.to_excel(w, sheet_name="GreyNoise Results", index=False)
    
    print("  Done.")
    print("=" * 70)
