"""
MULTI-SOURCE EXPLOIT CROSS-VALIDATION
======================================
Cross-validates Stage 2 (EPSS-elevated) CVEs against four independent
exploitation/weaponization sources. None of these is the "ground truth"
that GreyNoise/Shadowserver would provide, but together they triangulate
whether a CVE has reached the level of operational threat where someone
has built tooling for it.

Sources (all free, no API key required):
  1. Nuclei templates (ProjectDiscovery) - working scanner templates
  2. PoC-in-GitHub (nomi-sec) - public proof-of-concept code
  3. Metasploit Framework modules - production exploit modules
  4. VulnCheck KEV (community) - extended KEV with broader coverage

A CVE flagged by multiple sources is much stronger evidence than KEV alone.

USAGE:
    pip install requests pandas openpyxl
    python multisource_validation.py

Reads: multiyear_results.xlsx (must exist with Stage 2 CVEs)
       analysis_results_v5.xlsx (for the 2023 cohort details)
Writes: exploit_validation.xlsx
"""

import requests
import pandas as pd
import json
import sys
import time
import re
from collections import defaultdict

OUTPUT_FILE = "exploit_validation.xlsx"


def get_stage2_cves():
    """Load all Stage 2 (Accelerated) CVEs from the v5 results."""
    print("[0] Loading Stage 2 CVEs from analysis_results.xlsx...")
    df = pd.read_excel("analysis_results.xlsx", sheet_name="CVE Details")
    acc = df[df["Framework Tier (Historical)"] == "Accelerated"]
    cve_set = set(acc["CVE ID"].str.strip().str.upper())
    print(f"    Loaded {len(cve_set)} Stage 2 CVEs.")
    return cve_set, df


def get_all_cves_from_v5():
    """Load all 30k CVEs for full-cohort cross-validation."""
    df = pd.read_excel("analysis_results.xlsx", sheet_name="CVE Details")
    return set(df["CVE ID"].str.strip().str.upper()), df


# ============================================================
# SOURCE 1: NUCLEI TEMPLATES
# ============================================================
def download_nuclei_cves():
    """
    ProjectDiscovery's nuclei-templates repo organises CVE templates under
    http/cves/YEAR/CVE-YEAR-XXXX.yaml. We can fetch the directory listings
    via the GitHub API and extract every CVE that has a template.
    """
    print("\n[1] Downloading Nuclei template CVE coverage...")
    nuclei_cves = set()

    # The repo has http/cves/{2021..2024}/ directories
    for year in range(2021, 2025):
        api_url = f"https://api.github.com/repos/projectdiscovery/nuclei-templates/contents/http/cves/{year}"
        try:
            r = requests.get(api_url, timeout=60,
                           headers={"User-Agent": "research-script",
                                    "Accept": "application/vnd.github.v3+json"})
            if r.status_code == 200:
                items = r.json()
                year_count = 0
                for item in items:
                    name = item.get("name", "")
                    m = re.match(r"(CVE-\d{4}-\d+)\.yaml", name, re.IGNORECASE)
                    if m:
                        nuclei_cves.add(m.group(1).upper())
                        year_count += 1
                print(f"    {year}: {year_count} templates")
            elif r.status_code == 403:
                # Rate limited - try the git tree API instead
                print(f"    {year}: GitHub API rate limited, trying tree API...")
                break
            else:
                print(f"    {year}: HTTP {r.status_code}")
        except Exception as e:
            print(f"    {year}: failed ({e})")
        time.sleep(0.5)

    # Fallback: use the git tree API which gives the entire repo in one request
    if len(nuclei_cves) < 100:
        print("    Falling back to git tree API...")
        try:
            tree_url = "https://api.github.com/repos/projectdiscovery/nuclei-templates/git/trees/main?recursive=1"
            r = requests.get(tree_url, timeout=120,
                           headers={"User-Agent": "research-script",
                                    "Accept": "application/vnd.github.v3+json"})
            r.raise_for_status()
            tree = r.json().get("tree", [])
            for item in tree:
                path = item.get("path", "")
                m = re.search(r"cves/\d{4}/(CVE-\d{4}-\d+)\.yaml", path, re.IGNORECASE)
                if m:
                    nuclei_cves.add(m.group(1).upper())
            print(f"    Tree API: {len(nuclei_cves)} CVE templates total")
        except Exception as e:
            print(f"    Tree API failed: {e}")

    print(f"    Total Nuclei CVE coverage: {len(nuclei_cves)}")
    return nuclei_cves


# ============================================================
# SOURCE 2: POC-IN-GITHUB
# ============================================================
def download_pocingithub():
    """
    nomi-sec/PoC-in-GitHub maintains a daily-updated index of GitHub PoC
    repositories per CVE. The repo has one JSON file per CVE under
    {YEAR}/CVE-YEAR-XXXX.json. The git tree API gives us the full list.
    """
    print("\n[2] Downloading PoC-in-GitHub coverage...")
    poc_cves = set()

    try:
        tree_url = "https://api.github.com/repos/nomi-sec/PoC-in-GitHub/git/trees/master?recursive=1"
        r = requests.get(tree_url, timeout=120,
                       headers={"User-Agent": "research-script",
                                "Accept": "application/vnd.github.v3+json"})
        r.raise_for_status()
        tree = r.json().get("tree", [])
        for item in tree:
            path = item.get("path", "")
            m = re.search(r"(CVE-\d{4}-\d+)\.json", path, re.IGNORECASE)
            if m:
                poc_cves.add(m.group(1).upper())
        print(f"    PoC-in-GitHub: {len(poc_cves)} CVEs with PoCs")
    except Exception as e:
        print(f"    Failed: {e}")
        # Try the trickest mirror as fallback
        print("    Trying trickest/cve as fallback...")
        try:
            tree_url = "https://api.github.com/repos/trickest/cve/git/trees/main?recursive=1"
            r = requests.get(tree_url, timeout=120,
                           headers={"User-Agent": "research-script"})
            r.raise_for_status()
            tree = r.json().get("tree", [])
            for item in tree:
                path = item.get("path", "")
                m = re.search(r"(CVE-\d{4}-\d+)\.md", path, re.IGNORECASE)
                if m:
                    poc_cves.add(m.group(1).upper())
            print(f"    Trickest: {len(poc_cves)} CVEs")
        except Exception as e2:
            print(f"    Trickest also failed: {e2}")

    return poc_cves


# ============================================================
# SOURCE 3: METASPLOIT FRAMEWORK MODULES
# ============================================================
def download_metasploit_cves():
    """
    Rapid7's metasploit-framework repo has modules under modules/exploits/.
    Each module's source includes a 'References' block with CVE IDs.
    The maintained list at modules_metadata_base.json gives us a clean index.
    """
    print("\n[3] Downloading Metasploit module CVE coverage...")
    msf_cves = set()

    urls = [
        "https://raw.githubusercontent.com/rapid7/metasploit-framework/master/db/modules_metadata_base.json",
    ]

    for url in urls:
        try:
            r = requests.get(url, timeout=180,
                           headers={"User-Agent": "research-script"})
            r.raise_for_status()
            data = r.json()
            print(f"    Loaded {len(data)} Metasploit modules")
            for mod_name, mod_data in data.items():
                refs = mod_data.get("references", [])
                for ref in refs:
                    if isinstance(ref, str) and ref.upper().startswith("CVE-"):
                        msf_cves.add(ref.strip().upper())
                    elif isinstance(ref, list) and len(ref) >= 2:
                        if str(ref[0]).upper() == "CVE":
                            msf_cves.add(f"CVE-{ref[1]}".upper())
            print(f"    Metasploit: {len(msf_cves)} CVEs with modules")
            return msf_cves
        except Exception as e:
            print(f"    Failed: {e}")

    # Fallback: parse module files directly via tree API
    print("    Trying git tree API fallback...")
    try:
        tree_url = "https://api.github.com/repos/rapid7/metasploit-framework/git/trees/master?recursive=1"
        r = requests.get(tree_url, timeout=120,
                       headers={"User-Agent": "research-script"})
        r.raise_for_status()
        tree = r.json().get("tree", [])
        # The tree might be truncated for huge repos; we'd need the modules/exploits subtree
        truncated = r.json().get("truncated", False)
        if truncated:
            print(f"    Tree truncated. Got {len(tree)} entries.")
        # Try to get modules/exploits subtree
        exploit_tree_url = "https://api.github.com/repos/rapid7/metasploit-framework/contents/modules/exploits"
        r2 = requests.get(exploit_tree_url, timeout=60,
                        headers={"User-Agent": "research-script"})
        if r2.status_code == 200:
            print(f"    Got modules/exploits listing")
    except Exception as e:
        print(f"    Tree fallback failed: {e}")

    return msf_cves


# ============================================================
# SOURCE 4: VULNCHECK KEV (COMMUNITY)
# ============================================================
def download_vulncheck_kev():
    """
    VulnCheck publishes an extended KEV-style catalog that includes
    exploits not yet in CISA KEV. The community endpoint requires a
    free API token. We try the public mirror first.
    """
    print("\n[4] Downloading VulnCheck KEV extended catalog...")
    vc_cves = set()

    # Try public mirrors and known data dumps
    urls = [
        # Community-maintained extended KEV mirrors
        "https://raw.githubusercontent.com/Ostorlab/KEV/main/vulncheck_data/vulncheck_kev.json",
        "https://raw.githubusercontent.com/Ostorlab/KEV/main/vulncheck_kev.json",
    ]

    for url in urls:
        try:
            r = requests.get(url, timeout=60,
                           headers={"User-Agent": "research-script"})
            if r.status_code == 200:
                data = r.json()
                if isinstance(data, list):
                    for entry in data:
                        if isinstance(entry, dict):
                            cve = entry.get("cve", entry.get("cveID", ""))
                            if cve and str(cve).upper().startswith("CVE-"):
                                vc_cves.add(str(cve).strip().upper())
                            elif "cve" in entry and isinstance(entry["cve"], list):
                                for c in entry["cve"]:
                                    if str(c).upper().startswith("CVE-"):
                                        vc_cves.add(str(c).strip().upper())
                elif isinstance(data, dict):
                    for entry in data.get("vulnerabilities", data.get("data", [])):
                        cve = entry.get("cve", entry.get("cveID", ""))
                        if cve and str(cve).upper().startswith("CVE-"):
                            vc_cves.add(str(cve).strip().upper())
                print(f"    VulnCheck KEV: {len(vc_cves)} CVEs")
                if len(vc_cves) > 0:
                    return vc_cves
        except Exception as e:
            print(f"    Failed: {e}")

    # Fallback: the Ostorlab KEV repo aggregates multiple sources
    print("    Trying Ostorlab KEV aggregator...")
    try:
        url = "https://raw.githubusercontent.com/Ostorlab/KEV/main/exploited_vulnerabilities.json"
        r = requests.get(url, timeout=60,
                       headers={"User-Agent": "research-script"})
        if r.status_code == 200:
            data = r.json()
            if isinstance(data, list):
                for entry in data:
                    if isinstance(entry, dict):
                        cve = entry.get("id", entry.get("cve", ""))
                        if str(cve).upper().startswith("CVE-"):
                            vc_cves.add(str(cve).strip().upper())
            print(f"    Ostorlab KEV: {len(vc_cves)} CVEs")
    except Exception as e:
        print(f"    Failed: {e}")

    return vc_cves


# ============================================================
# CROSS-VALIDATION ANALYSIS
# ============================================================
def cross_validate(stage2_cves, all_cves, sources):
    """
    For each Stage 2 CVE, check which sources flag it.
    Also compute base rates for the full cohort and KEV-listed CVEs.
    """
    print("\n" + "=" * 70)
    print("  CROSS-VALIDATION RESULTS")
    print("=" * 70)

    # Build per-CVE flag matrix
    rows = []
    for cve in sorted(stage2_cves):
        flags = {name: (cve in cves) for name, cves in sources.items()}
        flag_count = sum(flags.values())
        rows.append({
            "CVE ID": cve,
            **{f"In {name}": flags[name] for name in sources},
            "Source Count": flag_count,
            "Any Source": flag_count > 0,
        })
    detail_df = pd.DataFrame(rows)

    # Per-source counts in Stage 2
    print(f"\n  Stage 2 CVEs: {len(stage2_cves)}")
    print(f"\n  Per-source presence in Stage 2:")
    for name, cves in sources.items():
        in_stage2 = len(cves & stage2_cves)
        pct = in_stage2 / len(stage2_cves) * 100 if stage2_cves else 0
        print(f"    {name:25s}: {in_stage2:>4} ({pct:5.1f}%)")

    # At least one source
    any_source = sum(1 for r in rows if r["Any Source"])
    print(f"\n  Stage 2 CVEs with ANY source flag: {any_source} ({any_source/len(stage2_cves)*100:.1f}%)")

    # Multi-source corroboration
    print(f"\n  Multi-source corroboration:")
    for n in range(len(sources) + 1):
        count = sum(1 for r in rows if r["Source Count"] >= n)
        if count > 0:
            print(f"    >= {n} sources: {count} CVEs ({count/len(stage2_cves)*100:.1f}%)")

    # Base rate comparison: full cohort
    print(f"\n  Base rates (full {len(all_cves)} CVE cohort):")
    for name, cves in sources.items():
        in_cohort = len(cves & all_cves)
        pct = in_cohort / len(all_cves) * 100
        print(f"    {name:25s}: {in_cohort:>5} ({pct:5.2f}%)")

    # Lift calculation: how much more likely is a Stage 2 CVE to be in a source vs random?
    print(f"\n  Lift (Stage 2 rate / cohort base rate):")
    for name, cves in sources.items():
        stage2_rate = len(cves & stage2_cves) / len(stage2_cves) if stage2_cves else 0
        cohort_rate = len(cves & all_cves) / len(all_cves)
        lift = stage2_rate / cohort_rate if cohort_rate > 0 else float("inf")
        print(f"    {name:25s}: {lift:>6.1f}x")

    return detail_df


def main():
    # Load Stage 2 CVEs
    stage2_cves, _ = get_stage2_cves()
    all_cves, full_df = get_all_cves_from_v5()

    # Also identify KEV CVEs for sanity-check (sources should hit KEV at high rates)
    kev_cves = set(full_df[full_df["On KEV"] == True]["CVE ID"].str.strip().str.upper())
    print(f"    KEV CVEs in cohort: {len(kev_cves)}")

    # Download all sources
    sources = {}
    sources["Nuclei Templates"] = download_nuclei_cves()
    sources["PoC-in-GitHub"] = download_pocingithub()
    sources["Metasploit Modules"] = download_metasploit_cves()
    sources["VulnCheck KEV"] = download_vulncheck_kev()

    # Sanity check: KEV CVEs should be heavily flagged by these sources
    print("\n  KEV sanity check (KEV CVEs should be heavily covered):")
    for name, cves in sources.items():
        in_kev = len(cves & kev_cves)
        pct = in_kev / len(kev_cves) * 100 if kev_cves else 0
        print(f"    {name:25s}: {in_kev:>4}/{len(kev_cves)} ({pct:5.1f}%)")

    # Cross-validate Stage 2
    detail_df = cross_validate(stage2_cves, all_cves, sources)

    # Save
    print(f"\n  Saving {OUTPUT_FILE}...")

    # Summary sheet
    summary_rows = []
    summary_rows.append({"Metric": "Stage 2 CVEs (total)", "Value": len(stage2_cves)})
    summary_rows.append({"Metric": "", "Value": ""})
    for name, cves in sources.items():
        in_stage2 = len(cves & stage2_cves)
        summary_rows.append({
            "Metric": f"{name}: in Stage 2",
            "Value": f"{in_stage2} ({in_stage2/len(stage2_cves)*100:.1f}%)"
        })
    summary_rows.append({"Metric": "", "Value": ""})
    any_count = (detail_df["Any Source"]).sum()
    summary_rows.append({"Metric": "Stage 2 CVEs flagged by ANY source", "Value": f"{any_count} ({any_count/len(stage2_cves)*100:.1f}%)"})
    for n in range(2, len(sources) + 1):
        count = (detail_df["Source Count"] >= n).sum()
        summary_rows.append({"Metric": f"Stage 2 flagged by >= {n} sources", "Value": f"{count} ({count/len(stage2_cves)*100:.1f}%)"})

    summary_rows.append({"Metric": "", "Value": ""})
    summary_rows.append({"Metric": "--- Base rates (full cohort) ---", "Value": ""})
    for name, cves in sources.items():
        in_cohort = len(cves & all_cves)
        summary_rows.append({
            "Metric": f"{name}: cohort base rate",
            "Value": f"{in_cohort}/{len(all_cves)} ({in_cohort/len(all_cves)*100:.2f}%)"
        })

    summary_rows.append({"Metric": "", "Value": ""})
    summary_rows.append({"Metric": "--- KEV sanity check ---", "Value": ""})
    for name, cves in sources.items():
        in_kev = len(cves & kev_cves)
        summary_rows.append({
            "Metric": f"{name}: KEV coverage",
            "Value": f"{in_kev}/{len(kev_cves)} ({in_kev/len(kev_cves)*100:.1f}%)"
        })

    summary_rows.append({"Metric": "", "Value": ""})
    summary_rows.append({"Metric": "--- Lift (Stage 2 vs cohort) ---", "Value": ""})
    for name, cves in sources.items():
        stage2_rate = len(cves & stage2_cves) / len(stage2_cves) if stage2_cves else 0
        cohort_rate = len(cves & all_cves) / len(all_cves)
        lift = stage2_rate / cohort_rate if cohort_rate > 0 else 0
        summary_rows.append({
            "Metric": f"{name}: lift",
            "Value": f"{lift:.1f}x"
        })

    summary_df = pd.DataFrame(summary_rows)

    with pd.ExcelWriter(OUTPUT_FILE, engine="openpyxl") as w:
        summary_df.to_excel(w, sheet_name="Summary", index=False)
        detail_df.to_excel(w, sheet_name="Stage 2 Details", index=False)

    print(f"  Saved.")
    print("=" * 70)


if __name__ == "__main__":
    main()
