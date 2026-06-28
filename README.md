# SD-WAN CVE Trend Analysis

10-year trend analysis of CVEs affecting SD-WAN products, sourced from the NIST National Vulnerability Database (NVD) API 2.0.

## Pipeline Overview

```
01_ingest.py  →  nvd_cve.db         (raw NVD data, incremental)
02_filter.py  →  sdwan_analysis.db  (SD-WAN filtered CVEs)
04_excel_report.py reads sdwan_analysis.db → sdwan_report.xlsx
```

### Incremental design
- `nvd_cve.db` tracks completed years. Re-running `01_ingest.py` only pulls CVEs
  modified since the last run (uses NVD `lastModStartDate` parameter).
- Past years are never re-fetched. Only delta changes come through.
- `02_filter.py` uses `INSERT OR REPLACE` so it's safe to re-run any time.

## Setup

```bash
pip install -r requirements.txt
```

Get a free NVD API key (recommended — 10x faster): https://nvd.nist.gov/developers/request-an-api-key

```bash
export NVD_API_KEY=your-key-here
```

## Run

### Step 1 — Ingest raw CVE data

```bash
# Default: 2015 to current year
python 01_ingest.py

# Custom range
python 01_ingest.py --start 2015 --end 2025

# Resume a partially-completed run
python 01_ingest.py --resume
```

This writes `nvd_cve.db` with a `raw_cves` table (~150k–300k rows for 10 years).  
Without an API key, expect ~3–4 hours. With an API key: ~20–30 min.

### Step 2 — Filter for SD-WAN

```bash
python 02_filter.py

# With LLM disambiguation (removes Cisco/Fortinet false positives)
# Requires: export ANTHROPIC_API_KEY=your-key
python 02_filter.py --use-ai
```

Writes `sdwan_cves` table into the same `nvd_cve.db`.

### Step 3 — Analyze & visualize

```bash
python 03_analyze.py

# Custom output dir
python 03_analyze.py --out-dir reports/2025-run/
```

## Outputs

| File | Description |
|------|-------------|
| `reports/sdwan_cve_trend.png` | Annual CVE count stacked by severity |
| `reports/sdwan_vendor_heatmap.png` | Vendor × Year CVE count heatmap |
| `reports/sdwan_severity_pie.png` | Overall severity breakdown |
| `reports/sdwan_top_cwes.png` | Top 15 weakness types (CWE) |
| `reports/sdwan_vendor_severity.png` | Per-vendor severity stacked bar |
| `reports/sdwan_summary.csv` | Full CVE export |
| `reports/sdwan_yearly_summary.csv` | Year-level aggregation |

## Vendors Tracked

- Cisco (SD-WAN / Viptela / Catalyst SD-WAN)
- VMware / Broadcom (VeloCloud)
- Fortinet (FortiGate SD-WAN)
- Palo Alto Networks (Prisma SD-WAN / CloudGenix)
- Juniper (Session Smart Router / 128 Technology)
- HPE Aruba (Silver Peak / EdgeConnect)
- Versa Networks
- Cradlepoint
- Aryaka
- Citrix (NetScaler SD-WAN)
- Barracuda (CloudGen WAN)

## Notes

- NVD API 2.0 replaced legacy JSON feeds (deprecated Dec 2023).
- Without an API key the tool sleeps 6.5s between requests to respect the 5 req/30s limit.
- The `--use-ai` flag in `02_filter.py` uses Claude Haiku to reject false positives for broad vendor names (e.g., Cisco switches vs. Cisco SD-WAN).
