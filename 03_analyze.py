"""
03_analyze.py — Generate analytics and charts from the filtered SD-WAN CVE data.

Run AFTER 02_filter.py has populated analysis.db.

Usage:
    python 03_analyze.py
    python 03_analyze.py --db analysis.db --out-dir reports/

Outputs (in --out-dir):
    sdwan_cve_trend.png          — CVEs per year (total + by severity)
    sdwan_vendor_heatmap.png     — Vendor × Year CVE count heatmap
    sdwan_severity_pie.png       — Overall severity breakdown
    sdwan_top_cwes.png           — Top 15 weaknesses (CWE)
    sdwan_vendor_severity.png    — Per-vendor severity stacked bar
    sdwan_summary.csv            — Full data export
    sdwan_yearly_summary.csv     — Year-level aggregation
"""

import argparse
import sqlite3
import json
from pathlib import Path
from collections import defaultdict

import pandas as pd
import matplotlib
matplotlib.use("Agg")  # non-interactive backend
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker
import seaborn as sns

# ── Style ─────────────────────────────────────────────────────────────────────

SEVERITY_ORDER   = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE", "UNKNOWN"]
SEVERITY_COLORS  = {
    "CRITICAL": "#d62728",
    "HIGH":     "#ff7f0e",
    "MEDIUM":   "#f7c04a",
    "LOW":      "#2ca02c",
    "NONE":     "#aec7e8",
    "UNKNOWN":  "#c7c7c7",
}

sns.set_theme(style="whitegrid", palette="muted", font_scale=1.1)
plt.rcParams.update({"figure.dpi": 150, "savefig.bbox": "tight"})

# ── Load Data ─────────────────────────────────────────────────────────────────

def load_data(db_path: str) -> pd.DataFrame:
    conn = sqlite3.connect(db_path)
    df = pd.read_sql_query("SELECT * FROM filtered_cves WHERE family = 'SDWAN'", conn)
    conn.close()

    df["published"] = pd.to_datetime(df["published"], errors="coerce", utc=True)
    df["year"] = df["published"].dt.year.astype("Int64")

    # Normalise severity
    df["cvss_severity"] = (
        df["cvss_severity"]
        .str.upper()
        .fillna("UNKNOWN")
        .replace("", "UNKNOWN")
    )
    df.loc[~df["cvss_severity"].isin(SEVERITY_ORDER), "cvss_severity"] = "UNKNOWN"

    print(f"[Analyze] Loaded {len(df)} SD-WAN CVEs from {db_path}")
    return df


# ── Chart 1: Annual CVE trend ─────────────────────────────────────────────────

def plot_annual_trend(df: pd.DataFrame, out_dir: Path):
    pivot = (
        df.groupby(["year", "cvss_severity"])
        .size()
        .unstack(fill_value=0)
        .reindex(columns=[s for s in SEVERITY_ORDER if s in df["cvss_severity"].unique()], fill_value=0)
    )

    fig, axes = plt.subplots(2, 1, figsize=(13, 9), sharex=True,
                             gridspec_kw={"height_ratios": [3, 1]})

    # Stacked bar — severity breakdown
    ax = axes[0]
    bottom = None
    for sev in [s for s in SEVERITY_ORDER if s in pivot.columns]:
        vals = pivot[sev]
        ax.bar(pivot.index, vals, bottom=bottom,
               color=SEVERITY_COLORS[sev], label=sev, width=0.7)
        bottom = vals if bottom is None else bottom + vals

    ax.set_title("SD-WAN CVEs by Year and Severity", fontsize=15, fontweight="bold")
    ax.set_ylabel("Number of CVEs")
    ax.legend(title="CVSS Severity", loc="upper left", framealpha=0.8)
    ax.yaxis.set_major_locator(ticker.MaxNLocator(integer=True))

    # Line — total per year
    ax2 = axes[1]
    totals = pivot.sum(axis=1)
    ax2.plot(totals.index, totals.values, marker="o", color="#1f77b4", linewidth=2)
    ax2.set_ylabel("Total")
    ax2.set_xlabel("Year")
    ax2.yaxis.set_major_locator(ticker.MaxNLocator(integer=True))

    plt.tight_layout()
    out = out_dir / "sdwan_cve_trend.png"
    fig.savefig(out)
    plt.close(fig)
    print(f"[Chart] {out}")


# ── Chart 2: Vendor × Year heatmap ───────────────────────────────────────────

def explode_vendors(df: pd.DataFrame) -> pd.DataFrame:
    """Explode comma-separated vendors into one row per vendor."""
    rows = []
    for _, r in df.iterrows():
        for v in str(r["vendors"]).split(","):
            v = v.strip()
            if v and v != "Generic":
                rows.append({**r.to_dict(), "vendor": v})
    return pd.DataFrame(rows)


def plot_vendor_heatmap(df: pd.DataFrame, out_dir: Path):
    vdf = explode_vendors(df)
    if vdf.empty:
        print("[Chart] No vendor data for heatmap, skipping")
        return

    pivot = (
        vdf.groupby(["vendor", "year"])
        .size()
        .unstack(fill_value=0)
    )
    # Sort vendors by total descending
    pivot = pivot.loc[pivot.sum(axis=1).sort_values(ascending=False).index]

    fig, ax = plt.subplots(figsize=(max(12, len(pivot.columns)), max(6, len(pivot) * 0.8)))
    sns.heatmap(
        pivot, ax=ax, cmap="YlOrRd", linewidths=0.5, linecolor="white",
        annot=True, fmt="d", cbar_kws={"label": "CVE Count"},
    )
    ax.set_title("SD-WAN CVEs per Vendor per Year", fontsize=14, fontweight="bold")
    ax.set_xlabel("Year")
    ax.set_ylabel("Vendor")
    plt.xticks(rotation=45, ha="right")
    plt.yticks(rotation=0)
    plt.tight_layout()

    out = out_dir / "sdwan_vendor_heatmap.png"
    fig.savefig(out)
    plt.close(fig)
    print(f"[Chart] {out}")


# ── Chart 3: Severity pie ─────────────────────────────────────────────────────

def plot_severity_pie(df: pd.DataFrame, out_dir: Path):
    counts = df["cvss_severity"].value_counts()
    counts = counts.reindex([s for s in SEVERITY_ORDER if s in counts.index])

    fig, ax = plt.subplots(figsize=(7, 7))
    wedges, texts, autotexts = ax.pie(
        counts.values,
        labels=counts.index,
        colors=[SEVERITY_COLORS[s] for s in counts.index],
        autopct="%1.1f%%",
        startangle=140,
        wedgeprops={"edgecolor": "white", "linewidth": 1.5},
    )
    for t in autotexts:
        t.set_fontsize(10)
    ax.set_title("SD-WAN CVE Severity Distribution (All Years)", fontsize=13, fontweight="bold")

    out = out_dir / "sdwan_severity_pie.png"
    fig.savefig(out)
    plt.close(fig)
    print(f"[Chart] {out}")


# ── Chart 4: Top CWEs ─────────────────────────────────────────────────────────

def plot_top_cwes(df: pd.DataFrame, out_dir: Path, top_n: int = 15):
    cwe_counts: dict[str, int] = defaultdict(int)
    for val in df["weaknesses"].dropna():
        for cwe in str(val).split(","):
            cwe = cwe.strip()
            if cwe:
                cwe_counts[cwe] += 1

    if not cwe_counts:
        print("[Chart] No CWE data, skipping top-CWE chart")
        return

    top = sorted(cwe_counts.items(), key=lambda x: x[1], reverse=True)[:top_n]
    labels, values = zip(*top)

    fig, ax = plt.subplots(figsize=(10, 7))
    bars = ax.barh(list(reversed(labels)), list(reversed(values)), color="#4c72b0")
    ax.bar_label(bars, padding=3, fontsize=9)
    ax.set_title(f"Top {top_n} Weakness Types (CWE) in SD-WAN CVEs", fontsize=13, fontweight="bold")
    ax.set_xlabel("Number of CVEs")
    ax.set_xlim(0, max(values) * 1.15)
    plt.tight_layout()

    out = out_dir / "sdwan_top_cwes.png"
    fig.savefig(out)
    plt.close(fig)
    print(f"[Chart] {out}")


# ── Chart 5: Vendor severity stacked bar ─────────────────────────────────────

def plot_vendor_severity(df: pd.DataFrame, out_dir: Path):
    vdf = explode_vendors(df)
    if vdf.empty:
        return

    pivot = (
        vdf.groupby(["vendor", "cvss_severity"])
        .size()
        .unstack(fill_value=0)
        .reindex(columns=[s for s in SEVERITY_ORDER if s in vdf["cvss_severity"].unique()], fill_value=0)
    )
    # Sort by total
    pivot = pivot.loc[pivot.sum(axis=1).sort_values(ascending=False).index]

    fig, ax = plt.subplots(figsize=(12, 6))
    bottom = None
    for sev in [s for s in SEVERITY_ORDER if s in pivot.columns]:
        vals = pivot[sev]
        ax.bar(pivot.index, vals, bottom=bottom,
               color=SEVERITY_COLORS[sev], label=sev, width=0.6)
        bottom = vals if bottom is None else bottom + vals

    ax.set_title("CVE Severity by Vendor (All Years)", fontsize=13, fontweight="bold")
    ax.set_ylabel("Number of CVEs")
    ax.set_xlabel("Vendor")
    ax.legend(title="CVSS Severity", loc="upper right", framealpha=0.8)
    ax.yaxis.set_major_locator(ticker.MaxNLocator(integer=True))
    plt.xticks(rotation=25, ha="right")
    plt.tight_layout()

    out = out_dir / "sdwan_vendor_severity.png"
    fig.savefig(out)
    plt.close(fig)
    print(f"[Chart] {out}")


# ── CSV Exports ───────────────────────────────────────────────────────────────

def export_csvs(df: pd.DataFrame, out_dir: Path):
    # Full export
    full_out = out_dir / "sdwan_summary.csv"
    df.to_csv(full_out, index=False)
    print(f"[CSV]   {full_out}")

    # Yearly aggregation
    yearly = df.groupby("year").agg(
        total_cves=("cve_id", "count"),
        critical=("cvss_severity", lambda x: (x == "CRITICAL").sum()),
        high=("cvss_severity",     lambda x: (x == "HIGH").sum()),
        medium=("cvss_severity",   lambda x: (x == "MEDIUM").sum()),
        low=("cvss_severity",      lambda x: (x == "LOW").sum()),
        avg_cvss_score=("cvss_score", "mean"),
        max_cvss_score=("cvss_score", "max"),
    ).reset_index()
    yearly["avg_cvss_score"] = yearly["avg_cvss_score"].round(2)
    yearly["max_cvss_score"] = yearly["max_cvss_score"].round(2)
    yearly_out = out_dir / "sdwan_yearly_summary.csv"
    yearly.to_csv(yearly_out, index=False)
    print(f"[CSV]   {yearly_out}")

    # Print summary table to console
    print("\n── Yearly Summary ──")
    print(yearly.to_string(index=False))


# ── Main ──────────────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Visualise SD-WAN CVE trends")
    p.add_argument("--db",      default="analysis.db", help="analysis.db written by 02_filter.py")
    p.add_argument("--out-dir", default="reports",    help="Output directory for charts and CSVs")
    return p.parse_args()


def main():
    args = parse_args()
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    df = load_data(args.db)

    if df.empty:
        print("[Analyze] No data found. Run 02_filter.py first.")
        return

    plot_annual_trend(df, out_dir)
    plot_vendor_heatmap(df, out_dir)
    plot_severity_pie(df, out_dir)
    plot_top_cwes(df, out_dir)
    plot_vendor_severity(df, out_dir)
    export_csvs(df, out_dir)

    print(f"\n[Done] All outputs written to: {out_dir}/")


if __name__ == "__main__":
    main()
