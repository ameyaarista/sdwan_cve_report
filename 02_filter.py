"""
02_filter.py — Filter raw CVEs from nvd_cve.db for SD-WAN products
               and write results to analysis.db.

Reads:  nvd_cve.db    (raw_cves table — written by 01_ingest.py)
Writes: analysis.db   (filtered_cves table)

Usage:
    python3 02_filter.py
    python3 02_filter.py --raw nvd_cve.db --out analysis.db
    python3 02_filter.py --use-ai              # LLM disambiguation (needs ANTHROPIC_API_KEY)
"""

import argparse
import json
import os
import re
import sqlite3

from families import FAMILIES

# ── Output DB schema ──────────────────────────────────────────────────────────

DDL = """
CREATE TABLE IF NOT EXISTS filtered_cves (
    cve_id        TEXT,
    family        TEXT,
    published     TEXT,
    year          INTEGER,
    vendors       TEXT,
    cvss_score    REAL,
    cvss_severity TEXT,
    cvss_vector   TEXT,
    description   TEXT,
    weaknesses    TEXT,
    ai_verified   INTEGER DEFAULT 0,
    ai_note       TEXT,
    PRIMARY KEY (cve_id, family)
);
CREATE INDEX IF NOT EXISTS idx_family ON filtered_cves(family);
CREATE INDEX IF NOT EXISTS idx_year   ON filtered_cves(year);
"""

# ── Pattern compilation ───────────────────────────────────────────────────────

def compile_family(family_cfg: dict):
    """Compile vendor keyword patterns for one family."""
    return [
        (vendor, [re.compile(p, re.IGNORECASE) for p in pats])
        for vendor, pats in family_cfg["vendors"]
    ]


def match_vendors(text: str, compiled: list) -> list[str]:
    matched = []
    for vendor, patterns in compiled:
        for pat in patterns:
            if pat.search(text):
                matched.append(vendor)
                break
    return matched


def is_relevant(description: str, vendors: list[str], family_cfg: dict) -> bool:
    if not vendors:
        return False

    unambiguous     = family_cfg["unambiguous"]
    vendor_checks   = family_cfg["vendor_checks"]
    vendor_excludes = family_cfg.get("vendor_excludes", {})
    default_check   = family_cfg["default_check"]
    generic         = family_cfg.get("generic_pattern")

    # Generic catch-all (e.g. "sd-wan" in description)
    if generic and generic.search(description) and "Generic" in vendors:
        return True

    for v in vendors:
        if v == "Generic":
            continue
        # Reject if description matches an exclude pattern for this vendor
        excl = vendor_excludes.get(v)
        if excl and excl.search(description):
            continue
        if v in unambiguous:
            return True
        chk = vendor_checks.get(v, default_check)
        if chk and chk.search(description):
            return True

    return False


def vendor_labels(vendors: list[str]) -> str:
    specific = [v for v in vendors if v != "Generic"]
    final    = specific if specific else []
    return ",".join(sorted(set(final)))

# ── CVSS / description / CWE extraction ──────────────────────────────────────

def extract_cvss(metrics_json: str) -> tuple:
    try:
        m = json.loads(metrics_json)
    except Exception:
        return None, None, None
    for key in ("cvssMetricV31", "cvssMetricV30"):
        if key in m:
            d = m[key][0].get("cvssData", {})
            return d.get("baseScore"), d.get("baseSeverity"), d.get("vectorString")
    if "cvssMetricV2" in m:
        d   = m["cvssMetricV2"][0].get("cvssData", {})
        sev = m["cvssMetricV2"][0].get("baseSeverity")
        return d.get("baseScore"), sev, d.get("vectorString")
    return None, None, None


def extract_description(descriptions_json: str) -> str:
    try:
        descs = json.loads(descriptions_json)
        for d in descs:
            if d.get("lang") == "en":
                return d.get("value", "")
        if descs:
            return descs[0].get("value", "")
    except Exception:
        pass
    return ""


def extract_cwes(weaknesses_json: str) -> str:
    try:
        wk   = json.loads(weaknesses_json)
        cwes = []
        for w in wk:
            for d in w.get("description", []):
                v = d.get("value", "")
                if v.startswith("CWE-"):
                    cwes.append(v)
        return ",".join(sorted(set(cwes)))
    except Exception:
        return ""

# ── AI disambiguation ─────────────────────────────────────────────────────────

def ai_verify(rows: list[dict], family_name: str) -> list[dict]:
    try:
        import anthropic
    except ImportError:
        print("[AI] anthropic not installed — skipping (pip install anthropic)")
        return rows

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        print("[AI] ANTHROPIC_API_KEY not set — skipping")
        return rows

    client = anthropic.Anthropic(api_key=api_key)
    SYSTEM = (
        f"You are a cybersecurity analyst specialising in {family_name} networking products. "
        f"Decide whether a CVE genuinely affects a {family_name} product or component. "
        "Reply with exactly: YES <brief reason> or NO <brief reason>."
    )

    print(f"[AI] Verifying {len(rows)} CVEs for family '{family_name}'...")
    for row in rows:
        try:
            resp = client.messages.create(
                model="claude-haiku-4-5-20251001",
                max_tokens=80,
                system=SYSTEM,
                messages=[{"role": "user", "content":
                           f"CVE: {row['cve_id']}\n{row['description']}"}],
            )
            answer = resp.content[0].text.strip()
            row["ai_verified"] = 1 if answer.upper().startswith("YES") else -1
            row["ai_note"]     = answer[:200]
            if row["ai_verified"] == -1:
                print(f"  [AI] REJECTED {row['cve_id']}: {answer[:80]}")
        except Exception as e:
            print(f"  [AI] Error {row['cve_id']}: {e}")

    kept = [r for r in rows if r.get("ai_verified", 0) != -1]
    print(f"[AI] Rejected {len(rows) - len(kept)} false positives")
    return kept

# ── Per-family filter run ─────────────────────────────────────────────────────

def run_family(family_key: str, family_cfg: dict, rows_raw, dst: sqlite3.Connection,
               use_ai: bool):
    display = family_cfg["display_name"]
    compiled = compile_family(family_cfg)

    matched = []
    for row in rows_raw:
        desc    = extract_description(row["descriptions"])
        vendors = match_vendors(desc, compiled)

        if not is_relevant(desc, vendors, family_cfg):
            continue

        labels = vendor_labels(vendors)
        if not labels:          # skip Generic-only
            continue

        score, severity, vector = extract_cvss(row["metrics"])
        published = row["published"] or ""
        year      = int(published[:4]) if len(published) >= 4 else None

        matched.append({
            "cve_id":        row["cve_id"],
            "family":        family_key,
            "published":     published,
            "year":          year,
            "vendors":       labels,
            "cvss_score":    score,
            "cvss_severity": severity,
            "cvss_vector":   vector,
            "description":   desc,
            "weaknesses":    extract_cwes(row["weaknesses"]),
            "ai_verified":   0,
            "ai_note":       None,
        })

    print(f"  [{display}] {len(matched)} CVEs matched")

    if use_ai and matched:
        matched = ai_verify(matched, display)

    final = [r for r in matched if r.get("ai_verified", 0) != -1]

    # Remove old records for this family before re-inserting
    dst.execute("DELETE FROM filtered_cves WHERE family=?", (family_key,))
    dst.executemany(
        """INSERT OR REPLACE INTO filtered_cves
           (cve_id,family,published,year,vendors,cvss_score,cvss_severity,
            cvss_vector,description,weaknesses,ai_verified,ai_note)
           VALUES (:cve_id,:family,:published,:year,:vendors,:cvss_score,:cvss_severity,
                   :cvss_vector,:description,:weaknesses,:ai_verified,:ai_note)""",
        final,
    )
    dst.commit()
    print(f"  [{display}] Saved {len(final)} CVEs")

    # Quick vendor summary
    by_vendor: dict[str, int] = {}
    for r in final:
        for v in r["vendors"].split(","):
            v = v.strip()
            if v:
                by_vendor[v] = by_vendor.get(v, 0) + 1
    for v, n in sorted(by_vendor.items(), key=lambda x: -x[1]):
        print(f"    {v}: {n}")

    return len(final)

# ── Main ──────────────────────────────────────────────────────────────────────

def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("--raw",    default="nvd_cve.db",  help="Source raw DB (01_ingest.py)")
    p.add_argument("--out",    default="analysis.db",  help="Output analysis DB")
    p.add_argument("--family", default=None,
                   choices=list(FAMILIES.keys()),
                   help="Run one family only (default: all)")
    p.add_argument("--use-ai", action="store_true")
    return p.parse_args()


def main():
    args = parse_args()

    src = sqlite3.connect(args.raw)
    src.row_factory = sqlite3.Row

    dst = sqlite3.connect(args.out)
    dst.executescript(DDL)
    dst.commit()

    rows_raw = src.execute(
        "SELECT cve_id, published, descriptions, metrics, weaknesses FROM raw_cves"
    ).fetchall()
    print(f"[Filter] {len(rows_raw)} raw CVEs in {args.raw}\n")

    families_to_run = (
        {args.family: FAMILIES[args.family]} if args.family else FAMILIES
    )

    total = 0
    for family_key, family_cfg in families_to_run.items():
        print(f"── {family_cfg['display_name']} ──")
        total += run_family(family_key, family_cfg, rows_raw, dst, args.use_ai)
        print()

    print(f"[Filter] Done — {total} total CVEs across all families → {args.out}")

    # Cross-family summary
    print("\n── Summary by family ──")
    for row in dst.execute(
        "SELECT family, COUNT(*) as n FROM filtered_cves GROUP BY family ORDER BY n DESC"
    ).fetchall():
        print(f"  {row[0]}: {row[1]}")

    src.close()
    dst.close()


if __name__ == "__main__":
    main()
