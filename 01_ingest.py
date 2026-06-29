"""
01_ingest.py — Download CVE data from NVD API 2.0 into nvd_cve.db.

Two modes, chosen automatically:
  INITIAL   First-ever run, or --full flag. Fetches year by year from
            --start to today, skipping years already marked complete.
  DELTA     Every subsequent run. Fetches only CVEs modified since the
            last run using lastModStartDate / lastModEndDate.
            Past years need not be re-fetched — their data doesn't change.

Usage:
    python3 01_ingest.py                  # auto mode
    python3 01_ingest.py --start 2015     # set start year for initial run
    python3 01_ingest.py --full           # force re-fetch everything
    python3 01_ingest.py --api-key KEY    # or: export NVD_API_KEY=...

Free API key (10x faster): https://nvd.nist.gov/developers/request-an-api-key
"""

import argparse
import json
import os
import sqlite3
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import requests

# ── Config ────────────────────────────────────────────────────────────────────

BASE_URL          = "https://services.nvd.nist.gov/rest/json/cves/2.0"
RAW_DB_PATH       = Path("nvd_cve.db")
DEFAULT_START_YEAR = 2015
CHUNK_DAYS        = 100    # NVD hard limit is 120 days per date-range request
SLEEP_NO_KEY      = 6.5
SLEEP_WITH_KEY    = 0.7

# ── Schema ────────────────────────────────────────────────────────────────────

DDL = """
CREATE TABLE IF NOT EXISTS raw_cves (
    cve_id        TEXT PRIMARY KEY,
    published     TEXT,
    last_modified TEXT,
    status        TEXT,
    descriptions  TEXT,
    metrics       TEXT,
    weaknesses    TEXT,
    ref_links     TEXT,
    raw_json      TEXT
);

-- Tracks completed full-year fetches (initial population)
CREATE TABLE IF NOT EXISTS ingest_log (
    year          INTEGER PRIMARY KEY,
    total_fetched INTEGER,
    fetched_at    TEXT
);

-- Key-value store for global run metadata
CREATE TABLE IF NOT EXISTS ingest_meta (
    key   TEXT PRIMARY KEY,
    value TEXT
);
"""

# ── DB helpers ────────────────────────────────────────────────────────────────

def open_db(path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(path)
    conn.executescript(DDL)
    conn.commit()
    return conn


def meta_get(conn: sqlite3.Connection, key: str) -> str | None:
    row = conn.execute("SELECT value FROM ingest_meta WHERE key=?", (key,)).fetchone()
    return row[0] if row else None


def meta_set(conn: sqlite3.Connection, key: str, value: str):
    conn.execute("INSERT OR REPLACE INTO ingest_meta (key,value) VALUES (?,?)", (key, value))
    conn.commit()


def year_done(conn: sqlite3.Connection, year: int) -> bool:
    return conn.execute(
        "SELECT 1 FROM ingest_log WHERE year=?", (year,)
    ).fetchone() is not None


def mark_year_done(conn: sqlite3.Connection, year: int, count: int):
    conn.execute(
        "INSERT OR REPLACE INTO ingest_log (year,total_fetched,fetched_at) VALUES (?,?,?)",
        (year, count, utcnow()),
    )
    conn.commit()


def utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000")


# ── HTTP ──────────────────────────────────────────────────────────────────────

def get_json(session: requests.Session, params: dict, api_key: str | None) -> dict:
    headers = {"apiKey": api_key} if api_key else {}
    # Build URL manually — requests over-encodes colons in datetime values
    qs = "&".join(f"{k}={v}" for k, v in params.items())
    url = f"{BASE_URL}?{qs}"

    max_attempts = 10
    for attempt in range(max_attempts):
        try:
            r = session.get(url, headers=headers, timeout=120)
            if r.status_code == 200:
                return r.json()
            if r.status_code == 403:
                wait = 35 * (attempt + 1)
                print(f"  [WARN] 403 — rate limited, sleeping {wait}s")
                time.sleep(wait)
            elif r.status_code == 503:
                wait = 15 * (attempt + 1)
                print(f"  [WARN] 503 — sleeping {wait}s")
                time.sleep(wait)
            else:
                print(f"  [WARN] HTTP {r.status_code} (attempt {attempt+1}/{max_attempts})")
                time.sleep(10)
        except requests.RequestException as e:
            # Exponential backoff: 15s, 30s, 60s, 120s …
            wait = min(15 * (2 ** attempt), 300)
            print(f"  [ERR] {e} (attempt {attempt+1}/{max_attempts}, retry in {wait}s)")
            time.sleep(wait)

    raise RuntimeError(f"Failed after {max_attempts} attempts — URL: {url}")


def fetch_window(
    session: requests.Session,
    date_key: str,   # "pub" or "lastMod"
    start: str,
    end: str,
    api_key: str | None,
    sleep_s: float,
) -> list[dict]:
    """Fetch all CVEs in one date window, paginating as needed."""
    start_key = f"{date_key}StartDate"
    end_key   = f"{date_key}EndDate"
    params    = {start_key: start, end_key: end, "startIndex": 0}

    data  = get_json(session, params, api_key)
    total = data.get("totalResults", 0)
    items = list(data.get("vulnerabilities", []))

    while len(items) < total:
        time.sleep(sleep_s)
        params["startIndex"] = len(items)
        data  = get_json(session, params, api_key)
        batch = data.get("vulnerabilities", [])
        if not batch:
            break
        items.extend(batch)

    return items


def date_chunks(start_dt: datetime, end_dt: datetime) -> list[tuple[str, str]]:
    """Split [start_dt, end_dt] into ≤CHUNK_DAYS windows."""
    chunks = []
    cur = start_dt
    while cur <= end_dt:
        chunk_end = min(cur + timedelta(days=CHUNK_DAYS - 1), end_dt)
        chunks.append((
            cur.strftime("%Y-%m-%dT00:00:00.000"),
            chunk_end.strftime("%Y-%m-%dT23:59:59.999"),
        ))
        cur = chunk_end + timedelta(days=1)
    return chunks


# ── Upsert ────────────────────────────────────────────────────────────────────

def upsert(conn: sqlite3.Connection, items: list[dict]) -> int:
    saved = 0
    for vuln in items:
        cve = vuln.get("cve", {})
        try:
            conn.execute(
                """INSERT OR REPLACE INTO raw_cves
                   (cve_id,published,last_modified,status,
                    descriptions,metrics,weaknesses,ref_links,raw_json)
                   VALUES (?,?,?,?,?,?,?,?,?)""",
                (
                    cve.get("id", ""),
                    cve.get("published", ""),
                    cve.get("lastModified", ""),
                    cve.get("vulnStatus", ""),
                    json.dumps(cve.get("descriptions", [])),
                    json.dumps(cve.get("metrics", {})),
                    json.dumps(cve.get("weaknesses", [])),
                    json.dumps(cve.get("references", [])),
                    json.dumps(vuln),
                ),
            )
            saved += 1
        except sqlite3.Error as e:
            print(f"  [DB ERR] {cve.get('id')}: {e}")
    conn.commit()
    return saved


# ── Modes ─────────────────────────────────────────────────────────────────────

def run_initial(conn, session, start_year: int, api_key, sleep_s):
    """Year-by-year full population, skipping already-complete years."""
    current_year = datetime.now().year
    total = 0

    for year in range(start_year, current_year + 1):
        # Past years: skip if already done
        if year < current_year and year_done(conn, year):
            row = conn.execute(
                "SELECT total_fetched FROM ingest_log WHERE year=?", (year,)
            ).fetchone()
            print(f"[{year}] Already complete ({row[0]} CVEs) — skipping")
            continue

        start_dt = datetime(year, 1, 1)
        end_dt   = datetime(year, 12, 31) if year < current_year else datetime.now()
        chunks   = date_chunks(start_dt, end_dt)

        year_items = []
        for i, (s, e) in enumerate(chunks, 1):
            print(f"[{year}] Chunk {i}/{len(chunks)}: {s[:10]} → {e[:10]}")
            items = fetch_window(session, "pub", s, e, api_key, sleep_s)
            print(f"         {len(items)} CVEs")
            year_items.extend(items)
            if i < len(chunks):
                time.sleep(sleep_s)

        n = upsert(conn, year_items)
        print(f"[{year}] Saved {n} CVEs")
        total += n

        # Only mark past years as "done" — current year always re-fetches
        if year < current_year:
            mark_year_done(conn, year, n)

        time.sleep(sleep_s)

    return total


def run_delta(conn, session, last_run: str, api_key, sleep_s):
    """Fetch only CVEs modified since last_run."""
    now = utcnow()
    print(f"[Delta] Fetching CVEs modified since {last_run}")

    last_dt = datetime.fromisoformat(last_run.replace("Z", "+00:00")).replace(tzinfo=None)
    now_dt  = datetime.now()

    chunks = date_chunks(last_dt, now_dt)
    total  = 0

    for i, (s, e) in enumerate(chunks, 1):
        print(f"[Delta] Chunk {i}/{len(chunks)}: {s[:10]} → {e[:10]}")
        items = fetch_window(session, "lastMod", s, e, api_key, sleep_s)
        print(f"        {len(items)} CVEs modified")
        n = upsert(conn, items)
        total += n
        if i < len(chunks):
            time.sleep(sleep_s)

    return total, now


# ── Main ──────────────────────────────────────────────────────────────────────

def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("--start",   type=int, default=DEFAULT_START_YEAR)
    p.add_argument("--full",    action="store_true", help="Re-fetch all years from scratch")
    p.add_argument("--api-key", default=os.environ.get("NVD_API_KEY"))
    p.add_argument("--db",      default=str(RAW_DB_PATH))
    return p.parse_args()


def main():
    args    = parse_args()
    sleep_s = SLEEP_WITH_KEY if args.api_key else SLEEP_NO_KEY

    if not args.api_key:
        print("[WARN] No API key — rate limited to 5 req/30s. Get one free:")
        print("       https://nvd.nist.gov/developers/request-an-api-key\n")

    conn    = open_db(Path(args.db))
    session = requests.Session()
    session.headers["Accept"] = "application/json"

    last_run = meta_get(conn, "last_run")

    if args.full or last_run is None:
        mode = "FULL" if args.full else "INITIAL"
        print(f"[Mode] {mode} — fetching {args.start} → {datetime.now().year}")
        if args.full:
            conn.execute("DELETE FROM ingest_log")
            conn.commit()
        n = run_initial(conn, session, args.start, args.api_key, sleep_s)
    else:
        print("[Mode] DELTA — pulling changes since last run")
        n, now = run_delta(conn, session, last_run, args.api_key, sleep_s)
        meta_set(conn, "last_run", now)

    # Record last_run after a successful initial population too
    if last_run is None:
        meta_set(conn, "last_run", utcnow())

    conn.close()
    print(f"\n[Done] {n} CVEs upserted → {args.db}")


if __name__ == "__main__":
    main()
