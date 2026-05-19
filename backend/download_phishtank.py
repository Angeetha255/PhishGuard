"""
PhishGuard AI — Phishing Dataset Downloader
=============================================
Downloads phishing URLs from multiple free, open sources:
  1. phishunt.io/feed.csv          — real-time verified phishing feed
  2. Phishing.Database (GitHub)    — large active phishing URL list
  3. OpenPhish feed                — community phishing feed

Combines them with the existing clean_phishing_dataset.csv and
Phishing_Legitimate_full.csv to produce a final phishtank.csv
ready for train_model.py.
"""

import os
import sys
import time
import requests
import pandas as pd
from io import StringIO

DATA_DIR = os.path.join(os.path.dirname(__file__), 'data')
os.makedirs(DATA_DIR, exist_ok=True)

HEADERS = {
    'User-Agent': 'Mozilla/5.0 (compatible; PhishGuardAI/2.0; +https://github.com/phishguard)'
}

# ── Source definitions ─────────────────────────────────────────────────────────

SOURCES = [
    {
        'name':   'phishunt.io CSV feed',
        'url':    'https://phishunt.io/feed.csv',
        'format': 'csv',
        'url_col': 'url',
    },
    {
        'name':   'OpenPhish community feed',
        'url':    'https://openphish.com/feed.txt',
        'format': 'txt',
    },
    {
        'name':   'Phishing.Database active list',
        'url':    'https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-links-ACTIVE.txt',
        'format': 'txt',
        'max_bytes': 5 * 1024 * 1024,   # cap at 5 MB (~50k URLs) to keep training fast
    },
]


def fetch_source(src: dict) -> list:
    """Download a source and return a list of phishing URL strings."""
    name      = src['name']
    url       = src['url']
    fmt       = src['format']
    max_bytes = src.get('max_bytes', None)

    print(f'\n  Fetching: {name}')
    print(f'  URL: {url}')

    try:
        resp = requests.get(url, headers=HEADERS, timeout=60, stream=True)
        resp.raise_for_status()

        # Stream with optional byte cap
        chunks = []
        total  = 0
        for chunk in resp.iter_content(chunk_size=65536):
            chunks.append(chunk)
            total += len(chunk)
            if max_bytes and total >= max_bytes:
                print(f'  ⚠️  Capped at {total/1024:.0f} KB')
                break
        raw = b''.join(chunks).decode('utf-8', errors='ignore')

        print(f'  Downloaded: {total/1024:.1f} KB')

        if fmt == 'txt':
            urls = [line.strip() for line in raw.splitlines()
                    if line.strip() and line.strip().startswith(('http://', 'https://'))]
            print(f'  Parsed: {len(urls):,} URLs')
            return urls

        elif fmt == 'csv':
            df = pd.read_csv(StringIO(raw))
            url_col = src.get('url_col', 'url')
            # Try to find the URL column case-insensitively
            col_map = {c.lower(): c for c in df.columns}
            actual_col = col_map.get(url_col.lower())
            if not actual_col:
                # Try common alternatives
                for candidate in ('url', 'phish_url', 'link', 'address'):
                    if candidate in col_map:
                        actual_col = col_map[candidate]
                        break
            if not actual_col:
                print(f'  ⚠️  Could not find URL column. Columns: {df.columns.tolist()}')
                return []
            urls = df[actual_col].dropna().astype(str).tolist()
            urls = [u for u in urls if u.startswith(('http://', 'https://'))]
            print(f'  Parsed: {len(urls):,} URLs')
            return urls

    except requests.exceptions.Timeout:
        print(f'  ❌ Timeout fetching {name}')
    except requests.exceptions.HTTPError as e:
        print(f'  ❌ HTTP error {e.response.status_code} for {name}')
    except Exception as e:
        print(f'  ❌ Error fetching {name}: {e}')

    return []


def build_phishtank_csv():
    print('=' * 60)
    print('  PhishGuard AI — Dataset Downloader')
    print('=' * 60)

    all_phishing_urls = []

    # ── Download from live sources ─────────────────────────
    for src in SOURCES:
        urls = fetch_source(src)
        all_phishing_urls.extend(urls)
        time.sleep(1)   # be polite

    # ── Deduplicate ────────────────────────────────────────
    all_phishing_urls = list(dict.fromkeys(all_phishing_urls))  # preserve order, dedupe
    print(f'\nTotal unique phishing URLs from live sources: {len(all_phishing_urls):,}')

    # ── Build DataFrame ────────────────────────────────────
    df_phishing = pd.DataFrame({
        'url':   all_phishing_urls,
        'label': 1,
    })

    # ── Save phishtank.csv ─────────────────────────────────
    out_path = os.path.join(DATA_DIR, 'phishtank.csv')
    df_phishing.to_csv(out_path, index=False)
    print(f'\n✅ Saved phishtank.csv → {out_path}')
    print(f'   Rows: {len(df_phishing):,}')

    # ── Summary ────────────────────────────────────────────
    print('\n' + '=' * 60)
    print('  Dataset Summary')
    print('=' * 60)

    # Check existing datasets
    for fname in ('clean_phishing_dataset.csv', 'Phishing_Legitimate_full.csv', 'phishtank.csv'):
        fpath = os.path.join(DATA_DIR, fname)
        if os.path.exists(fpath):
            try:
                n = sum(1 for _ in open(fpath, encoding='utf-8', errors='ignore')) - 1
                size_kb = os.path.getsize(fpath) / 1024
                print(f'  {fname}: {n:,} rows  ({size_kb:.1f} KB)')
            except Exception:
                print(f'  {fname}: exists')
        else:
            print(f'  {fname}: NOT FOUND')

    print('\nRun train_model.py to train the model with all datasets.')
    return out_path


if __name__ == '__main__':
    build_phishtank_csv()
